# app.py
import os
import re
import ssl
import math
import smtplib
import secrets
import datetime
import atexit, signal, sys
import threading, uuid
from io import BytesIO
from urllib.parse import urlparse
from wsgiref.util import FileWrapper
from email.message import EmailMessage
import logging

from flask import (
    Flask, request, render_template, redirect, url_for, flash, Response, session, jsonify
)
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from markupsafe import Markup, escape

from dotenv import load_dotenv
load_dotenv()

import requests
import nltk
nltk.download('stopwords', quiet=True)

# Security add-ons
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from bson import ObjectId
from pymongo import ASCENDING, DESCENDING, TEXT

# Local modules
from db_utils import get_db, User, load_user, allowed_file, close_mongo_client
from openai_utils import (
    transcribe_audio,
    translate_between_languages,
    optimize_text,
    generate_meeting_notes_smart
)

# Timing utils (you said these files are added)
from timing_utils import step_timer

# Optional Markdown rendering
try:
    import markdown as md
    HAS_MD = True
except Exception:
    HAS_MD = False


# --------------------------------------------------------------------------------------
# App setup & config
# --------------------------------------------------------------------------------------
app = Flask(__name__)

# Logging (so timing lines show clearly)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Secrets & config
app.secret_key = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Prod-only stricter cookies
if (os.getenv("FLASK_ENV") or "").lower() == "production":
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['REMEMBER_COOKIE_SECURE'] = True

# CSRF
csrf = CSRFProtect(app)

# Rate limiting
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

# Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.user_loader(load_user)


# Graceful shutdown (prevents noisy pymongo atexit warnings)
def _graceful_shutdown(*_args):
    try:
        close_mongo_client()
    except Exception:
        pass
atexit.register(_graceful_shutdown)
for sig_name in ("SIGINT", "SIGTERM"):
    sig = getattr(signal, sig_name, None)
    if sig is not None:
        signal.signal(sig, lambda s, f: (_graceful_shutdown(), sys.exit(0)))


# --------------------------------------------------------------------------------------
# Language support (SRS: source is REQUIRED, output is OPTIONAL -> default EN)
# --------------------------------------------------------------------------------------
SUPPORTED_INPUT_LANGS = {
    "en": "English", "ur": "Urdu", "ar": "Arabic", "hi": "Hindi",
    "fr": "French", "es": "Spanish", "de": "German", "tr": "Turkish",
    "ru": "Russian", "zh": "Chinese (Simplified)"
}
SUPPORTED_OUTPUT_LANGS = SUPPORTED_INPUT_LANGS.copy()
DEFAULT_OUTPUT_LANGS = ["en"]


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------
def fetch_media_from_url(url: str, upload_dir: str) -> str:
    """
    Downloads a direct media file (.mp3/.wav/.mp4) to uploads/ and returns the local path.
    Handles generic file URLs (Google Drive handled in caller).
    """
    parsed = urlparse(url)
    name = os.path.basename(parsed.path)

    if not name or '.' not in name:
        raise ValueError("URL must point to a direct media file (.mp3, .wav, .mp4)")

    ext = name.rsplit('.', 1)[1].lower()
    if ext not in {'mp3', 'wav', 'mp4'}:
        raise ValueError("Unsupported media type in URL (use .mp3, .wav, .mp4)")

    local_path = os.path.join(upload_dir, secure_filename(name))
    try:
        with requests.get(url, stream=True, timeout=30) as r:
            r.raise_for_status()
            with open(local_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
    except Exception as e:
        raise ValueError(f"Failed to download from the URL: {e}")

    return local_path


def _is_rtl_language(code: str) -> bool:
    return (code or "").lower() in {"ar", "ur", "fa", "he", "ps", "ku"}


def generate_pdf_bytes(text: str, lang_code: str = "en") -> bytes:
    """
    Generate a simple PDF from plain/markdown-ish text.
    Tries ReportLab (better Unicode & RTL shaping), falls back to FPDF.
    Put fonts in: static/fonts/NotoSans-Regular.ttf, NotoNaskhArabic-Regular.ttf, DejaVuSans.ttf
    """
    # Try ReportLab path first
    try:
        from reportlab.pdfgen import canvas
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm

        # Fonts directory
        root = app.root_path
        fonts_dir = os.path.join(root, "static", "fonts")
        latin_font = None
        rtl_font = None

        # Prefer Noto or DejaVu
        for candidate in ["NotoSans-Regular.ttf", "DejaVuSans.ttf"]:
            p = os.path.join(fonts_dir, candidate)
            if os.path.exists(p):
                latin_font = p
                break

        for candidate in ["NotoNaskhArabic-Regular.ttf", "DejaVuSans.ttf"]:
            p = os.path.join(fonts_dir, candidate)
            if os.path.exists(p):
                rtl_font = p
                break

        buf = BytesIO()
        c = canvas.Canvas(buf, pagesize=A4)
        width, height = A4

        if latin_font:
            pdfmetrics.registerFont(TTFont("LATIN", latin_font))
        if rtl_font:
            pdfmetrics.registerFont(TTFont("RTL", rtl_font))

        use_rtl = _is_rtl_language(lang_code)
        font_name = "RTL" if (use_rtl and rtl_font) else ("LATIN" if latin_font else "Helvetica")

        c.setFont(font_name, 11)
        textobject = c.beginText()
        textobject.setTextOrigin(20 * mm, height - 20 * mm)
        line_height = 5.0 * mm

        lines = (text or "").splitlines() or [""]

        # Optional shaping for RTL (if libs installed)
        try:
            if use_rtl:
                import arabic_reshaper
                from bidi.algorithm import get_display
                shaped = []
                for ln in lines:
                    ln = ln.strip("\n")
                    if ln:
                        ln = arabic_reshaper.reshape(ln)
                        ln = get_display(ln)
                    shaped.append(ln)
                lines = shaped
        except Exception:
            pass

        for ln in lines:
            textobject.textLine(ln)
            if textobject.getY() - line_height < 15 * mm:
                c.drawText(textobject)
                c.showPage()
                c.setFont(font_name, 11)
                textobject = c.beginText()
                textobject.setTextOrigin(20 * mm, height - 20 * mm)
        c.drawText(textobject)
        c.showPage()
        c.save()
        buf.seek(0)
        return buf.read()

    except Exception:
        # Fallback: FPDF (limited for complex scripts)
        from fpdf import FPDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        font_path = os.path.join(app.root_path, 'static', 'fonts', 'DejaVuSans.ttf')
        if os.path.exists(font_path):
            pdf.add_font('DejaVu', '', font_path, uni=True)
            pdf.set_font('DejaVu', size=12)
        else:
            pdf.set_font('Arial', size=12)
        for line in (text or "").splitlines() or [""]:
            pdf.multi_cell(0, 8, txt=line)
        return pdf.output(dest='S').encode('latin-1', errors='ignore')


# --------------------------------------------------------------------------------------
# Background Job Manager (simple in-process queue with progress)
# --------------------------------------------------------------------------------------
class JobStore:
    def __init__(self):
        self._jobs = {}
        self._lock = threading.Lock()

    def create(self, total=100):
        job_id = uuid.uuid4().hex
        with self._lock:
            self._jobs[job_id] = {
                "percent": 0,
                "message": "Queued",
                "done": False,
                "error": None,
                "meeting_id": None,
                "total": total,
                "started_at": datetime.datetime.utcnow().isoformat()
            }
        return job_id

    def update(self, job_id, percent=None, message=None, error=None, meeting_id=None, done=None):
        with self._lock:
            j = self._jobs.get(job_id)
            if not j:
                return
            if percent is not None:
                j["percent"] = max(0, min(100, int(percent)))
            if message is not None:
                j["message"] = message
            if error is not None:
                j["error"] = str(error)
            if meeting_id is not None:
                j["meeting_id"] = str(meeting_id)
            if done is not None:
                j["done"] = bool(done)

    def get(self, job_id):
        with self._lock:
            return self._jobs.get(job_id, None)

JOB_STORE = JobStore()


def _process_pipeline_in_background(job_id, *, user_id, file_path, filename, language, target_languages):
    """Runs the full pipeline, updates JOB_STORE, and logs timings."""
    def p(pct, msg):
        JOB_STORE.update(job_id, percent=pct, message=msg)

    try:
        with app.app_context():
            db = get_db()

            total_t0 = datetime.datetime.utcnow()

            # 1) Transcribe
            p(5, "Transcribing audio…")
            with step_timer("Transcribe"):
                raw_transcript, detected_lang = transcribe_audio(file_path, language)

            if detected_lang and detected_lang != language:
                p(12, f"Note: detected '{detected_lang}', using selected '{language}'")
            else:
                p(12, "Cleaning transcript…")

            # 2) Clean (source)
            with step_timer("Clean (source)"):
                optimized_source = optimize_text(raw_transcript, lang=language)

            # 3) Multilingual outputs
            p(20, "Preparing outputs…")
            transcript_by_lang = {language: optimized_source}
            notes_by_lang = {}

            n = max(len(target_languages), 1)
            per_target = 80 / n
            cur = 20

            for tgt in target_languages:
                # translate + clean
                cur += per_target * 0.4
                p(cur, f"Translating & cleaning → {SUPPORTED_OUTPUT_LANGS.get(tgt, tgt)}")
                with step_timer(f"Translate+Clean {language}->{tgt}"):
                    if tgt == language:
                        ttext = optimized_source
                    else:
                        ttext = translate_between_languages(optimized_source, language, tgt)
                        ttext = optimize_text(ttext, lang=tgt)
                transcript_by_lang[tgt] = ttext

                # notes
                cur += per_target * 0.6
                p(cur, f"Generating notes → {SUPPORTED_OUTPUT_LANGS.get(tgt, tgt)}")
                with step_timer(f"Notes {tgt}"):
                    notes_by_lang[tgt] = generate_meeting_notes_smart(ttext, target_language=tgt)

            # 4) Persist
            p(min(98, int(cur)), "Saving to database…")
            with step_timer("Persist to DB"):
                meeting_id = db.meetings_col.insert_one({
                    'user_id': user_id,
                    'audio_filename': filename,
                    'selected_source_language': language,
                    'detected_source_language': detected_lang or None,
                    'raw_transcript': raw_transcript,
                    'optimized_source': optimized_source,
                    'target_languages': target_languages,
                    'transcript_by_lang': transcript_by_lang,
                    'notes_by_lang': notes_by_lang,
                    'timestamp': datetime.datetime.now(),
                    'deleted': False
                }).inserted_id

            total_dt = (datetime.datetime.utcnow() - total_t0).total_seconds()
            logging.info(f"[TIMING] Pipeline total: {total_dt:.2f}s for file={filename}")

            JOB_STORE.update(job_id, percent=100, message="Complete", meeting_id=str(meeting_id), done=True)

    except Exception as e:
        JOB_STORE.update(job_id, error=str(e), message="Error", done=True)


# --------------------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------------------
@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("20 per hour")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        fullname = (request.form.get('fullname') or '').strip()
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        confirm_password = request.form.get('confirmPassword') or ''
        
        if not fullname or not username or not password:
            flash('Full name, username and password are required')
            return redirect(url_for('register'))

        # Password validation
        if len(password) < 6:
            flash('Password must be at least 6 characters long')
            return redirect(url_for('register'))
        
        if not re.search(r'[A-Z]', password):
            flash('Password must contain at least one capital letter (A-Z)')
            return redirect(url_for('register'))
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
            flash('Password must contain at least one special character (!@#$%^&*)')
            return redirect(url_for('register'))
        
        if not re.search(r'[0-9]', password):
            flash('Password must contain at least one number (0-9)')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('register'))

        db = get_db()
        if db.users_col.find_one({'username': username}):
            flash('Username already exists')
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password)
        db.users_col.insert_one({'fullname': fullname, 'username': username, 'password': hashed_pw})
        flash('Registered successfully. Please login.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")   # brute-force protection
def login():

    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        db = get_db()
        user = db.users_col.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            user_obj = User(str(user['_id']), username, user.get('fullname'))
            login_user(user_obj, remember=True)
            session['username'] = username  # fallback for loader
            return redirect(url_for('dashboard'))

        flash('Invalid username or password')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/upload', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per hour")
def upload():
    if request.method == 'POST':
        file = request.files.get('audio')
        meeting_url = (request.form.get('meeting_url') or '').strip()

        # REQUIRED by SRS: user must pick the source language
        language = (request.form.get('language') or '').strip().lower()
        if language not in SUPPORTED_INPUT_LANGS:
            flash(f"Unsupported or missing source language. Supported: {', '.join(SUPPORTED_INPUT_LANGS.keys())}")
            return redirect(request.url)

        # OPTIONAL outputs; default to English if none selected
        target_languages = request.form.getlist('target_languages') or []
        target_languages = [t.strip().lower() for t in target_languages if t in SUPPORTED_OUTPUT_LANGS]
        if not target_languages:
            target_languages = DEFAULT_OUTPUT_LANGS[:]

        # Accept file OR URL
        try:
            if meeting_url:
                url = meeting_url
                if "drive.google.com" in url:
                    # Extract file id
                    m = re.search(r"/d/([A-Za-z0-9_-]+)", url) or re.search(r"[?&]id=([A-Za-z0-9_-]+)", url)
                    if not m:
                        raise ValueError(
                            "Google Drive link detected but no file id found. "
                            "Make it shareable ('Anyone with the link') or use a direct download link."
                        )
                    file_id = m.group(1)
                    direct_url = f"https://drive.google.com/uc?id={file_id}&export=download"
                    with requests.get(direct_url, stream=True, timeout=60) as r:
                        r.raise_for_status()
                        ctype = (r.headers.get('Content-Type') or '').lower().split(';')[0]
                        ext_map = {
                            'audio/mpeg': 'mp3',
                            'audio/mp3': 'mp3',
                            'audio/wav': 'wav',
                            'audio/x-wav': 'wav',
                            'audio/mp4': 'mp4',
                            'video/mp4': 'mp4',
                            'application/octet-stream': 'mp3',
                        }
                        ext = ext_map.get(ctype, 'mp3')
                        filename = secure_filename(f"drive_{file_id}.{ext}")
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        with open(file_path, 'wb') as f:
                            for chunk in r.iter_content(chunk_size=8192):
                                if chunk:
                                    f.write(chunk)
                else:
                    # Normalize Dropbox to direct download
                    if "dropbox.com" in url:
                        if "?dl=0" in url:
                            url = url.replace("?dl=0", "?dl=1")
                        elif "dl=1" not in url:
                            url = url + ("&dl=1" if "?" in url else "?dl=1")

                    # Generic fetch
                    file_path = fetch_media_from_url(url, app.config['UPLOAD_FOLDER'])
                    filename = os.path.basename(file_path)

            elif file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
            else:
                flash('Provide a file OR a direct media URL (.mp3/.wav/.mp4)')
                return redirect(request.url)

        except Exception as e:
            flash(f'URL download failed: {e}')
            return redirect(request.url)

        # ----- Start background job (thread) instead of doing pipeline inline -----
        job_id = JOB_STORE.create()
        threading.Thread(
            target=_process_pipeline_in_background,
            args=(job_id,),
            kwargs=dict(
                user_id=current_user.id,
                file_path=file_path,
                filename=filename,
                language=language,
                target_languages=target_languages
            ),
            daemon=True
        ).start()

        # Redirect user to processing page
        return redirect(url_for('processing', job_id=job_id))

    # GET → pass language maps for the template
    return render_template(
        'upload.html',
        SUPPORTED_INPUT_LANGS=SUPPORTED_INPUT_LANGS,
        SUPPORTED_OUTPUT_LANGS=SUPPORTED_OUTPUT_LANGS
    )


@app.route('/processing/<job_id>')
@login_required
def processing(job_id):
    job = JOB_STORE.get(job_id)
    if not job:
        flash("Invalid job id")
        return redirect(url_for('upload'))
    return render_template('processing.html', job_id=job_id)


@app.route('/status/<job_id>')
@login_required
def status(job_id):
    job = JOB_STORE.get(job_id)
    if not job:
        return jsonify({"error": "not_found"}), 404
    return jsonify(job), 200


@app.route('/notes/<meeting_id>')
@login_required
def view_notes(meeting_id):
    db = get_db()
    try:
        oid = ObjectId(meeting_id)
    except Exception:
        flash('Invalid meeting id')
        return redirect(url_for('dashboard'))

    meeting = db.meetings_col.find_one({'_id': oid, 'user_id': current_user.id})
    if not meeting:
        flash('Meeting not found')
        return redirect(url_for('dashboard'))

    notes_by_lang = meeting.get('notes_by_lang') or {}
    available_langs = sorted(list(notes_by_lang.keys()))
    if not available_langs:
        # Backward compatibility
        single = meeting.get('final_notes', '') or ''
        fallback_lang = meeting.get('selected_source_language') or meeting.get('original_language', 'en')
        available_langs = [fallback_lang]
        notes_by_lang = {fallback_lang: single}

    sel = (request.args.get('lang') or '').lower()
    if sel not in available_langs:
        sel = 'en' if 'en' in available_langs else available_langs[0]

    notes_text = notes_by_lang.get(sel, '')
    if HAS_MD:
        html = md.markdown(notes_text, extensions=['extra', 'sane_lists'])
        notes_html = Markup(html)
    else:
        notes_html = Markup(f'<pre style="white-space: pre-wrap;">{escape(notes_text)}</pre>')

    return render_template(
        'notes.html',
        notes_html=notes_html,
        meeting_id=meeting_id,
        selected_lang=sel,
        available_langs=available_langs,
        SUPPORTED_LANGS=SUPPORTED_OUTPUT_LANGS
    )


@app.route('/download/<meeting_id>/<format>')
@login_required
def download(meeting_id, format):
    db = get_db()
    try:
        oid = ObjectId(meeting_id)
    except Exception:
        flash('Invalid meeting id')
        return redirect(url_for('dashboard'))

    meeting = db.meetings_col.find_one({'_id': oid, 'user_id': current_user.id})
    if not meeting:
        flash('Meeting not found')
        return redirect(url_for('dashboard'))

    sel = (request.args.get('lang') or '').lower()
    notes_by_lang = meeting.get('notes_by_lang') or {}
    if sel and sel in notes_by_lang:
        notes = notes_by_lang[sel]
    else:
        if 'en' in notes_by_lang:
            sel = 'en'
            notes = notes_by_lang['en']
        else:
            notes = meeting.get('final_notes', '') or ''
            sel = sel or meeting.get('selected_source_language', 'en')

    plain = notes

    if format == 'pdf':
        pdf_bytes = generate_pdf_bytes(plain, lang_code=sel)
        buffer = BytesIO(pdf_bytes)
        return Response(
            FileWrapper(buffer, 1024 * 1024),
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename=meeting_notes_{sel}.pdf'},
            direct_passthrough=True
        )

    elif format == 'docx':
        from docx import Document
        buffer = BytesIO()
        doc = Document()
        for line in (plain or '').splitlines() or ['']:
            doc.add_paragraph(line)
        doc.save(buffer)
        buffer.seek(0)
        return Response(
            FileWrapper(buffer, 1024 * 1024),
            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            headers={'Content-Disposition': f'attachment; filename=meeting_notes_{sel}.docx'},
            direct_passthrough=True
        )

    flash('Invalid format')
    return redirect(url_for('view_notes', meeting_id=meeting_id))


@app.route('/share/<meeting_id>', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
def share_meeting(meeting_id):
    db = get_db()
    try:
        oid = ObjectId(meeting_id)
    except Exception:
        flash('Invalid meeting id')
        return redirect(url_for('dashboard'))

    meeting = db.meetings_col.find_one({'_id': oid, 'user_id': current_user.id})
    if not meeting:
        flash('Meeting not found')
        return redirect(url_for('dashboard'))

    recipient = (request.form.get('email') or '').strip()
    sel = (request.form.get('lang') or request.args.get('lang') or '').lower()

    if not recipient:
        flash('Recipient email required')
        return redirect(url_for('view_notes', meeting_id=meeting_id))

    notes_by_lang = meeting.get('notes_by_lang') or {}
    notes = notes_by_lang.get(sel) or notes_by_lang.get('en') or (meeting.get('final_notes', '') or '')
    lang_for_name = sel or ('en' if 'en' in notes_by_lang else meeting.get('selected_source_language', 'en'))

    # Generate PDF bytes (multilingual-friendly)
    pdf_bytes = generate_pdf_bytes(notes, lang_code=lang_for_name)

    # Build and send the email
    msg = EmailMessage()
    msg['Subject'] = f"Meeting Notes — {meeting.get('audio_filename','file')} ({lang_for_name})"
    msg['From'] = os.getenv("SMTP_FROM")
    msg['To'] = recipient
    msg.set_content("Attached are your meeting notes (PDF).")
    msg.add_attachment(pdf_bytes, maintype='application', subtype='pdf', filename=f'meeting_notes_{lang_for_name}.pdf')

    context = ssl.create_default_context()
    with smtplib.SMTP(os.getenv("SMTP_HOST"), int(os.getenv("SMTP_PORT", "587"))) as server:
        server.starttls(context=context)
        server.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASS"))
        server.send_message(msg)

    flash('Email sent!')
    return redirect(url_for('view_notes', meeting_id=meeting_id, lang=lang_for_name))


@app.route('/delete/<meeting_id>', methods=['POST'])
@login_required
def delete_meeting(meeting_id):
    try:
        oid = ObjectId(meeting_id)
    except Exception:
        flash("Invalid id")
        return redirect(url_for('history'))

    db = get_db()
    res = db.meetings_col.update_one(
        {'_id': oid, 'user_id': current_user.id},
        {'$set': {
            'deleted': True,
            'deleted_at': datetime.datetime.utcnow(),
            'deleted_by': current_user.id
        }}
    )
    flash('Moved to trash' if res.modified_count else 'Not found')
    return redirect(url_for('history', page=request.args.get('page', 1), q=request.args.get('q',''), lang=request.args.get('lang','')))


@app.route('/restore/<meeting_id>', methods=['POST'])
@login_required
def restore_meeting(meeting_id):
    try:
        oid = ObjectId(meeting_id)
    except Exception:
        flash("Invalid id")
        return redirect(url_for('history', include_deleted=1))

    db = get_db()
    res = db.meetings_col.update_one(
        {'_id': oid, 'user_id': current_user.id},
        {'$set': {'deleted': False}, '$unset': {'deleted_at': '', 'deleted_by': ''}}
    )
    flash('Restored' if res.modified_count else 'Not found')
    return redirect(url_for('history', include_deleted=1))


@app.route('/purge/<meeting_id>', methods=['POST'])
@login_required
def purge_meeting(meeting_id):
    """Permanent delete. Also remove the local file if present."""
    try:
        oid = ObjectId(meeting_id)
    except Exception:
        flash("Invalid id")
        return redirect(url_for('history', include_deleted=1))

    db = get_db()
    m = db.meetings_col.find_one({'_id': oid, 'user_id': current_user.id})
    if not m:
        flash('Not found')
        return redirect(url_for('history', include_deleted=1))

    # try to remove local file
    fname = m.get('audio_filename')
    if fname:
        fpath = os.path.join(app.config['UPLOAD_FOLDER'], fname)
        try:
            if os.path.exists(fpath):
                os.remove(fpath)
        except Exception as e:
            app.logger.warning(f"File remove failed: {e}")

    res = db.meetings_col.delete_one({'_id': oid, 'user_id': current_user.id})
    flash('Deleted forever' if res.deleted_count else 'Not found')
    return redirect(url_for('history', include_deleted=1))


@app.route('/history')
@login_required
def history():
    db = get_db()
    # filters
    q = (request.args.get('q') or '').strip()
    lang = (request.args.get('lang') or '').strip().lower()
    include_deleted = request.args.get('include_deleted') == '1'

    # Build base filter
    base_flt = {'user_id': current_user.id}
    if not include_deleted:
        base_flt['deleted'] = {'$ne': True}
    if q:
        base_flt['audio_filename'] = {'$regex': q, '$options': 'i'}
    
    # Handle language filter - check if language exists in output languages
    if lang:
        flt = {
            '$and': [
                base_flt,
                {
                    '$or': [
                        {'target_languages': lang},  # Language was selected as output
                        {f'notes_by_lang.{lang}': {'$exists': True}}  # Notes exist in this language
                    ]
                }
            ]
        }
    else:
        flt = base_flt

    # pagination
    page = max(int(request.args.get('page', 1)), 1)
    per_page = 10
    total = db.meetings_col.count_documents(flt)
    pages = max(math.ceil(total / per_page), 1)
    page = min(page, pages)

    cursor = (db.meetings_col.find(flt)
              .sort('timestamp', -1)
              .skip((page - 1) * per_page)
              .limit(per_page))

    meetings = []
    for m in cursor:
        m['_id_str'] = str(m['_id'])
        meetings.append(m)

    return render_template(
        'history.html',
        meetings=meetings,
        page=page,
        pages=pages,
        total=total,
        q=q,
        lang=lang,
        include_deleted=include_deleted,
        SUPPORTED_OUTPUT_LANGS=SUPPORTED_OUTPUT_LANGS
    )


# --------------------------------------------------------------------------------------
# Indexes (with auto-migration for language index)
# --------------------------------------------------------------------------------------
with app.app_context():
    db = get_db()
    try:
        # Always useful
        db.meetings_col.create_index([('user_id', ASCENDING), ('timestamp', DESCENDING)], name='user_time_idx')
        db.meetings_col.create_index([('audio_filename', TEXT)], name='filename_text_idx')
        db.meetings_col.create_index([('deleted', ASCENDING)], name='deleted_idx')

        # ---- Language index migration ----
        existing = {ix['name']: ix for ix in db.meetings_col.list_indexes()}
        old = existing.get('lang_idx')
        if old:
            old_keys = list(old['key'].items())
            if len(old_keys) == 1 and old_keys[0][0] == 'original_language' and old_keys[0][1] == 1:
                db.meetings_col.drop_index('lang_idx')

        # Create the new index with a NEW name to avoid collisions
        db.meetings_col.create_index([('selected_source_language', ASCENDING)], name='selected_lang_idx')

    except Exception as e:
        app.logger.warning(f"Index init failed: {e}")


# --------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)
