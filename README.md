# TalkToText Pro — Multilingual Meeting Notes (Flask)

Turn audio into clean transcripts and structured meeting notes in multiple languages. Upload a file or paste a URL (Google Drive / Dropbox supported), pick the **source language (required)** and **desired output languages (optional; defaults to English)**, then download/share notes (PDF/DOCX) or view your history.

## Features
- Email/password auth (Flask-Login, hashed passwords)
- Upload **.mp3 / .wav / .mp4** or paste URL (Drive/Dropbox direct download handled)
- **Source language is required**; **output languages optional** (default: English)
- Pipeline: Transcribe → Clean → Translate (per output lang) → Generate structured notes (Markdown)
- Multilingual notes view/download (PDF/DOCX) and **email share**
- Background processing with a progress screen (`/processing/<job_id>` + `/status/<job_id>`)
- History with search, soft-delete (trash), restore, and purge
- CSRF protection + basic rate limiting
- Timing logs for each step (see terminal)
- Unicode PDF (ReportLab/FPDF) with best-effort RTL support (Urdu/Arabic)

## Project Structure
```
.
├─ app.py                # main app (routes, background job, helpers)
├─ db_utils.py           # Mongo connection + User loader/helpers
├─ openai_utils.py       # Whisper/Chat API helpers (transcribe/clean/translate/notes)
├─ timing_utils.py       # step_timer / logging helpers
├─ bench.py              # CLI quick benchmark (bypass web UI)
├─ templates/            # Jinja (base, login, register, dashboard, upload, notes, history, processing)
└─ static/
   └─ fonts/             # DejaVuSans.ttf, NotoSans, NotoNaskhArabic (optional but recommended)
```

## Requirements
- Python 3.10+ (tested on 3.12)
- MongoDB (Atlas/local), OpenAI API key, SMTP account

### Install
```bash
python -m venv venv
venv\Scripts\activate         # Windows
# source venv/bin/activate      # macOS/Linux

pip install -U pip
pip install flask flask-login flask-wtf flask-limiter python-dotenv pymongo requests             openai fpdf python-docx markdown nltk reportlab arabic-reshaper python-bidi
```

> `reportlab`, `arabic-reshaper`, and `python-bidi` are optional but improve Urdu/Arabic PDF output.

## Environment Variables (`.env`)
```
FLASK_SECRET_KEY=replace_me
FLASK_ENV=development

# Mongo
MONGODB_URI=mongodb+srv://user:pass@cluster/db
MONGODB_DBNAME=talktotext_db

# OpenAI
OPENAI_API_KEY=sk-...

# SMTP (for /share)
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USER=no-reply@your-domain.com
SMTP_PASS=yourStrongPassword
SMTP_FROM="TalkToText Pro" <no-reply@your-domain.com>
```

## Run
```bash
python app.py
# open http://127.0.0.1:5000
```

## Usage (happy path)
1. **Register** → **Login**.
2. Go to **Upload**.
   - Pick **audio file** *or* paste **URL** (Drive/Dropbox supported).
   - Choose **Original Language** (required).
   - Choose one or more **Output Languages** (optional; empty = English).
3. Submit → you’ll see **Processing** progress.
4. After completion you’re redirected to **Notes** (language switcher if multiple).
5. **Download** PDF/DOCX, **Share via email**, or check **History**.

## Multi-language behavior
- **Source language (required)**: enforced by the form and used by transcription.
- **Output language(s) (optional)**: if none selected → defaults to **English**.
- Notes/transcripts are stored per language; the Notes page lets you switch/download/share per language.

## Timings
- Step timings are logged to the terminal, e.g.:
  ```
  [TIMING] Transcribe: 22.10s
  [TIMING] Clean (source): 1.97s
  [TIMING] Translate+Clean en->ur: 4.11s
  [TIMING] Notes ur: 3.42s
  [TIMING] Persist to DB: 0.18s
  [TIMING] Pipeline total: 34.71s for file=meeting.mp3
  ```
- CLI quick check:
  ```bash
  python bench.py ".\sample.mp3" en en,ur,fr
  ```

## Data Model (Mongo)
**users_col**
- `_id`, `username`, `password` (hashed)

**meetings_col**
- `_id`, `user_id`, `audio_filename`
- `selected_source_language`, `detected_source_language`
- `raw_transcript`, `optimized_source`
- `target_languages` (list)
- `transcript_by_lang` (dict)
- `notes_by_lang` (dict)
- `deleted` (bool), `deleted_at`, `deleted_by`
- `timestamp`

## Routes (main ones)
- `/`, `/register`, `/login`, `/logout`, `/dashboard`
- `/upload` (POST starts background job) → `/processing/<job_id>` → `/status/<job_id>`
- `/notes/<meeting_id>` (view per language)
- `/download/<meeting_id>/<pdf|docx>?lang=XX`
- `/share/<meeting_id>` (POST email PDF; optional `lang` in form)
- `/history`, `/delete/<id>`, `/restore/<id>`, `/purge/<id>`

## Troubleshooting
- **Index init failed (lang_idx conflict)**: auto-migration creates `selected_lang_idx`. Old warning is safe.
- **SMTP not defined**: set all SMTP envs; some providers require “App Passwords”.
- **Whisper model errors**: the code falls back to `gpt-4o-mini-transcribe`.
- **Urdu/Arabic PDF broken**: add fonts to `static/fonts/` and install `reportlab`, `arabic-reshaper`, `python-bidi`.

## Security Notes
- CSRF on all forms, rate limiting on auth/upload/share.
- Passwords are **hashed** (Werkzeug).
- Cookies set `HttpOnly` + `SameSite=Lax` (+ `Secure` in production).
- Uploaded files saved under `uploads/`; consider periodic cleanup/purge in prod.

