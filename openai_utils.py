# openai_utils.py
import os
from typing import Optional, Tuple
from openai import OpenAI

# Initialize client from env var
openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# -------- Transcription (user-selected source language) --------
def transcribe_audio(file_path: str, language: str) -> Tuple[str, str]:
    """
    Transcribe with the user-selected source language (per SRS).
    Returns (text, detected_language_code_or_empty).
    """
    try:
        with open(file_path, "rb") as audio_file:
            try:
                # Prefer whisper-1 in verbose_json to get a detected language field
                t = openai_client.audio.transcriptions.create(
                    model="whisper-1",
                    file=audio_file,
                    language=language,              # force selected source
                    response_format="verbose_json"  # to get .language
                )
                text = (getattr(t, "text", "") or "").strip()
                detected = (getattr(t, "language", "") or "").strip().lower() or ""
                return text, detected
            except Exception:
                # Fallback model if whisper-1 unavailable
                audio_file.seek(0)
                fallback = openai_client.audio.transcriptions.create(
                    model="gpt-4o-mini-transcribe",
                    file=audio_file,
                    language=language
                )
                text = getattr(fallback, "text", "") or ""
                return text.strip(), ""  # fallback may not return detected language
    except Exception as e:
        return f"[Transcription error] {e}", ""


# -------- Translation (generic source -> target) --------
def translate_between_languages(text: str, source_lang: str, target_lang: str) -> str:
    """
    Translate text from source_lang to target_lang.
    Preserves structure/formatting; no added commentary.
    """
    if not text:
        return text
    s = (source_lang or "").lower()
    t = (target_lang or "").lower()
    if s == t or t in ("", "auto"):
        return text

    try:
        resp = openai_client.chat.completions.create(
            model="gpt-4o",
            temperature=0.1,
            max_tokens=1800,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a precise, literal translator. "
                        f"Translate from {s or 'auto-detected'} to {t}. "
                        "HARD RULES:\n"
                        "1) Preserve paragraph breaks, line breaks, and list formatting exactly.\n"
                        "2) Preserve Markdown (headings, tables, code fences), inline code, and URLs.\n"
                        "3) Preserve numbers, names, dates, product/spec terms; do NOT normalize units.\n"
                        "4) Keep bracketed tags like [applause], [music], [inaudible] unchanged.\n"
                        "5) Do NOT add explanations, notes, or brackets of your own.\n"
                        "6) Output ONLY the translation text, no preface or quotes."
                    ),
                },
                {"role": "user", "content": text},
            ],
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        return f"[Translation error] {e}"


# -------- Light Clean-up (language-aware) --------
def optimize_text(text: str, lang: Optional[str] = None) -> str:
    """
    Clean transcripts conservatively: remove timestamps/noise/duplicate lines,
    fix obvious ASR artifacts when certain, and preserve layout & Markdown.
    """
    if not text:
        return text
    try:
        lang_hint = (lang or "auto").lower()
        resp = openai_client.chat.completions.create(
            model="gpt-4o",
            temperature=0.1,
            max_tokens=2000,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a careful transcript cleaner. "
                        f"Text language: {lang_hint}. "
                        "GOAL: improve readability WITHOUT losing meaning.\n"
                        "ALLOWED REMOVALS: timestamps like [00:01:23], noise tags like [applause]/[music]/[inaudible], "
                        "verbatim duplicates, obvious ASR artifacts.\n"
                        "ALLOWED FIXES: small typo fixes when context is certain.\n"
                        "PRESERVE: speaker labels (e.g., 'Alice:'), paragraph breaks, Markdown formatting, code blocks, URLs, lists.\n"
                        "DO NOT: translate, paraphrase heavily, reorder content, or remove any substantive info.\n"
                        "Output ONLY the cleaned transcript; keep the original language."
                    ),
                },
                {"role": "user", "content": text},
            ],
        )
        return resp.choices[0].message.content.strip()
    except Exception:
        return text


# -------- Structured Notes (Markdown) in target language --------
def generate_meeting_notes(optimized_text: str, target_language: str = "en") -> str:
    """
    Produce structured Markdown notes in target_language with strict anti-hallucination rules.
    """
    tl = (target_language or "en").lower()
    system_prompt = (
        "You are a professional note-taker. "
        "Produce structured Markdown notes ONLY. "
        "HARD RULES:\n"
        "• Never invent facts, names, dates, or metrics not present in the text.\n"
        "• If a field is missing, write exactly: Not specified.\n"
        "• Keep facts concrete; avoid vague summaries.\n"
        f"• Write the notes in: {tl}."
    )

    user_prompt = f"""
Source Text (already cleaned):
\"\"\"{optimized_text}\"\"\"


## Executive Summary
- Provide 2–5 bullets (concise, factual).

## Key Discussion Points
- Bulleted list of main topics/arguments/decisions with concrete details (figures, dates, owners) when present.

## Decisions
- If present, list each decision as a bullet.
- If none: Not specified.

## Action Items
- Use: **Owner** — Action — Due date (or “Not specified”).
- If none: Not specified.

## Risks & Blockers
- If any, list concisely; else: Not specified.

## Sentiment / Tone
- One short line (e.g., positive, mixed, tense) + 1–2 cues.

## Metadata (Inferred)
- Date/Time: (infer if present; else Not specified)
- Meeting/Session Title: (infer short title; else Not specified)
- Participants/Speakers: (names/roles if present; else Not specified)
"""
    try:
        resp = openai_client.chat.completions.create(
            model="gpt-4o",
            temperature=0.2,
            max_tokens=1800,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        return (
            "## Executive Summary\n- Not specified\n\n"
            "## Key Discussion Points\n- Not specified\n\n"
            "## Decisions\nNot specified\n\n"
            "## Action Items\nNot specified\n\n"
            "## Risks & Blockers\nNot specified\n\n"
            "## Sentiment / Tone\nNot specified\n\n"
            "## Metadata (Inferred)\n- Date/Time: Not specified\n- Meeting/Session Title: Not specified\n- Participants/Speakers: Not specified\n\n"
            f"> [Notes generation error] {e}"
        )


# -------- Token-limit handling: condense + smart notes --------
def condense_text_for_notes(text: str, lang_hint: str = "auto", target_tokens: int = 3000) -> str:
    """
    Condense very long transcripts to a compact, information-dense version.
    Preserve concrete facts (decisions, owners, dates, metrics) and paragraphing.
    """
    if not text:
        return text
    try:
        resp = openai_client.chat.completions.create(
            model="gpt-4o",
            temperature=0.1,
            max_tokens=3500,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an expert editor. Create a compact, information-dense condensation of the transcript. "
                        "PRESERVE: decisions, owners, dates, deadlines, metrics, numbers, key arguments, risks, and follow-ups. "
                        "REMOVE: filler, small talk, exact repeats. "
                        f"Input language may be {lang_hint}. Keep the same language as input. "
                        "Preserve paragraph breaks; do not add commentary."
                    ),
                },
                {"role": "user", "content": text[:120000]},
            ],
        )
        return resp.choices[0].message.content.strip()
    except Exception:
        # Safe fallback: truncate
        return text[:20000]


def generate_meeting_notes_smart(optimized_text: str, target_language: str = "en") -> str:
    """
    Wrapper that avoids token overflows:
    condense first if text is very long, then produce structured notes.
    """
    if not optimized_text:
        return generate_meeting_notes("", target_language=target_language)

    # rough char-based threshold (≈ tokens ~ chars/4)
    if len(optimized_text) > 20000:  # ~5k tokens ballpark
        condensed = condense_text_for_notes(optimized_text, lang_hint="auto", target_tokens=3000)
        return generate_meeting_notes(condensed, target_language=target_language)
    else:
        return generate_meeting_notes(optimized_text, target_language=target_language)
