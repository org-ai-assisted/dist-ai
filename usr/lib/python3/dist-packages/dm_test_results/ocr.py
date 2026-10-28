## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Shared tesseract OCR for the screenshot tools (image-redact-tokens masks matching word
boxes; image-ocr-sidecar + image-text-assert read the text). One authoritative copy of the
tesseract invocation, so the word-box and plain-text paths cannot drift.

Determinism: tesseract output is deterministic for a given image + tesseract VERSION + psm.
The text therefore carries OCR glyph noise and is version-tied -- so content ASSERTION matches
EXPECTED TOKENS (normalized, case-insensitive) rather than exact text, which tolerates that
noise and minor UI/OCR drift. No numpy (same leaf-module contract as imaging.py / image_gate.py)."""

import subprocess


def tesseract_words(path, psm=6):
    """Return [(left, top, width, height, text), ...] from tesseract's TSV word boxes.

    --psm 6 (assume a uniform block of text) suits a console/log/desktop frame. Raises on a
    tesseract/OS failure so a caller can treat the frame as best-effort-unchanged."""
    ## Capture as BYTES (no text=True): tesseract's stderr can carry non-UTF-8 warning bytes, and
    ## text=True would strict-decode stderr too and crash the read. Decode only stdout, with
    ## 'replace' so a stray bad byte in the recognized text degrades to U+FFFD, never an exception.
    proc = subprocess.run(
        ["tesseract", path, "stdout", "--psm", str(psm), "tsv"],
        capture_output=True, check=True,
    )
    lines = proc.stdout.decode("utf-8", "replace").splitlines()
    if not lines:
        return []
    header = lines[0].split("\t")
    col = {name: i for i, name in enumerate(header)}
    need = ("left", "top", "width", "height", "text")
    if not all(k in col for k in need):
        return []
    words = []
    for row in lines[1:]:
        cells = row.split("\t")
        if len(cells) <= col["text"]:
            continue
        text = cells[col["text"]]
        if not text.strip():
            continue
        try:
            left = int(cells[col["left"]])
            top = int(cells[col["top"]])
            width = int(cells[col["width"]])
            height = int(cells[col["height"]])
        except ValueError:
            continue
        words.append((left, top, width, height, text))
    return words


def ocr_text(path, psm=6):
    """Deterministic plain-text OCR (line structure preserved). Raises on a tesseract/OS
    failure so the caller decides whether a read miss is fatal. Captures as BYTES (no text=True):
    tesseract's stderr can carry non-UTF-8 warning bytes, and text=True would strict-decode stderr
    too and crash. Decode only stdout, with 'replace', so a stray bad byte degrades to U+FFFD and
    the recognized text is never lost to an exception."""
    proc = subprocess.run(
        ["tesseract", path, "stdout", "--psm", str(psm)],
        capture_output=True, check=True,
    )
    return proc.stdout.decode("utf-8", "replace")


## The content gate OCRs varied layouts: a multi-region GUI installer page (a full-width row
## separated by whitespace, e.g. the "Encrypt system" checkbox) AND a simple centered menu (the
## GRUB "Choose boot mode" screen). NO single page-segmentation mode reads both -- psm 6 (uniform
## block) drops the separated GUI row, while psm 3 (auto layout) mis-segments the centered menu and
## drops its text. The UNION of the two reads every token either reads, with no per-frame tuning.
ROBUST_PSMS = (3, 6)


def ocr_texts(path, psms=ROBUST_PSMS):
    """OCR the frame under each page-segmentation mode; return the list of transcripts that
    SUCCEEDED, in order. Raises (like ocr_text) ONLY if EVERY mode failed -- so one mode erroring
    never hides another's successful read, which would otherwise turn a real content mismatch into
    a silent 'ocr-error'. See ROBUST_PSMS for why multiple modes are needed."""
    texts = []
    last_exc = None
    for psm in psms:
        try:
            texts.append(ocr_text(path, psm=psm))
        except (subprocess.CalledProcessError, OSError) as exc:
            ## ocr_text decodes stdout with 'replace' and never strict-decodes stderr, so a bad byte
            ## is no longer an exception -- only a real tesseract/OS failure reaches here.
            last_exc = exc
    if not texts:
        raise last_exc if last_exc is not None else RuntimeError(
            "ocr_texts: no page-segmentation modes given")
    return texts


def ocr_text_union(path, psms=ROBUST_PSMS):
    """Concatenated OCR across modes for DISPLAY ONLY (the published sidecar) -- robust to a
    per-mode failure (reuses ocr_texts). NOT for token matching: use ocr_texts +
    missing_tokens_multi, whose independent per-transcript check avoids the cross-transcript seam
    that substring-matching one joined blob would create."""
    return "\n".join(ocr_texts(path, psms))


def normalize(text):
    """Lowercase and collapse every whitespace run to a single space, for token matching
    that tolerates OCR spacing and case noise."""
    return " ".join(text.lower().split())


def missing_tokens(text, expected):
    """The expected tokens (in order, de-duplicated preserving first position) NOT present in
    TEXT after normalization. A token is matched case-insensitively with internal whitespace
    normalized, so 'Welcome to Calamares' matches regardless of OCR spacing/case. An expected
    token that is empty/whitespace-only after normalization is ignored (it would match every
    frame -- fail-open)."""
    hay = normalize(text)
    missing = []
    seen = set()
    for tok in expected:
        norm = normalize(tok)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        if norm not in hay:
            missing.append(tok)
    return missing


def missing_tokens_multi(texts, expected):
    """missing_tokens across SEVERAL transcripts (e.g. one per page-segmentation mode): a token is
    present when it appears in ANY ONE transcript, and missing only when absent from them ALL. Each
    transcript is normalized and matched INDEPENDENTLY -- never concatenated -- so a multi-word
    token cannot be matched across the boundary between two transcripts (the false-match seam a
    joined-text union would allow)."""
    hays = [normalize(text) for text in texts]
    missing = []
    seen = set()
    for tok in expected:
        norm = normalize(tok)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        if not any(norm in hay for hay in hays):
            missing.append(tok)
    return missing
