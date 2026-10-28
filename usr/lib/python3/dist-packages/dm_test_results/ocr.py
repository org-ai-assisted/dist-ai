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
    proc = subprocess.run(
        ["tesseract", path, "stdout", "--psm", str(psm), "tsv"],
        capture_output=True, text=True, check=True,
    )
    lines = proc.stdout.splitlines()
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
    failure so the caller decides whether a read miss is fatal."""
    proc = subprocess.run(
        ["tesseract", path, "stdout", "--psm", str(psm)],
        capture_output=True, text=True, check=True,
    )
    return proc.stdout


## The content gate OCRs varied layouts: a multi-region GUI installer page (a full-width row
## separated by whitespace, e.g. the "Encrypt system" checkbox) AND a simple centered menu (the
## GRUB "Choose boot mode" screen). NO single page-segmentation mode reads both -- psm 6 (uniform
## block) drops the separated GUI row, while psm 3 (auto layout) mis-segments the centered menu and
## drops its text. The UNION of the two reads every token either reads, with no per-frame tuning.
ROBUST_PSMS = (3, 6)


def ocr_text_union(path, psms=ROBUST_PSMS):
    """OCR text concatenated across several page-segmentation modes, so a token read under ANY
    mode is present for matching. Deterministic (fixed psms, fixed order). Raises on a tesseract/OS
    failure like ocr_text. See ROBUST_PSMS for why the union is needed."""
    return "\n".join(ocr_text(path, psm=p) for p in psms)


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
