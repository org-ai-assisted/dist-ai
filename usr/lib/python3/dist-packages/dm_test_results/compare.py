## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Golden visual-regression: normalize a screenshot, compare it to an approved
golden, and classify the result into a fail-closed bucket.

The normalized (masked) image is what is BOTH compared AND shown on the site, so
the human sees exactly what was compared. Normalization blanks legitimately
non-deterministic regions (the taskbar clock, and any configured UUID/MAC/host
rects) to a constant, so only a MEANINGFUL pixel change registers.

Buckets (only MATCH is green; the AND of every precondition):
  MATCH   golden exists AND its bytes match the approved sha256 AND the record is
          status=approved AND the normalized current is within tolerance.
  CHANGED an approved golden exists but the current differs (or the golden file no
          longer matches the approved hash) -> needs a human to re-approve.
  NEW     no golden, or no approval record, or the record is not yet approved
          -> needs a first human approval.
  UNKNOWN the current image could not be read/normalized, or any error -> never a
          pass (fail closed).

Visual-regression applies ONLY to screenshot attachments. A text-only step has no
golden and is judged on its functional status alone (model.py).
"""

import hashlib
import json

import numpy
from PIL import Image

APPROVALS_SCHEMA = "golden-approvals/v1"
APPROVAL_STATUS_APPROVED = "approved"

BUCKET_MATCH = "MATCH"
BUCKET_CHANGED = "CHANGED"
BUCKET_NEW = "NEW"
BUCKET_UNKNOWN = "UNKNOWN"
## The one green bucket. NEW/CHANGED/UNKNOWN are never green.
BUCKET_GREEN = BUCKET_MATCH

## A current vs golden is a MATCH only when at most this fraction of pixels differ
## by more than CHANNEL_THRESHOLD on any channel. Deliberately tight: a masked VM
## screenshot is near-deterministic, so only a real UI change should move them.
## At 0.0002 a ~20x20-pixel block on a 1080p shot already trips CHANGED, so a small
## status-icon / word change is not approved as green by a loose fraction. Both are
## overridable (--tolerance / --channel-threshold) for a noisier lane.
DEFAULT_TOLERANCE = 0.0002
DEFAULT_CHANNEL_THRESHOLD = 16


class CompareError(Exception):
    """A malformed approvals record or an unreadable golden."""


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def top_right_rect(size, frac_w=0.16, frac_h=0.06):
    """A mask rect over the top-right corner (the usual taskbar-clock location),
    as a fraction of the image. Convenience for a caller that has no measured
    coordinates; a caller with exact coordinates passes its own rect instead."""
    width, height = size
    rect_w = max(1, int(round(width * frac_w)))
    rect_h = max(1, int(round(height * frac_h)))
    return (width - rect_w, 0, rect_w, rect_h)


def normalize_image(path, rects=None):
    """Load an image as RGB and blank each (x, y, w, h) rect to solid black. Rects
    are clamped to the image, so an oversized or off-image rect cannot raise. The
    result is deterministic for a given input + rects."""
    image = Image.open(path)
    image = image.convert("RGB")
    if rects:
        width, height = image.size
        black = Image.new("RGB", (1, 1), (0, 0, 0))
        for rect in rects:
            x, y, rect_w, rect_h = rect
            x0 = max(0, min(int(x), width))
            y0 = max(0, min(int(y), height))
            x1 = max(0, min(int(x) + int(rect_w), width))
            y1 = max(0, min(int(y) + int(rect_h), height))
            if x1 > x0 and y1 > y0:
                image.paste(black.resize((x1 - x0, y1 - y0)), (x0, y0))
    return image


def image_diff_ratio(image_a, image_b, channel_threshold=DEFAULT_CHANNEL_THRESHOLD):
    """Fraction of pixels differing by more than channel_threshold on any channel.
    Different dimensions -> 1.0 (wholly different); a resolution change is a real
    change, never silently tolerated."""
    if image_a.size != image_b.size:
        return 1.0
    arr_a = numpy.asarray(image_a, dtype=numpy.int16)
    arr_b = numpy.asarray(image_b, dtype=numpy.int16)
    per_pixel_max = numpy.abs(arr_a - arr_b).max(axis=2)
    differing = int((per_pixel_max > channel_threshold).sum())
    total = int(per_pixel_max.size)
    if total == 0:
        return 1.0
    return differing / total


def load_approvals(path):
    """Parse a golden-approvals/v1 file into {screenshot_id: record}. A MISSING
    file is the legitimate initial state -> {} (every shot then reads NEW). A
    present-but-malformed file fails closed (raises), never silently empty."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except FileNotFoundError:
        return {}
    if not isinstance(payload, dict) or payload.get("schema") != APPROVALS_SCHEMA:
        raise CompareError("approvals file is not %s: %s" % (APPROVALS_SCHEMA, path))
    records = payload.get("approvals")
    if not isinstance(records, dict):
        raise CompareError("approvals.approvals must be an object: %s" % path)
    return records


def classify(
    screenshot_id,
    current_path,
    golden_path,
    approvals,
    rects=None,
    tolerance=DEFAULT_TOLERANCE,
    channel_threshold=DEFAULT_CHANNEL_THRESHOLD,
):
    """Classify one screenshot into a bucket. Returns (bucket, detail) where detail
    carries the diff ratio / reason for the page. Fail-closed: any unexpected error
    yields UNKNOWN, never a pass."""
    detail = {"id": screenshot_id, "ratio": None, "reason": ""}
    try:
        try:
            current = normalize_image(current_path, rects)
        except (FileNotFoundError, OSError) as exc:
            detail["reason"] = "current unreadable: %s" % exc
            return BUCKET_UNKNOWN, detail

        record = approvals.get(screenshot_id)
        golden_exists = golden_path is not None and _is_file(golden_path)
        if record is None or not golden_exists:
            detail["reason"] = "no approved golden yet"
            return BUCKET_NEW, detail

        if record.get("status") != APPROVAL_STATUS_APPROVED:
            detail["reason"] = "golden recorded but not approved"
            return BUCKET_NEW, detail

        expected_sha = record.get("golden_sha256")
        actual_sha = sha256_file(golden_path)
        if not expected_sha or actual_sha != expected_sha:
            detail["reason"] = "golden file differs from the approved sha256"
            return BUCKET_CHANGED, detail

        golden = normalize_image(golden_path, rects)
        ratio = image_diff_ratio(current, golden, channel_threshold)
        detail["ratio"] = ratio
        if ratio <= tolerance:
            detail["reason"] = "within tolerance"
            return BUCKET_MATCH, detail
        detail["reason"] = "differs beyond tolerance"
        return BUCKET_CHANGED, detail
    except Exception as exc:  # noqa: BLE001 -- fail closed: any error is non-green
        detail["reason"] = "classification error: %s" % exc
        return BUCKET_UNKNOWN, detail


def _is_file(path):
    import os

    return os.path.isfile(path)
