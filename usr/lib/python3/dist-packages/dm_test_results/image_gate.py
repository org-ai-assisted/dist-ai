## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Shared primitives for the screenshot gates (image-blank-check, image-dup-check):
image iteration, the fail-closed --allow name matcher, and a deterministic content
hash. One authoritative copy of the allow-matching semantics -- a bare '' / '.' / '-'
must exempt NOTHING (fail-closed), a property worth keeping in a single place.

PIL only, no numpy (same leaf-module contract as imaging.py)."""

import hashlib
import os

from PIL import Image

IMAGE_EXTS = (".png", ".webp")


def iter_images(paths):
    """Yield each image path to check. A directory expands to its *.png/*.webp entries
    (non-recursive, sorted); an explicitly named file is yielded as-is whatever its
    extension (so a caller can check one arbitrary file)."""
    for path in paths:
        if os.path.isdir(path):
            for name in sorted(os.listdir(path)):
                if name.lower().endswith(IMAGE_EXTS):
                    yield os.path.join(path, name)
        else:
            yield path


def is_allowed(base, allow):
    """Whether basename BASE is exempted by an --allow value.

    Match the frame NAME as a whole or a dash-delimited suffix token of the stem
    (e.g. 'firmware-logo' matches '43-installed-firmware-logo.png'), never a raw
    substring: a bare substring is fail-OPEN -- '' or '.' is a substring of every
    basename, so it would silently exempt EVERY frame and pass a check that checked
    nothing. A token with no alphanumeric character (so '', '.', '-') is not a real
    frame name and matches NOTHING -- otherwise '.' would still match a stem ending
    in '-.' (e.g. 'shot-..png'). Fail-closed."""
    stem = os.path.splitext(base)[0]
    for name in allow:
        if not any(c.isalnum() for c in name):
            continue
        if stem == name or stem.endswith("-" + name):
            return True
    return False


def content_hash(path):
    """Deterministic sha256 of the decoded RGB pixels: identical iff two frames are
    pixel-for-pixel equal, robust to container/metadata differences (a PNG and a
    lossless WEBP of the same frame hash equal). The size is bound into the digest,
    so two differently-sized frames can never collide even if one pixel stream is a
    shifted view of the other."""
    with Image.open(path) as image:
        rgb = image.convert("RGB")
        digest = hashlib.sha256()
        digest.update(("%dx%d\n" % rgb.size).encode())
        digest.update(rgb.tobytes())
    return digest.hexdigest()
