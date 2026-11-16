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


def name_matches(base, name):
    """Whether basename BASE is named NAME, matched as the whole stem or a dash-delimited
    suffix token of it (e.g. 'firmware-logo' matches '43-installed-firmware-logo.png'),
    never a raw substring: a bare substring is fail-OPEN -- '' or '.' is a substring of
    every basename, so it would silently match EVERY frame. A token with no alphanumeric
    character (so '', '.', '-') is not a real frame name and matches NOTHING -- otherwise
    '.' would still match a stem ending in '-.' (e.g. 'shot-..png'). Fail-closed."""
    if not any(c.isalnum() for c in name):
        return False
    stem = os.path.splitext(base)[0]
    return stem == name or stem.endswith("-" + name)


def is_allowed(base, allow):
    """Whether basename BASE is exempted by any of the --allow values (see name_matches)."""
    return any(name_matches(base, name) for name in allow)


def content_hash(path):
    """Deterministic sha256 of the decoded RGBA pixels: identical iff two frames are
    pixel-for-pixel equal INCLUDING alpha, so two frames differing only in transparency are
    NOT collapsed (an RGB-only hash would, and the dup gate could then fail a good run on
    distinct frames). Robust to container/metadata differences (a PNG and a lossless WEBP of
    the same frame hash equal). The size is bound into the digest, so two differently-sized
    frames can never collide even if one pixel stream is a shifted view of the other."""
    with Image.open(path) as image:
        rgba = image.convert("RGBA")
        digest = hashlib.sha256()
        digest.update(("%dx%d\n" % rgba.size).encode())
        digest.update(rgba.tobytes())
    return digest.hexdigest()
