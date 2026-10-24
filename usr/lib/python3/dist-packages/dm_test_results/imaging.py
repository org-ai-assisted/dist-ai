## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Screenshot normalization for the verification site: load a shot as RGB and blank
the non-deterministic regions (the taskbar clock, any configured UUID/MAC/host rects)
to a constant, so a published shot is stable and privacy-clean.

PIL only, no numpy: the generator is the sole consumer, and keeping this leaf numpy-free
lets site_classes stay importable by the numpy-free website-tests/deploy contract checks.
"""

from PIL import Image


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
