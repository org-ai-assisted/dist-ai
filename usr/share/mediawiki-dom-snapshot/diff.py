#!/usr/bin/env python3
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.
##
## AI-Assisted

"""Three-axis regression diff between two snapshot fixture sets.

For every page that exists in both fixture sets, compare:

  1. DOM HTML       text diff of dom.html
  2. asset bodies   manifest.json: which URLs changed sha256; for text
                    bodies (CSS/JS/JSON) also print a unified diff of
                    the asset content; for binary bodies print before/
                    after sizes.
  3. screenshot     pixel diff of screenshot.png. Reports the count of
                    differing pixels and the perceptual hash distance
                    (pHash from imagehash). A small pHash distance with
                    a large pixel-diff count usually means font /
                    anti-aliasing jitter, not a real change; a large
                    pHash distance means the layout shifted.

Exit code: 0 if the only deltas are in URL parameters that the normaliser
explicitly scrubs (i.e. nothing observably changed); 1 otherwise.

Usage:
    diff.py <baseline-dir> <candidate-dir> [--brief]

    --brief   skip per-asset body diff text; show only the summary
              table. Useful for the first pass.
"""
import argparse
import difflib
import json
import sys
from pathlib import Path

from PIL import Image, ImageChops
import imagehash

## Asset content types that are useful to print as text diffs.
TEXT_CONTENT_TYPES = (
    "text/",
    "application/javascript",
    "application/json",
    "application/xml",
    "image/svg+xml",
)


def is_textual(content_type: str) -> bool:
    ct = (content_type or "").lower()
    return any(ct.startswith(p) for p in TEXT_CONTENT_TYPES)


def text_diff(a: str, b: str, a_label: str, b_label: str, max_lines: int = 40) -> str:
    lines = list(
        difflib.unified_diff(
            a.splitlines(keepends=False),
            b.splitlines(keepends=False),
            fromfile=a_label,
            tofile=b_label,
            lineterm="",
            n=2,
        )
    )
    if len(lines) > max_lines:
        kept = lines[:max_lines]
        kept.append(f"... ({len(lines) - max_lines} more diff lines truncated)")
        lines = kept
    return "\n".join(lines)


def diff_page_html(base: Path, cand: Path) -> tuple[int, str]:
    a = (base / "dom.html").read_text(encoding="utf-8")
    b = (cand / "dom.html").read_text(encoding="utf-8")
    if a == b:
        return 0, ""
    out = text_diff(a, b, str(base / "dom.html"), str(cand / "dom.html"), max_lines=60)
    return abs(a.count("\n") - b.count("\n")) + 1, out


def diff_assets(base: Path, cand: Path, brief: bool) -> tuple[list[tuple], list[str]]:
    """Returns (rows, body_diffs).  rows: [(url, status, base_size, cand_size, base_hash[:12], cand_hash[:12])]."""
    bm = json.loads((base / "manifest.json").read_text(encoding="utf-8"))
    cm = json.loads((cand / "manifest.json").read_text(encoding="utf-8"))
    all_urls = sorted(set(bm) | set(cm))
    rows: list[tuple] = []
    body_diffs: list[str] = []
    base_assets = base / "assets"
    cand_assets = cand / "assets"
    for url in all_urls:
        be = bm.get(url)
        ce = cm.get(url)
        if be is None:
            rows.append((url, "NEW", "-", str(ce.get("size", "?")), "-", (ce.get("sha256") or "")[:12]))
            continue
        if ce is None:
            rows.append((url, "GONE", str(be.get("size", "?")), "-", (be.get("sha256") or "")[:12], "-"))
            continue
        bh = be.get("sha256") or ""
        ch = ce.get("sha256") or ""
        if bh == ch:
            continue  ## same content, no row
        rows.append((url, "CHANGED", str(be.get("size", "?")), str(ce.get("size", "?")), bh[:12], ch[:12]))
        if brief:
            continue
        ## Show text diff for textual assets.
        if is_textual(be.get("content_type", "")) and is_textual(ce.get("content_type", "")):
            bpath = base_assets / be.get("asset", "")
            cpath = cand_assets / ce.get("asset", "")
            if bpath.exists() and cpath.exists():
                try:
                    btxt = bpath.read_text(encoding="utf-8")
                    ctxt = cpath.read_text(encoding="utf-8")
                    body_diffs.append(f"\n=== asset diff: {url} ===\n" + text_diff(
                        btxt, ctxt, str(bpath), str(cpath), max_lines=120,
                    ))
                except UnicodeDecodeError:
                    pass
    return rows, body_diffs


def diff_screenshot(base: Path, cand: Path) -> tuple[int, int, str]:
    """Returns (pixel_diff_count, phash_distance, summary).
    pixel_diff_count is the number of bytes that differ across the two
    images (channels included), so the upper bound for a 1280x800 RGB
    image is 1280*800*3 = ~3 million.
    """
    b_path = base / "screenshot.png"
    c_path = cand / "screenshot.png"
    if not (b_path.exists() and c_path.exists()):
        return 0, 0, "(one screenshot missing; skipped)"
    a = Image.open(b_path).convert("RGB")
    b = Image.open(c_path).convert("RGB")
    if a.size != b.size:
        return -1, -1, f"size differs: {a.size} vs {b.size}"
    diff = ImageChops.difference(a, b)
    pixels_diff = sum(1 for v in diff.getdata() if v != (0, 0, 0))
    pa = imagehash.phash(a)
    pb = imagehash.phash(b)
    phash_dist = pa - pb
    return pixels_diff, phash_dist, f"pixels_diff={pixels_diff} phash_dist={phash_dist}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("baseline")
    ap.add_argument("candidate")
    ap.add_argument("--brief", action="store_true",
                    help="suppress per-asset body diff text")
    args = ap.parse_args()

    base_root = Path(args.baseline)
    cand_root = Path(args.candidate)
    for p in (base_root, cand_root):
        if not p.is_dir():
            print(f"{p}: not a directory", file=sys.stderr)
            return 2

    base_pages = {p.name for p in base_root.iterdir() if p.is_dir()}
    cand_pages = {p.name for p in cand_root.iterdir() if p.is_dir()}
    only_b = sorted(base_pages - cand_pages)
    only_c = sorted(cand_pages - base_pages)
    common = sorted(base_pages & cand_pages)

    any_diff = False
    summary: list[str] = []

    for name in only_b:
        any_diff = True
        summary.append(f"  {name:<40} REMOVED")
    for name in only_c:
        any_diff = True
        summary.append(f"  {name:<40} NEW")

    body_diffs_all: list[str] = []
    for name in common:
        b = base_root / name
        c = cand_root / name
        html_lines_diff, html_diff_text = diff_page_html(b, c)
        asset_rows, asset_body_diffs = diff_assets(b, c, brief=args.brief)
        pixels_diff, phash_dist, ss_summary = diff_screenshot(b, c)
        any = html_lines_diff > 0 or asset_rows or (pixels_diff > 0)
        if not any:
            summary.append(f"  {name:<40} identical")
            continue
        any_diff = True
        bits = []
        if html_lines_diff > 0:
            bits.append(f"html+{html_lines_diff}")
        if asset_rows:
            bits.append(f"assets={len(asset_rows)}")
        if pixels_diff > 0:
            bits.append(ss_summary)
        summary.append(f"  {name:<40} {' '.join(bits)}")
        ## Detail section per page.
        body_diffs_all.append(f"\n========== {name} ==========")
        if html_diff_text:
            body_diffs_all.append("\n--- DOM HTML diff ---")
            body_diffs_all.append(html_diff_text)
        if asset_rows:
            body_diffs_all.append("\n--- asset manifest deltas ---")
            body_diffs_all.append(f"{'url':<80} {'status':<8} {'base_sz':>9} {'cand_sz':>9} {'base_sha':<13} {'cand_sha':<13}")
            for r in asset_rows:
                body_diffs_all.append(
                    f"{(r[0] if len(r[0]) < 80 else r[0][:77] + '...'):<80} "
                    f"{r[1]:<8} {r[2]:>9} {r[3]:>9} {r[4]:<13} {r[5]:<13}"
                )
        if not args.brief:
            body_diffs_all.extend(asset_body_diffs)
        if pixels_diff > 0:
            body_diffs_all.append(f"\n--- screenshot: {ss_summary} ---")

    print("=== summary ===")
    for line in summary:
        print(line)
    if body_diffs_all:
        print("")
        print("=== details ===")
        for line in body_diffs_all:
            print(line)

    return 1 if any_diff else 0


if __name__ == "__main__":
    sys.exit(main())
