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


def diff_assets(base: Path, cand: Path, brief: bool) -> tuple[list[tuple], list[str], int]:
    """Compare every per-URL entry: body sha256 and header set.
    Returns (rows, body_diffs, header_delta_count) where each row is
    (url, status, base_size, cand_size, base_hash[:12], cand_hash[:12]).
    Header deltas are reported as separate lines in body_diffs.
    """
    bm = json.loads((base / "manifest.json").read_text(encoding="utf-8"))
    cm = json.loads((cand / "manifest.json").read_text(encoding="utf-8"))
    all_urls = sorted(set(bm) | set(cm))
    rows: list[tuple] = []
    body_diffs: list[str] = []
    header_delta_urls: list[str] = []
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
        bh_eq = bh == ch
        bheaders = be.get("headers") or {}
        cheaders = ce.get("headers") or {}
        h_eq = bheaders == cheaders
        if bh_eq and h_eq:
            continue
        if not bh_eq:
            rows.append((url, "CHANGED", str(be.get("size", "?")),
                         str(ce.get("size", "?")), bh[:12], ch[:12]))
        if not h_eq:
            header_delta_urls.append(url)
        if brief:
            continue
        if not bh_eq and is_textual(be.get("content_type", "")) and is_textual(ce.get("content_type", "")):
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
        if not h_eq:
            keys = sorted(set(bheaders) | set(cheaders))
            lines = [f"\n=== header diff: {url} ==="]
            for k in keys:
                bv = bheaders.get(k, "<absent>")
                cv = cheaders.get(k, "<absent>")
                if bv != cv:
                    lines.append(f"  {k}:")
                    lines.append(f"    - {bv}")
                    lines.append(f"    + {cv}")
            body_diffs.append("\n".join(lines))
    return rows, body_diffs, len(header_delta_urls)


## Threshold above which a per-pixel max-channel delta counts as a
## "real" pixel change rather than antialiasing jitter. Empirically,
## sub-pixel font / border rendering produces deltas of 1-2 out of 255
## even when the pages render visually identically; a delta of 4+ on a
## single channel is consistent with a colour or geometry change.
PIXEL_JITTER_THRESHOLD = 3


def diff_screenshot(base: Path, cand: Path) -> tuple[bool, int, int, int, str]:
    """Returns (is_visual_regression, pixels_diff, max_channel_delta,
    phash_distance, summary).

    is_visual_regression captures the SIGNAL: it's True when any of
      - phash distance > 0   (the perceptual hash sees a real change)
      - any single channel-delta > PIXEL_JITTER_THRESHOLD
        (a pixel changed more than antialiasing would explain)
      - image sizes don't match (impossible at the same viewport)
    Sub-threshold pixel deltas with phash=0 are returned as raw
    numbers for forensic inspection but do NOT flip the signal.
    """
    b_path = base / "screenshot.png"
    c_path = cand / "screenshot.png"
    if not (b_path.exists() and c_path.exists()):
        return False, 0, 0, 0, "(one screenshot missing; skipped)"
    a = Image.open(b_path).convert("RGB")
    b = Image.open(c_path).convert("RGB")
    if a.size != b.size:
        return True, -1, -1, -1, f"size differs: {a.size} vs {b.size}"
    diff = ImageChops.difference(a, b)

    ## numpy for fast aggregates; falls back to PIL if numpy missing.
    try:
        import numpy as np
        arr = np.asarray(diff)
        pixels_diff = int((arr > 0).any(axis=2).sum())
        max_delta = int(arr.max())
    except ImportError:
        pixels_diff = sum(1 for v in diff.getdata() if v != (0, 0, 0))
        ## Slow path: scan for max channel delta.
        max_delta = 0
        for v in diff.getdata():
            m = max(v)
            if m > max_delta:
                max_delta = m

    phash_dist = imagehash.phash(a) - imagehash.phash(b)
    is_real = phash_dist > 0 or max_delta > PIXEL_JITTER_THRESHOLD
    summary = (
        f"pixels_diff={pixels_diff} max_channel_delta={max_delta} "
        f"phash_dist={phash_dist}"
    )
    if not is_real and pixels_diff > 0:
        summary += " (subpixel-jitter; phash sees no change)"
    return is_real, pixels_diff, max_delta, phash_dist, summary


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
    def _diff_json_file(b: Path, c: Path, name: str) -> tuple[int, str]:
        bp = b / name
        cp = c / name
        if not (bp.exists() and cp.exists()):
            return 0, ""
        bj = json.loads(bp.read_text(encoding="utf-8"))
        cj = json.loads(cp.read_text(encoding="utf-8"))
        if bj == cj:
            return 0, ""
        a_text = json.dumps(bj, indent=2, sort_keys=True)
        b_text = json.dumps(cj, indent=2, sort_keys=True)
        diff = text_diff(a_text, b_text, str(bp), str(cp), max_lines=60)
        n = abs(a_text.count("\n") - b_text.count("\n")) + 1
        return n, diff

    def diff_one(label: str, b: Path, c: Path):
        if not ((b / "dom.html").exists() and (c / "dom.html").exists()):
            return
        html_lines_diff, html_diff_text = diff_page_html(b, c)
        asset_rows, asset_body_diffs, header_deltas = diff_assets(b, c, brief=args.brief)
        ss_real, pixels_diff, max_delta, phash_dist, ss_summary = diff_screenshot(b, c)
        styles_lines, styles_diff = _diff_json_file(b, c, "computed_styles.json")
        console_lines, console_diff = _diff_json_file(b, c, "console.json")
        any_real = (
            html_lines_diff > 0
            or asset_rows
            or header_deltas
            or ss_real
            or styles_lines > 0
            or console_lines > 0
        )
        if not any_real and pixels_diff == 0:
            summary.append(f"  {label:<48} identical")
            return
        if not any_real:
            summary.append(f"  {label:<48} subpixel-only ({ss_summary})")
            return
        nonlocal any_diff
        any_diff = True
        bits = []
        if html_lines_diff > 0:
            bits.append(f"html+{html_lines_diff}")
        if asset_rows:
            bits.append(f"assets={len(asset_rows)}")
        if header_deltas:
            bits.append(f"headers={header_deltas}")
        if styles_lines > 0:
            bits.append(f"styles+{styles_lines}")
        if console_lines > 0:
            bits.append(f"console+{console_lines}")
        if ss_real:
            bits.append(ss_summary)
        summary.append(f"  {label:<48} {' '.join(bits)}")
        body_diffs_all.append(f"\n========== {label} ==========")
        if html_diff_text:
            body_diffs_all.append("\n--- DOM HTML diff ---")
            body_diffs_all.append(html_diff_text)
        if asset_rows:
            body_diffs_all.append("\n--- asset manifest deltas ---")
            body_diffs_all.append(
                f"{'url':<80} {'status':<8} {'base_sz':>9} {'cand_sz':>9} {'base_sha':<13} {'cand_sha':<13}"
            )
            for r in asset_rows:
                body_diffs_all.append(
                    f"{(r[0] if len(r[0]) < 80 else r[0][:77] + '...'):<80} "
                    f"{r[1]:<8} {r[2]:>9} {r[3]:>9} {r[4]:<13} {r[5]:<13}"
                )
        if not args.brief:
            body_diffs_all.extend(asset_body_diffs)
            if styles_diff:
                body_diffs_all.append("\n--- computed styles diff ---")
                body_diffs_all.append(styles_diff)
            if console_diff:
                body_diffs_all.append("\n--- console messages diff ---")
                body_diffs_all.append(console_diff)
        if ss_real:
            body_diffs_all.append(f"\n--- screenshot: {ss_summary} ---")

    for name in common:
        b = base_root / name
        c = cand_root / name
        ## v0.3 captures into per-mode subdirs (anon-first, anon-repeat,
        ## user-first, user-repeat); v0.2 captured directly. Detect.
        modes_b = sorted(p.name for p in b.iterdir() if p.is_dir() and (p / "dom.html").exists())
        modes_c = sorted(p.name for p in c.iterdir() if p.is_dir() and (p / "dom.html").exists())
        if modes_b or modes_c:
            for mode in sorted(set(modes_b) | set(modes_c)):
                if mode not in modes_b:
                    summary.append(f"  {name}/{mode:<40} MISSING in base"); any_diff = True; continue
                if mode not in modes_c:
                    summary.append(f"  {name}/{mode:<40} MISSING in cand"); any_diff = True; continue
                diff_one(f"{name}/{mode}", b / mode, c / mode)
        else:
            diff_one(name, b, c)

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
