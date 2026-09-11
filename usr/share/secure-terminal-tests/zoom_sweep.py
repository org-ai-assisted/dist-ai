#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Diagnostic + shot driver for the zoom-artifact sweep. Runs UNDER a real headless
Wayland compositor (wl-headless-run), like every Qt suite in this tree.

Subcommands:
  one BOARD MODE WxH ZOOM [--dump DIR]
        A single capture cell: build the tab, feed the board, walk+pin the zoom, run
        the detectors, print the verdict. --dump saves the window + viewport PNG. This
        is the FAST feedback path: one cell renders in ~1s, so a change to a board or a
        detector is observable without the full matrix.
  full [--dump DIR] [--boards B,B] [--res WxH,WxH] [--zooms N,N]
        The comprehensive diagnostic sweep across the full matrix; prints every
        artifact found. --dump saves a PNG per cell.
  publish --out DIR [--webp]
        Emit the curated human-verification subset (window PNGs, optional webp).

Exit non-zero if ANY cell reports an artifact (so `full` doubles as a gate).
"""

import argparse
import faulthandler
import os
import signal
import sys

if os.environ.get('ZOOM_FAULT_LOG'):
    faulthandler.enable(file=open(os.environ['ZOOM_FAULT_LOG'], 'w'), all_threads=True)
else:
    faulthandler.enable()

try:
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)   # auto-reap the boards' /bin/cat children
except (OSError, ValueError, AttributeError):
    pass

from st_qt_platform import require_wayland
require_wayland('zoom-sweep')

import zoom_regression_lib as Z


def _parse_res(s):
    w, h = s.lower().split('x')
    return (int(w), int(h))


def _display_mode(term):
    return getattr(term, '_mode', 'detail')


def _save(result, dump_dir, tag):
    os.makedirs(dump_dir, exist_ok=True)
    wp = os.path.join(dump_dir, 'zoom-%s-win.png' % tag)
    vp = os.path.join(dump_dir, 'zoom-%s-view.png' % tag)
    result['win_image'].save(wp)
    result['viewport_image'].save(vp)
    return wp


def _tag(board, mode, display, res, zoom):
    return '%s-%s-%s-%dx%d-z%d' % (board, mode, display, res[0], res[1], zoom)


def cmd_one(args):
    h = Z.ZoomHarness()
    try:
        res = _parse_res(args.res)
        result = h.capture(Z.BOARDS[args.board][0], args.mode, res, int(args.zoom),
                           display_mode=args.display)
        spec = Z.board_spec(args.board)
        issues = Z.analyze(result, spec, _display_mode(result['term']))
        tag = _tag(args.board, args.mode, args.display, res, int(args.zoom))
        saved = _save(result, args.dump, tag) if args.dump else None
        print('cell %s zoom=%d blocks=%d ink=%.3f%s'
              % (tag, result['zoom'], result['term'].document().blockCount(),
                 Z.ink_fraction(result['viewport_image']),
                 (' -> %s' % saved) if saved else ''))
        if issues:
            for i in issues:
                print('  ARTIFACT: ' + i)
            return 1
        print('  clean')
        return 0
    finally:
        h.close()


def cmd_full(args):
    boards = args.boards.split(',') if args.boards else list(Z.BOARDS)
    resolutions = [_parse_res(s) for s in args.res.split(',')] if args.res else list(Z.RESOLUTIONS)
    zooms = [int(z) for z in args.zooms.split(',')] if args.zooms else list(Z.CANONICAL_ZOOMS)
    displays = args.display.split(',') if args.display else [Z.PRIMARY_DISPLAY]
    h = Z.ZoomHarness()
    total = 0
    flagged = 0
    try:
        for board in boards:
            spec = Z.board_spec(board)
            for mode in Z.MODES:
                for display in displays:
                    if not Z.valid_display_for(mode, display):
                        continue          # reveal/detail are CLI-only (set_mode refuses in TUI)
                    for res in resolutions:
                        for zoom in zooms:
                            total += 1
                            result = h.capture(Z.BOARDS[board][0], mode, res, zoom,
                                               display_mode=display)
                            issues = Z.analyze(result, spec, _display_mode(result['term']))
                            tag = _tag(board, mode, display, res, zoom)
                            if args.dump:
                                _save(result, args.dump, tag)
                            if issues:
                                flagged += 1
                                print('ARTIFACT %s:' % tag)
                                for i in issues:
                                    print('  ' + i)
                            h.close_term(result['term'])
    finally:
        h.close()
    print('full sweep: %d cells, %d with artifacts' % (total, flagged))
    return 1 if flagged else 0


# Curated human-verification subset: (board, tab-mode, display-mode, resolution, zoom).
# SHOW display-mode is primary (the mode that needs the most eyeballing); a few detail
# cells are kept for contrast. One board per artifact class, both tab-modes, a spread of
# zoom levels + resolutions -- kept small (~24) and stable.
PUBLISH_SUBSET = [
    ('tui-showcase', 'cli', 'show', (860, 620), z) for z in (50, 100, 200, 400)
] + [
    ('tui-showcase', 'tui', 'show', (1280, 800), z) for z in (75, 125, 250)
] + [
    ('tui-showcase', 'cli', 'detail', (1280, 800), z) for z in (100, 200)
] + [
    ('colorgrad', 'cli', 'show', (1280, 800), z) for z in (50, 100, 200)
] + [
    ('longline-box', 'cli', 'show', (860, 620), z) for z in (75, 110, 300)
] + [
    ('exact-grid', 'cli', 'show', (1366, 768), z) for z in (100, 150)
] + [
    ('altscreen-short', 'tui', 'show', (1280, 800), z) for z in (100, 200)
] + [
    ('wide-cjk', 'cli', 'show', (1280, 800), z) for z in (100, 250)
] + [
    ('art', 'cli', 'show', (860, 620), z) for z in (100, 300)
]


def cmd_publish(args):
    os.makedirs(args.out, exist_ok=True)
    h = Z.ZoomHarness()
    manifest = []
    try:
        for board, mode, display, res, zoom in PUBLISH_SUBSET:
            result = h.capture(Z.BOARDS[board][0], mode, res, zoom, display_mode=display)
            tag = _tag(board, mode, display, res, zoom)
            path = os.path.join(args.out, 'zoom-verify-%s.png' % tag)
            result['win_image'].save(path)
            manifest.append((tag, board, mode, display, res, zoom, os.path.basename(path)))
            print('published %s' % os.path.basename(path))
            h.close_term(result['term'])
    finally:
        h.close()
    # A machine-readable manifest for the page-builder.
    with open(os.path.join(args.out, 'manifest.tsv'), 'w', encoding='utf-8') as fh:
        for tag, board, mode, display, res, zoom, fn in manifest:
            fh.write('%s\t%s\t%s\t%s\t%dx%d\t%d\t%s\n'
                     % (tag, board, mode, display, res[0], res[1], zoom, fn))
    print('published %d shots + manifest.tsv to %s' % (len(manifest), args.out))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog='zoom-sweep')
    sub = p.add_subparsers(dest='cmd', required=True)

    po = sub.add_parser('one')
    po.add_argument('board')
    po.add_argument('mode', choices=Z.MODES)
    po.add_argument('res')
    po.add_argument('zoom')
    po.add_argument('--display', default=Z.PRIMARY_DISPLAY, choices=Z.DISPLAY_MODES_TESTED)
    po.add_argument('--dump', default=None)
    po.set_defaults(fn=cmd_one)

    pf = sub.add_parser('full')
    pf.add_argument('--dump', default=None)
    pf.add_argument('--boards', default=None)
    pf.add_argument('--res', default=None)
    pf.add_argument('--zooms', default=None)
    pf.add_argument('--display', default=Z.PRIMARY_DISPLAY,
                    help='comma list of display modes (default: show)')
    pf.set_defaults(fn=cmd_full)

    pp = sub.add_parser('publish')
    pp.add_argument('--out', required=True)
    pp.add_argument('--webp', action='store_true')
    pp.set_defaults(fn=cmd_publish)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == '__main__':
    # os._exit, never sys.exit: a normal interpreter shutdown runs Qt's static
    # destructors and SIGSEGVs (the same reason the widget suites os._exit in finish()).
    _rc = main()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(_rc)
