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
  publish --out DIR
        Emit the curated human-verification subset as window PNGs + a manifest.tsv.
        The page-build step converts these to webp; this command stays PNG-only.

Exit non-zero if ANY cell reports an artifact (so `full` doubles as a gate).
"""

import argparse
import faulthandler
import os
import signal
import sys

_FAULT_LOG = None
if os.environ.get('ZOOM_FAULT_LOG'):
    # Held open for the whole process: faulthandler writes the crash traceback to it, so
    # it must stay open until the process ends (the OS closes it at os._exit). Kept in a
    # module global so it is not garbage-collected in the meantime.
    _FAULT_LOG = open(os.environ['ZOOM_FAULT_LOG'], 'w', encoding='ascii')
    faulthandler.enable(file=_FAULT_LOG, all_threads=True)
else:
    faulthandler.enable()

try:
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)   # auto-reap the boards' /bin/cat children
except (OSError, ValueError, AttributeError):
    pass                                # not the main thread / unsupported: reaping is optional

from st_qt_platform import require_wayland
require_wayland('zoom-sweep')

import zoom_regression_lib as Z


def _parse_res(s):
    try:
        w, h = s.lower().split('x')
        return (int(w), int(h))
    except (ValueError, AttributeError):
        raise SystemExit('zoom-sweep: bad resolution %r (want WIDTHxHEIGHT, e.g. 1280x800)' % (s,))


def _check_boards(names):
    unknown = [n for n in names if n not in Z.BOARDS]
    if unknown:
        raise SystemExit('zoom-sweep: unknown board(s) %s; known: %s'
                         % (', '.join(unknown), ', '.join(sorted(Z.BOARDS))))
    return names


def _parse_zoom(s):
    try:
        v = int(s)
    except (ValueError, TypeError):
        raise SystemExit('zoom-sweep: bad zoom %r (want an integer percent, e.g. 150)' % (s,))
    # Reject out-of-range up front: the app clamps a zoom to ZOOM_MIN..ZOOM_MAX, so
    # accepting e.g. 999999 would render at ZOOM_MAX while the cell label / dump filename
    # (_tag) still said 999999 -- a shot whose own name lies about its zoom.
    if not (Z.ZOOM_MIN <= v <= Z.ZOOM_MAX):
        raise SystemExit('zoom-sweep: zoom %d out of range %d..%d'
                         % (v, Z.ZOOM_MIN, Z.ZOOM_MAX))
    return v


def _parse_zooms(s):
    return [_parse_zoom(z) for z in s.split(',')]


def _check_displays(names):
    unknown = [n for n in names if n not in Z.DISPLAY_MODES_TESTED]
    if unknown:
        raise SystemExit('zoom-sweep: unknown display mode(s) %s; known: %s'
                         % (', '.join(unknown), ', '.join(Z.DISPLAY_MODES_TESTED)))
    return names


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
    # Parse/validate args (clean SystemExit) BEFORE building the harness, so a bad value
    # never reaches the Qt objects (a raw exception after that hits the static-teardown
    # SIGSEGV path). res/zoom raise SystemExit -> routed through os._exit in __main__.
    res = _parse_res(args.res)
    zoom = _parse_zoom(args.zoom)
    h = Z.ZoomHarness()
    try:
        result = h.capture(Z.BOARDS[args.board][0], args.mode, res, zoom,
                           display_mode=args.display)
        spec = Z.board_spec(args.board)
        issues = Z.analyze(result, spec, _display_mode(result['term']))
        tag = _tag(args.board, args.mode, args.display, res, zoom)
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
    # All arg validation (clean SystemExit) BEFORE the harness -- see cmd_one.
    boards = _check_boards(args.boards.split(',')) if args.boards else list(Z.BOARDS)
    resolutions = [_parse_res(s) for s in args.res.split(',')] if args.res else list(Z.RESOLUTIONS)
    zooms = _parse_zooms(args.zooms) if args.zooms else list(Z.CANONICAL_ZOOMS)
    displays = _check_displays(args.display.split(',')) if args.display else [Z.PRIMARY_DISPLAY]
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
    po.add_argument('board', choices=sorted(Z.BOARDS))
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
    pp.set_defaults(fn=cmd_publish)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == '__main__':
    # os._exit, never sys.exit: a normal interpreter shutdown runs Qt's static
    # destructors and SIGSEGVs (the same reason the widget suites os._exit in finish()).
    # A SystemExit raised AFTER the harness (QApplication) exists -- e.g. a validation
    # error in cmd_one/cmd_full -- would otherwise unwind normally and hit that teardown
    # crash, masking the clean exit code; catch it and route it through os._exit too.
    try:
        _rc = main()
    except SystemExit as _exc:
        _rc = _exc.code if isinstance(_exc.code, int) else (0 if _exc.code is None else 1)
        if isinstance(_exc.code, str):
            sys.stderr.write(_exc.code + '\n')
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(_rc)
