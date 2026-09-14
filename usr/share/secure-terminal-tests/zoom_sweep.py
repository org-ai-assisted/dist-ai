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

Exit non-zero if ANY cell reports an artifact (so `full` doubles as a gate).

The published human-verification zoom shots on secure-terminal.github.io are NOT emitted
here: they are captured against the REAL decorated app (window title bar + shell prompt) by
the dist-ai shot harness -- `secure-terminal-shots zoom-verify` (comparison-capture.sh
--zoom-verify). This in-process harness is the automated artifact GATE only.
"""

import argparse
import faulthandler
import os
import signal
import sys
import traceback

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
        w, h = int(w), int(h)
    except (ValueError, AttributeError):
        raise SystemExit('zoom-sweep: bad resolution %r (want WIDTHxHEIGHT, e.g. 1280x800)' % (s,))
    # Reject non-positive dims up front, mirroring _parse_zoom's range check: 0x0 (or a
    # negative via `-- -5x800`) would resize the window to a degenerate size Qt cannot
    # render while the cell label / dump filename (_tag) still claimed those dims -- a shot
    # whose own name lies about its resolution.
    if w < 1 or h < 1:
        raise SystemExit('zoom-sweep: resolution %r must be positive (got %dx%d)' % (s, w, h))
    return (w, h)


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


def _checked_save(image, path):
    # QImage.save() returns False on write failure (unwritable path, path is a dir, disk
    # full) WITHOUT raising -- an ignored return turns a MISSING shot into a fabricated
    # success. A shot tool that cannot write its shot must fail loud, never report a path
    # it did not create.
    if not image.save(path):
        raise RuntimeError('zoom-sweep: failed to write image %r' % (path,))
    return path


def _save(result, dump_dir, tag):
    os.makedirs(dump_dir, exist_ok=True)
    wp = os.path.join(dump_dir, 'zoom-%s-win.png' % tag)
    vp = os.path.join(dump_dir, 'zoom-%s-view.png' % tag)
    _checked_save(result['win_image'], wp)
    _checked_save(result['viewport_image'], vp)
    return wp


def _tag(board, mode, display, res, zoom):
    return '%s-%s-%s-%dx%d-z%d' % (board, mode, display, res[0], res[1], zoom)


def cmd_one(args):
    # Parse/validate args (clean SystemExit) BEFORE building the harness, so a bad value
    # never reaches the Qt objects (a raw exception after that hits the static-teardown
    # SIGSEGV path). res/zoom raise SystemExit -> routed through os._exit in __main__.
    res = _parse_res(args.res)
    zoom = _parse_zoom(args.zoom)
    # Reject an invalid mode/display combo like cmd_full skips it: set_mode refuses
    # reveal/detail in TUI, so the window would stay in a fallback mode while _tag still
    # named the requested one -- a shot whose filename lies about what it rendered.
    if not Z.valid_display_for(args.mode, args.display):
        raise SystemExit('zoom-sweep: display %r is not valid in %s mode (reveal/detail are CLI-only)'
                         % (args.display, args.mode))
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

    args = p.parse_args(argv)
    return args.fn(args)


def _main_exit_code(argv=None):
    # Compute the process exit code, NEVER letting an exception unwind past here: any
    # exception raised AFTER the harness (QApplication) exists -- a SystemExit validation
    # error, a RuntimeError from _checked_save, an OSError from os.makedirs -- would else
    # unwind normally and run Qt's static destructors, which SIGSEGV during teardown (the
    # same reason the widget suites os._exit in finish()), masking the real failure with a
    # crash. Route every ordinary error AND a mid-run Ctrl-C through os._exit; a genuine
    # failure still fails loud (traceback + non-zero rc), just via a clean hard-exit.
    try:
        return main(argv)
    except SystemExit as exc:
        if isinstance(exc.code, str):
            sys.stderr.write(exc.code + '\n')
            return 1
        return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
    except (Exception, KeyboardInterrupt):  # pylint: disable=broad-except
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    _rc = _main_exit_code()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(_rc)
