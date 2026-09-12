#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Shared library for the zoom-artifact regression: boards, an app-faithful capture
harness, and deterministic artifact detectors.

Purpose: sweep the REAL secure-terminal (a live MainWindow, not a shortcut) across
multiple window resolutions, both CLI and TUI tabs, and a band of font-zoom levels,
and catch zoom/reflow artifacts -- extraneous blank rows, text cut off the right
edge, and blank/empty screens -- with deterministic checks that do not depend on a
pixel-perfect golden.

Faithfulness:
  - Zoom is driven exactly as a user drives it: a randomized (but SEEDED, so
    reproducible) sequence of Ctrl+wheel steps via `term.zoom_step.emit(+-1)`, which
    routes through the window's _on_zoom_step -> set_zoom debounce/coalesce path, then
    the level is pinned to an exact canonical percent via `win.set_zoom(level)` (the
    same absolute-zoom path the toolbar box and `ctl zoom` use, so the chip + reflow
    track it) before the grab. So the walk exercises the real coalescing path while the
    grab lands on a stable, comparable level.
  - Board bytes are fed through the real _on_readable output path (a pipe swapped onto
    the tab's _fd), which sets _raw -- so a later reflow (triggered by zoom or resize)
    replays the real retained output, not an _append shortcut that a reflow would wipe.

Detectors operate on the live QTextDocument + widget geometry (deterministic) with a
secondary pixel ink-fraction for the blank-screen case; each has a canary in the suite
that proves it fires. Golden-image comparison (subset, stable levels) lives in the
suite, built on capture() here.

Needs PyQt6 (headless Wayland) + python3-pyte, declared test deps -- a missing one is a
hard FAILURE upstream (require_wayland / the suite's import guard), never a silent skip.
"""

import os
import random
import zlib

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QEventLoop, QTimer
from PyQt6.QtGui import QImage

from secure_terminal.main import MainWindow, ZOOM_MIN, ZOOM_MAX
from secure_terminal.terminal import SecureTerminal


# The canonical zoom levels the sweep grabs at (percent). Randomized-walk between
# them, grab only here, so shots stay comparable across runs. Clamped to the app's
# real UI range (ZOOM_MIN..ZOOM_MAX) at use so an out-of-range request cannot ask the
# app for a zoom the toolbar itself refuses.
CANONICAL_ZOOMS = (50, 75, 100, 110, 125, 150, 200, 250, 300, 400)

# Realistic desktop window sizes (logical px). The sweep is repeated across all of
# them so a wrap/cutoff artifact that only shows at one grid width is still caught.
RESOLUTIONS = (
    (860, 620),        # the app's own comparison-shot default (labeled toolbar tier)
    (1280, 800),
    (1366, 768),
    (1920, 1080),
)

MODES = ('cli', 'tui')


def valid_display_for(mode, display):
    """TUI's fixed grid cannot expand a codepoint inline, so the window refuses
    reveal/detail there (set_mode). Only show/box are valid display modes in TUI."""
    if mode == 'tui' and display in ('reveal', 'detail'):
        return False
    return True


# The unicode display modes (sanitize.DISPLAY_MODES). SHOW is tested most: it renders
# structural/box-drawing glyphs in the program's own colour and tints confusables, so it
# is the visually richest, most reflow-sensitive path -- the one where a zoom artifact is
# most likely and most visible. detail/box/reveal follow. DETAIL is the shipped default.
PRIMARY_DISPLAY = 'show'
DISPLAY_MODES_TESTED = ('show', 'detail', 'box', 'reveal')


def clamp_zoom(level):
    return max(ZOOM_MIN, min(ZOOM_MAX, int(level)))


# Board byte-generators are single-sourced in a Qt-free module (zoom_boards) so the
# terminal-safe-corpus drift gate can regenerate them without PyQt6. Re-exported here
# (Z.BOARDS / Z.board_spec) for the capture harness, the sweep, and the suite.
from zoom_boards import BOARDS as BOARDS, board_spec as board_spec  # noqa: F401 -- redundant alias marks an intentional re-export (Z.BOARDS / Z.board_spec)


# A board's committed copy in the corpus, RELATIVE to the corpus root (so a published
# shot's banner shows a clean `cat demos/zoom-<name>-safe-to-cat.txt`, the exact reproduce
# path, not an absolute build-tree path).
def corpus_board_relpath(name):
    return os.path.join('demos', 'zoom-%s-safe-to-cat.txt' % name)


def corpus_root():
    """The terminal-safe-corpus checkout root that carries the zoom demos, or None if
    the corpus is not checked out. The board bytes there ARE zoom_boards output (the
    corpus drift-gates them), so a shot that `cat`s the file is single-sourced with the
    harness. Env override TERMINAL_SAFE_CORPUS_REPO; else the sibling-checkout layout."""
    roots = []
    env = os.environ.get('TERMINAL_SAFE_CORPUS_REPO')
    if env:
        roots.append(env)
    up = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):                 # walk up to find a sibling terminal-safe-corpus
        up = os.path.dirname(up)
        roots.append(os.path.join(up, 'terminal-safe-corpus'))
    for root in roots:
        if os.path.isfile(os.path.join(root, corpus_board_relpath('colorgrad'))):
            return root
    return None


# ---------------------------------------------------------------------------
# Capture harness.
# ---------------------------------------------------------------------------

# Harnesses register here so the QApplication + MainWindow they hold are NEVER garbage
# collected: a drop-to-zero refcount runs Qt's C++ destructors, which intermittently
# SIGSEGV in static teardown. Callers exit via os._exit (which runs no destructors), so
# holding the objects alive until the process dies is the correct, race-free teardown --
# the same reason the widget suites os._exit in finish() instead of returning.
_KEEPALIVE = []


def _detach(img):
    """Return an independent, standard-format copy of a grabbed image. A raw
    grab().toImage() can share its backing store with the source pixmap; converting to a
    plain format AND copying detaches it, so a later .save() / pixel read is safe (a
    shared-buffer save segfaulted under headless wayland)."""
    return img.convertToFormat(QImage.Format.Format_ARGB32).copy()


def image_hash(img):
    """A stable content hash of an image's pixels, for the stability check (two captures
    of the same cell must be byte-identical) and any golden comparison. Normalizes format
    first so two equal renders hash equal regardless of the grab's native format."""
    import hashlib
    norm = img.convertToFormat(QImage.Format.Format_ARGB32)
    ptr = norm.constBits()
    ptr.setsize(norm.sizeInBytes())
    return hashlib.sha256(bytes(ptr)).hexdigest()


def app():
    return QApplication.instance() or QApplication([])


def _pump(ms):
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def feed_output(term, raw):
    """Drive the REAL _on_readable with `raw` bytes via a pipe, as a child would print
    them -- runs the whole output path (pyte feed + OSC handlers + line render) AND sets
    _raw, so a later reflow replays real retained output. Chunked at the pty read size
    so a large payload cannot block the pipe."""
    old = term._fd
    first = True
    try:
        while raw or first:
            first = False
            chunk, raw = raw[:65536], raw[65536:]
            r, w = os.pipe()
            term._fd = r
            w_open = True
            try:
                os.write(w, chunk)
                os.close(w)
                w_open = False
                term._on_readable()
            finally:
                os.close(r)
                if w_open:
                    os.close(w)
    finally:
        term._fd = old
    term._flush_paint()


class ZoomHarness:
    """One live MainWindow reused across the sweep. A fresh tab is built per capture so
    board bytes never bleed between cells; the tab's child is shut down after the grab.
    """

    def __init__(self, show=True):
        self.app = app()
        # Freeze the text cursor: a blinking cursor never stops changing, so the settle
        # wait cannot converge and two grabs catch different blink phases (a stability
        # flake). 0 = no blink, cursor steady -> captures are deterministic.
        self.app.setCursorFlashTime(0)
        self.win = MainWindow()
        # MAP the window (show=True). An UNMAPPED top-level does not reliably propagate a
        # resize to its child viewport, so the terminal computes _cols from a stale narrow
        # size -- content then wraps at ~14 columns and the capture is nondeterministic
        # (layout sometimes settles, sometimes not). A mapped window under the headless
        # labwc compositor lays out correctly and deterministically. The exit-time Qt
        # destructor SIGSEGV that mapping otherwise triggers is prevented by _KEEPALIVE (the
        # objects are never garbage-collected; the process ends via os._exit).
        if show:
            self.win.show()
        self.win.resize(1280, 800)
        _pump(80)
        self._tabs = []
        _KEEPALIVE.append(self)          # never let Qt destructors run (see _KEEPALIVE)
        # Retire the window's startup tab so a captured shot shows ONLY the cell's own
        # tab (else the tab bar carries a stray empty startup tab beside it). shutdown()
        # releases its pty; removeTab detaches it without destroying (no teardown SIGSEGV).
        for i in reversed(range(self.win.tabs.count())):
            w = self.win.tabs.widget(i)
            if isinstance(w, SecureTerminal):
                try:
                    w.shutdown()
                except Exception:
                    pass                 # best-effort pty release; removeTab still detaches it
            self.win.tabs.removeTab(i)

    def _new_tab(self, mode, display_mode, cat_file=None):
        # cat_file (CLI publish path): launch `cat <corpus-file> -` so the tab banner
        # honestly shows the reproduce path; the file's bytes arrive via the real pty read
        # (same _raw/reflow path feed_output drives). The trailing `-` makes cat read stdin
        # AFTER the file, so it does NOT exit into a shell prompt -- the shot stays clean
        # (banner + board only), matching the bare-cat shots. Else a bare `cat` fed out of
        # band -- required for TUI (feed AFTER the zoom, see capture) and the regression suite.
        command = ['/bin/cat', cat_file, '-'] if cat_file else '/bin/cat'
        term = self.win.new_tab(command=command, tui=(mode == 'tui'))
        # new_tab returns None in some builds; fall back to the current widget.
        if not isinstance(term, SecureTerminal):
            term = self.win.tabs.currentWidget()
        assert isinstance(term, SecureTerminal), 'active tab is not a terminal'
        self.win.tabs.setCurrentWidget(term)
        # Route the display mode through the WINDOW (not term.apply_mode) so the toolbar
        # unicode chip tracks it -- a shot must not show "Detail" while rendering "Show".
        # set_mode refuses reveal/detail in TUI (the fixed grid cannot expand inline), so
        # the matrix only pairs TUI with show/box (see valid_display_for).
        self.win.set_mode(display_mode)
        self._tabs.append(term)
        return term

    def _zoom_walk(self, term, target, seed):
        """A reproducible randomized Ctrl+wheel walk that ENDS pinned at `target`.
        The walk emits real +-1 zoom steps (the debounce/coalesce path) through
        intermediate levels; then set_zoom lands the exact canonical percent."""
        rng = random.Random(seed)
        steps = rng.randint(3, 8)
        for _ in range(steps):
            term.zoom_step.emit(1 if rng.random() < 0.5 else -1)
            _pump(8)               # let steps coalesce as a burst, like a real wheel
        _pump(60)                  # drain the zoom debounce
        self.win.set_zoom(clamp_zoom(target))
        _pump(90)                  # font-debounce + reflow settle
        term._flush_paint()

    def capture(self, board, mode, resolution, zoom, display_mode=PRIMARY_DISPLAY, seed=None,
                board_name=None):
        """Build a tab in the given tab-mode (cli/tui) + unicode display-mode, feed the
        board, walk+pin zoom, settle, and return a result dict {term, win_image,
        viewport_image, zoom}. The tab is left open (reaped by close_term/close) so
        callers may inspect the live document before it is retired.

        board_name (the PUBLISH path): in CLI mode, `cat` the board's committed
        terminal-safe-corpus file instead of injecting the bytes -- so the shot's banner
        names the real reproduce path (`/bin/cat .../demos/zoom-<name>-safe-to-cat.txt`).
        Requires the corpus checked out (fail loud if the file is absent -- a silent
        fallback would re-ship the bare `/bin/cat` banner). TUI keeps the out-of-band feed
        (a static cat dumped before the zoom would garble; see the feed-order note)."""
        w, h = resolution
        self.win.resize(w, h)
        _pump(60)
        cat_file = None
        prev_cwd = None
        if board_name is not None and mode == 'cli':
            root = corpus_root()
            cat_file = corpus_board_relpath(board_name)
            if root is None or not os.path.isfile(os.path.join(root, cat_file)):
                raise SystemExit(
                    'zoom publish: terminal-safe-corpus board file %r not found; '
                    'check out terminal-safe-corpus as a sibling or set '
                    'TERMINAL_SAFE_CORPUS_REPO' % cat_file)
            # Spawn cat from the corpus root so the banner shows the RELATIVE reproduce
            # path (a clean `demos/...`, not an absolute build-tree path). The child's cwd
            # is fixed at fork, so restore ours right after.
            prev_cwd = os.getcwd()
            os.chdir(root)
        try:
            term = self._new_tab(mode, display_mode, cat_file=cat_file)
        finally:
            if prev_cwd is not None:
                os.chdir(prev_cwd)
        if seed is None:
            # A STABLE seed (crc32, not builtin hash() -- hash() is per-process randomized
            # by PYTHONHASHSEED, which would make the "reproducible" walk differ every run
            # and break golden/stability comparison).
            key = '%s|%s|%dx%d|%d' % (mode, display_mode, resolution[0], resolution[1], zoom)
            seed = zlib.crc32(key.encode())
        # Feed order is mode-aware:
        #  - CLI: feed THEN walk zoom. The flowing document replays _raw on each zoom, so
        #    the walk genuinely exercises the reflow/re-wrap path with content on screen.
        #  - TUI: walk zoom THEN feed. A TUI grid is redrawn by the PROGRAM on SIGWINCH;
        #    feeding once then resizing (with no program to redraw) would just scroll the
        #    static content away, leaving a blank/garbled grid -- a test artifact, not an
        #    app bug. Landing the zoom first, then feeding, renders the board into the
        #    FINAL grid exactly as a SIGWINCH-aware program would (the same reason the
        #    zoom-live capture re-injects after each zoom).
        if mode == 'cli':
            if cat_file is not None:
                # cat reads the real file: its output arrives via the pty (real _on_readable,
                # setting _raw), so wait for it to land before walking the zoom.
                for _ in range(200):
                    _pump(20)
                    if term._raw:
                        break
                _pump(40)
            else:
                feed_output(term, board)
                _pump(40)
            self._zoom_walk(term, zoom, seed)
        else:
            self._zoom_walk(term, zoom, seed)
            feed_output(term, board)
            _pump(40)
            term._flush_paint()
        # Wait for the render to SETTLE before grabbing: a dense truecolour board (every
        # cell a distinct colour, no run-coalescing) paints slowly, so a fixed pump can
        # grab a half-drawn frame -- two captures then differ (stability flake) and the
        # ink fraction is wrong. Poll the viewport hash until two consecutive grabs match
        # (or a bound), exactly as the shot harness's st_wait_render_settled does.
        self._settle(term)
        return {
            'term': term,
            'zoom': self.win.current_zoom_percent(),
            'win_image': _detach(self.win.grab().toImage()),
            'viewport_image': _detach(term.viewport().grab().toImage()),
        }

    def _settle(self, term, max_polls=40, interval_ms=80):
        """Pump the event loop until the viewport render stops changing (two consecutive
        grabs byte-identical), or max_polls elapse. Makes a slow (dense-truecolour) render
        deterministic before the grab -- the settled frame is what capture() returns."""
        term._flush_paint()
        prev = image_hash(term.viewport().grab().toImage())
        for _ in range(max_polls):
            _pump(interval_ms)
            term._flush_paint()
            cur = image_hash(term.viewport().grab().toImage())
            if cur == prev:
                return
            prev = cur

    def close_term(self, term):
        """Retire a single cell's tab: release its pty (shutdown) and detach it from the
        tab bar so the sweep does not keep pumping every prior tab's timers. The widget
        is NOT destroyed here -- destroying a SecureTerminal mid-run re-enters the Qt
        static-teardown / pty race that SIGSEGVs (the suites only ever shutdown(), never
        close/destroy; see the secure-terminal skill). removeTab merely reparents it out
        of the QTabWidget; it stays alive but inert until the process os._exit()s.

        Memory: a fresh tab per cell means a very long single-process sweep still
        accumulates inert widgets, so the full 640-cell diagnostic is chunked per board
        (zoom_sweep) rather than run in one process; the bounded CI suite stays well
        under any pressure."""
        try:
            term.shutdown()
        except Exception:
            pass                         # best-effort pty release; the retire proceeds regardless
        idx = self.win.tabs.indexOf(term)
        if idx >= 0:
            self.win.tabs.removeTab(idx)
        if term in self._tabs:
            self._tabs.remove(term)

    def close(self):
        for term in list(self._tabs):
            self.close_term(term)
        self._tabs = []


# ---------------------------------------------------------------------------
# Detectors. Each returns a list of issue strings (empty == clean), or a scalar for
# the pixel one. All are deterministic on the document/geometry except ink_fraction.
# ---------------------------------------------------------------------------

def block_texts(term):
    doc = term.document()
    out = []
    b = doc.firstBlock()
    while b.isValid():
        out.append(b.text())
        b = b.next()
    return out


def _interior_blank_count(texts):
    """Blank blocks that have a non-blank block both before AND after (a spurious blank
    row split into the middle of content). A block is "blank" when it has no visible
    text -- whitespace-only counts as blank. The SAME normalization (full strip) decides
    both the non-blank span and the interior blanks, so a whitespace-only leading or
    trailing block (e.g. a wrapped continuation of spaces) is not miscounted as interior.
    Pure over a block-text list, so the edge cases are directly testable."""
    norm = [t.strip() for t in texts]
    nonblank = [i for i, t in enumerate(norm) if t != '']
    if not nonblank:
        return 0
    first, last = nonblank[0], nonblank[-1]
    return sum(1 for i in range(first, last) if norm[i] == '')


def interior_blank_blocks(term):
    """Interior blank count over the tab's rendered blocks. The no-newline marker is a
    gutter glyph / zero-text run, not inline text, so it never reaches block text."""
    return _interior_blank_count(block_texts(term))


def trailing_blank_blocks(term):
    """Consecutive empty blocks at the very end, beyond the single cursor line a
    terminal legitimately keeps."""
    texts = [t.strip() for t in block_texts(term)]
    n = 0
    for t in reversed(texts):
        if t == '':
            n += 1
        else:
            break
    return max(0, n - 1)


def _bg_color(img):
    # Modal colour of the four corners: a robust background estimate independent of
    # theme (light or dark), without hardcoding a palette.
    w, h = img.width(), img.height()
    if w < 2 or h < 2:
        return img.pixel(0, 0)
    corners = [img.pixel(0, 0), img.pixel(w - 1, 0),
               img.pixel(0, h - 1), img.pixel(w - 1, h - 1)]
    return max(set(corners), key=corners.count)


def ink_fraction(img, step=4):
    """Fraction of sampled pixels that differ from the background. ~0 == blank screen."""
    if img.isNull():
        return 0.0
    w, h = img.width(), img.height()
    if w == 0 or h == 0:
        return 0.0
    bg = _bg_color(img)
    ink = 0
    total = 0
    y = 0
    while y < h:
        x = 0
        while x < w:
            total += 1
            if img.pixel(x, y) != bg:
                ink += 1
            x += step
        y += step
    return (ink / total) if total else 0.0


# Wrapping display modes: the child hard-wraps (CLI line mode) or the widget wraps
# (detail/reveal). Box/Show are deliberately NoWrap for cross-mode glyph stability, so a
# horizontal overflow there is expected, not a cutoff bug.
WRAPPING_MODES = ('detail', 'reveal')


def content_len(term):
    """Total non-whitespace text length across the document -- how much real text the
    tab is holding (0 for a colour-only board of spaces)."""
    return sum(len(t.strip()) for t in block_texts(term))


def analyze(result, spec, display_mode):
    """Per-cell detectors: the ones that give a reliable verdict from a SINGLE capture,
    with no false positives -- content that VANISHED. Returns a list of issue strings
    (empty == clean).

    Deliberately NOT gated here:
      - Absolute blank-row counts. A legit board row can be text-blank yet visually
        non-blank (a colorgrad row is coloured spaces), and a board can legitimately
        contain blank lines (ASCII art). The real "extraneous newline" artifact is
        ZOOM-INDUCED and is caught by zoom-invariance of the blank-row count across the
        canonical levels (analyze_zoom_invariance in the suite), not a per-cell threshold.
      - Horizontal overflow. This app always offers a manual-scroll scrollbar
        (ScrollBarAsNeeded) and deliberately leaves Box/Show (and plain coloured cells)
        NoWrap, so an overflow is reachable-by-scroll BY DESIGN, never an unrecoverable
        cutoff -- gating on it just detects "a scrollbar appeared". The function is kept
        for canaries; the visual case is covered by the golden + human-verification shots.
    """
    term = result['term']
    issues = []
    frac = ink_fraction(result['viewport_image'])

    # Blank-screen: a dense board that should fill the screen renders almost no ink.
    if spec['dense'] and not spec['tui_altscreen'] and frac < 0.02:
        issues.append('blank-screen: ink fraction %.4f on a dense board' % frac)

    # Invisible-content: the tab holds substantial real text yet the viewport shows
    # essentially NOTHING (near-zero ink) -- the content vanished / scrolled out of view
    # with nothing on screen. The threshold is deliberately near zero: tiny text in a
    # large window at low zoom is legitimately sparse (ink a few thousandths) but NOT
    # invisible, so only an all-but-empty viewport counts. A top-pinned alt frame
    # legitimately leaves most of the viewport blank, so it is exempt. Mode-agnostic.
    if not spec['tui_altscreen'] and content_len(term) >= 60 and frac < 0.0001:
        issues.append('invisible-content: %d chars of text but ink fraction %.4f'
                      % (content_len(term), frac))

    return issues


def blank_row_signature(term):
    """(interior, trailing) blank-block counts for a CLI capture. Meaningful only in CLI
    (the TUI grid pads legitimately). Wrapped continuation blocks are non-empty, so this
    is invariant to how a long line wraps under zoom -- only a SPURIOUS blank row (a
    double-advance / extraneous newline introduced by a zoom/reflow) changes it."""
    return (interior_blank_blocks(term), trailing_blank_blocks(term))


def analyze_zoom_invariance(signatures):
    """Given {zoom: (interior, trailing)} for one CLI (board, display, resolution) across
    the canonical zooms, return issues if the blank-row signature is NOT constant. A
    changing count means a zoom level introduced (or dropped) a blank row -- the
    extraneous-newline artifact -- while a board's own blank lines stay constant."""
    issues = []
    uniq = set(signatures.values())
    if len(uniq) > 1:
        detail = ', '.join('z%d=%s' % (z, signatures[z]) for z in sorted(signatures))
        issues.append('blank-row count varies with zoom (extraneous-newline artifact): '
                      + detail)
    return issues
