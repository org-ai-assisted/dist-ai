#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Tests for secure_terminal.cli -- the command-line sanitizing wrapper
## (secure-terminal-cli). It runs a command in a pseudo-terminal and neutralizes
## the output with the same core as the GUI.
##
## cli.main() is driven IN THIS PROCESS (not a forked child) so coverage.py can
## measure it: the process's own stdin/stdout/stderr are temporarily redirected
## to a pty, a helper thread feeds keystrokes and drains the sanitized output,
## and cli.main() runs on the main thread until the wrapped command exits. This
## exercises the real tty paths (raw mode, window size, resize, SIGWINCH,
## Ctrl-C) while keeping the traced code on the measured main thread. The only
## line that cannot be measured this way is the post-fork/pre-exec child block,
## which is marked no-cover in cli.py and covered end-to-end here (exit 127).

import os
import sys
import pty
import time
import fcntl
import select
import signal
import struct
import termios
import threading

try:
    from secure_terminal import cli
except Exception as exc:  # fail closed: a required dependency must not silently skip
    sys.stderr.write('secure-terminal-tests: FAIL missing dependency: '
                     '%s\n' % exc)
    sys.exit(1)

os.environ['SHELL'] = '/bin/sh'          # deterministic default-shell path

_failures = 0
_passed = 0


def ok(cond, msg):
    global _failures, _passed
    if cond:
        _passed += 1
        print('ok   %s' % msg)
    else:
        _failures += 1
        print('FAIL: %s' % msg)


def eq(got, want, msg):
    ok(got == want, '%s (got %r, want %r)' % (msg, got, want))


def _strip_bp(out):
    """Drop the bracketed-paste enable/disable the wrapper now writes to the OUTER
    terminal on a tty (DECSET 2004 on at startup, off at teardown). They are the
    ONLY escapes the wrapper legitimately emits itself; every other escape in the
    child's output must still be stripped, so tests assert on the remainder."""
    return out.replace(cli._BP_ENABLE, b'').replace(cli._BP_DISABLE, b'')


def _set_winsize(fd, rows, cols):
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
    except OSError:
        pass                # a pty may reject the window size; it is advisory


def run_in_pty(argv, feed=b'', feed2=b'', feed2_delay=0.4, tty_stdin=True,
               settle=0.8, feed_delay=0.0,
               winsize=None, close_stdin=False, send_winsize=False,
               send_sigint=False):
    """Run cli.main(argv) on THIS thread with fd 0/1/2 redirected to a pty (or,
    when tty_stdin is False, stdin to a pipe). A helper thread supplies `feed`
    and collects the sanitized output. Returns (output_bytes, exit_code)."""
    out_master, out_slave = pty.openpty()
    if winsize:
        _set_winsize(out_slave, *winsize)
    in_r = in_w = None
    if not tty_stdin:
        in_r, in_w = os.pipe()
    saved = (os.dup(0), os.dup(1), os.dup(2))
    os.dup2(out_slave, 1)
    os.dup2(out_slave, 2)
    os.dup2(out_slave if tty_stdin else in_r, 0)
    writer = out_master if tty_stdin else in_w
    chunks = []
    stop = threading.Event()
    prev_winch = signal.getsignal(signal.SIGWINCH)
    # A real interactive terminal delivers Ctrl-C with SIGINT at its DEFAULT
    # disposition (-> KeyboardInterrupt). When the whole suite is launched in the
    # BACKGROUND (CI, nohup, a detached runner), the shell hands its children
    # SIGINT as SIG_IGN; Python then KEEPS SIG_IGN and never installs its
    # KeyboardInterrupt handler, so the Ctrl-C test can reach 130 only when the
    # suite happens to run in the foreground. Pin the default handler for the
    # duration so the test reflects real terminal use however it was started.
    prev_sigint = signal.getsignal(signal.SIGINT)
    if send_sigint:
        signal.signal(signal.SIGINT, signal.default_int_handler)

    def driver():
        if feed_delay:
            time.sleep(feed_delay)             # let the wrapper install handlers
        if send_winsize:
            os.kill(os.getpid(), signal.SIGWINCH)
        if send_sigint:
            os.kill(os.getpid(), signal.SIGINT)
        if feed:
            try:
                os.write(writer, feed)
            except OSError:
                pass        # the child may have exited; the feed is best-effort
        if feed2:
            # a SEPARATE later write, so the wrapper takes a distinct os.read() --
            # e.g. a rescue keystroke arriving after a first burst (used to tell the
            # verbatim-forward behaviour apart from the old submit-stripping one).
            time.sleep(feed2_delay)
            try:
                os.write(writer, feed2)
            except OSError:
                pass        # the child may have exited; the feed is best-effort
        if close_stdin and not tty_stdin:
            try:
                os.close(in_w)                 # EOF on the wrapper's stdin
            except OSError:
                pass        # already closed by a prior path; harmless
        while not stop.is_set():
            try:
                r, _, _ = select.select([out_master], [], [], 0.1)
            except OSError:
                break
            if r:
                try:
                    c = os.read(out_master, 65536)
                except OSError:
                    break
                if not c:
                    break
                chunks.append(c)

    thread = threading.Thread(target=driver)
    thread.daemon = True
    thread.start()
    rc = 0
    try:
        rc = cli.main(argv)
    finally:
        time.sleep(0.15)                       # let the driver drain last output
        stop.set()
        thread.join(timeout=2)
        os.dup2(saved[0], 0)
        os.dup2(saved[1], 1)
        os.dup2(saved[2], 2)
        for fd in saved:
            try:
                os.close(fd)
            except OSError:
                pass        # a saved fd may already be closed; ignore
        # Restore each handler INDEPENDENTLY: a failure restoring SIGWINCH (e.g. a
        # C-installed prev_winch is None -> TypeError) must not skip the SIGINT
        # restore and leak the default handler into later tests.
        try:
            signal.signal(signal.SIGWINCH, prev_winch)
        except (OSError, ValueError, TypeError):
            pass            # restoring the handler off the main thread may fail
        if send_sigint:
            try:
                signal.signal(signal.SIGINT, prev_sigint)
            except (OSError, ValueError, TypeError):
                pass        # an off-main-thread restore may fail; harmless
        for fd in (out_master, out_slave, in_r, in_w):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass    # a pty/pipe fd may already be closed; ignore
    return b''.join(chunks), rc


# --- output is sanitized: escapes stripped, non-ASCII neutralised --------------
_out, _rc = run_in_pty(['--', 'printf',
                        'a\x1b[31mRED\x1b]0;title\x07b\xc2\xa0c'], winsize=(30, 100))
ok(b'\x1b' not in _strip_bp(_out),
   'CLI output carries no escape byte (ANSI/OSC stripped; only the outer-terminal '
   'bracketed-paste enable/disable is the wrapper\'s own)')
ok(b'RED' in _out and b'title' not in _out,
   'the SGR colour text shows; the OSC title payload is stripped')
ok(b'\xc2\xa0' not in _out, 'a non-ASCII byte is neutralised (not passed through)')
eq(_rc, 0, 'a command that exits cleanly returns 0')

# --- a sequence SPLIT across two real pty reads is still stripped whole -------
# render_output is stateless per chunk, so a sequence cut by a read boundary loses
# its introducer and the REMAINDER prints as text -- straight onto the OUTER
# terminal, `\r` and all, which is a prompt-spoofing primitive that needs no
# escape to survive. Only the read loop's carry makes it whole, so drive it here
# rather than grepping cli.py for the call: the child sleeps between writes so the
# wrapper genuinely takes two os.read()s.
## One shell script, split over three source lines for width; the explicit +
## keeps it one argument and marks the joining as deliberate, not a lost comma.
_split_o, _split_rc = run_in_pty(['--', 'sh', '-c',
    'printf "\\033[3"; sleep 0.4; '
    + 'printf "1mSAFE\\033]0;t"; sleep 0.4; '
    + 'printf "\\rroot@host# \\007END\\n"'], settle=2.0)
ok(b'SAFEEND' in _split_o,
   'the visible text of a split-up stream survives the carry intact')
ok(b'31m' not in _split_o,
   'a CSI split across two reads leaks no parameter bytes (no "31m")')
ok(b'root@host' not in _split_o,
   'an OSC split across two reads never spills a fake prompt onto the terminal')
ok(b'\x1b' not in _strip_bp(_split_o),
   'no escape byte reaches the outer terminal either way (bar the wrapper\'s own '
   'bracketed-paste enable/disable)')
eq(_split_rc, 0, 'the split-sequence child exits cleanly')

# A never-terminating OSC/DCS makes the wrapper discard all following output (a
# silent freeze). The suppression is NEVER lifted -- no escape byte reaches the
# outer terminal -- but past a threshold a one-time stderr notice explains the blank
# rather than leaving a dead terminal (claude ai-review: cli.py had this unmitigated).
## One shell command, split over two source lines for width; the + keeps it one arg.
_supp_o, _supp_rc = run_in_pty(['--', 'sh', '-c',
    'printf "\\033]0;"; head -c 200000 < /dev/zero | tr "\\000" A'], settle=2.0)
ok(b'suppressing output' in _supp_o,
   'an unterminated over-long escape sequence triggers the one-time suppression notice')
ok(b'AAAA' not in _strip_bp(_supp_o),
   'the suppressed payload never reaches the outer terminal (no leak as text)')
ok(b'\x1b' not in _strip_bp(_supp_o),
   'no escape byte leaks from the suppressed sequence (bar the wrapper bracketed-paste)')
eq(_supp_rc, 0, 'the suppressed-output child exits cleanly')

# --- display modes ------------------------------------------------------------
_o2, _ = run_in_pty(['--mode', 'reveal', '--', 'printf', 'x\u200by'])
ok(b'<U+200B>' in _o2, 'reveal mode shows the <U+XXXX> badge for a zero-width space')
_o3, _ = run_in_pty(['--mode', 'box', '--', 'printf', 'x\u200by'])
ok(b'x_y' in _o3, 'box mode maps the neutralised byte to _')

# F2: SHOW-mode Zalgo cap. render_output keeps every combining mark (it is a per-char
# homomorphism -- the T1 proof), so a flood of them would reach the real terminal via
# --mode show. cap_zalgo_show bounds each run at the CLI boundary. Unit + end-to-end.
from secure_terminal.sanitize import cap_zalgo_show, _ZALGO_MARK_MAX      # noqa: E402
_zc, _zt = cap_zalgo_show('a' + '\u0301' * 5000, 0)
ok(_zc.count('\u0301') == _ZALGO_MARK_MAX and _zt == _ZALGO_MARK_MAX,
   'cap_zalgo_show caps a Zalgo run at the mark limit')
ok(cap_zalgo_show('e\u0301\u0323', 0)[0] == 'e\u0301\u0323',
   'cap_zalgo_show leaves legit decomposed text (<= cap) unchanged')
_zc1, _zt1 = cap_zalgo_show('a' + '\u0301' * 5, 0)          # a partial run, then a carry
_zc2, _zt2 = cap_zalgo_show('\u0301' * 5000, _zt1)
ok(_zc1.count('\u0301') == 5 and _zc2.count('\u0301') == _ZALGO_MARK_MAX - 5,
   'cap_zalgo_show threads the run count across chunk reads (bounded total)')
_oz, _rcz = run_in_pty(['--mode', 'show', '--', 'python3', '-c',
                        'import sys; sys.stdout.write("a" + "\\u0301" * 5000)'])
ok(_oz.count(b'\xcc\x81') <= _ZALGO_MARK_MAX,
   'show mode caps a Zalgo flood reaching the real terminal (%d marks)'
   % _oz.count(b'\xcc\x81'))

# --- child environment: dumb terminal + no-op pager ---------------------------
# the CLI wrapper interprets no escapes, so it advertises a dumb terminal and
# defaults PAGER to a no-op cat (compatibility page: TERM=dumb, PAGER=cat)
os.environ.pop('PAGER', None)
_oenv, _ = run_in_pty(['--', 'sh', '-c', 'printf T=$TERM,P=$PAGER,'])
ok(b'T=dumb,' in _oenv, 'the cli wrapper child sees TERM=dumb')
ok(b'P=cat,' in _oenv, 'the cli wrapper child sees PAGER=cat by default')

# --- real line tools run under the wrapper: output survives, no escape leaks ---
# a representative slice of the compatibility programs table; the full-screen,
# interactive and network tools in it stay manual captures by design
# && chains the steps so any failure short-circuits and propagates its exit code
# (a ; chain would return only awk's status and mask an earlier failure); each
# result is labelled so an assertion cannot be satisfied by a stray digit elsewhere
## One shell pipeline, split over two source lines for width; the explicit +
## keeps it one argument and marks the joining as deliberate, not a lost comma.
_prog_o, _prog_rc = run_in_pty(['--', 'sh', '-c',
    'printf "beta\\nalpha\\n" | sort | sed "s/^/> /" | grep -c "^> " '
    + '| sed "s/^/count=/" && ls -1 /bin/sh && printf "awk=" && awk "BEGIN{print 6*7}"'])
ok(b'\x1b' not in _strip_bp(_prog_o),
   'real line tools (sort/sed/grep/ls/awk) leave no escape byte in the output '
   '(bar the wrapper\'s own bracketed-paste enable/disable)')
ok(b'count=2' in _prog_o,
   'the sort|sed|grep -c pipeline yields exactly 2 lines (labelled, not a stray digit)')
ok(b'/bin/sh' in _prog_o, 'ls output passes through')
ok(b'awk=42' in _prog_o, 'awk arithmetic output passes through')
eq(_prog_rc, 0, 'the chained real-tool commands all exit cleanly under the wrapper')

# --- exit-code propagation ----------------------------------------------------
eq(run_in_pty(['--', 'sh', '-c', 'exit 7'])[1], 7, 'a non-zero exit is propagated')
eq(run_in_pty(['--', 'sh', '-c', 'kill -TERM $$'])[1], 128 + signal.SIGTERM,
   'a child killed by a signal returns 128+signum')
eq(run_in_pty(['--', 'no-such-command-secure-terminal-xyz'])[1], 127,
   'a command that cannot be exec()d returns 127')

# --- pipe (non-tty) stdin: the raw-mode setup is skipped, output still safe ----
_o4, _rc4 = run_in_pty(['--', 'printf', 'q\x1b[2Jr'], tty_stdin=False)
ok(b'\x1b' not in _o4 and b'qr' in _o4,
   'with a non-tty stdin the output is still sanitized (qr, no clear-screen)')
eq(_rc4, 0, 'non-tty run still returns the child exit code')

# --- stdin EOF forwarding: closing our stdin sends the child an EOF (Ctrl-D) ---
_o4b, _rc4b = run_in_pty(['--', 'cat'], tty_stdin=False, feed=b'hi\n',
                         close_stdin=True, settle=1.0)
ok(b'hi' in _o4b, 'the wrapper forwards our input to the child (cat echoes it)')
eq(_rc4b, 0, 'a stdin EOF is forwarded so the child (cat) sees end-of-input and exits')

# COR-2: after stdin EOF the wrapper stops selecting on stdin and re-sends ^D at a SLOW
# cadence, not a 100%-CPU flood. A closed fd stays readable, so the base code re-read it every
# iteration and spun spamming EOF for as long as the child lived. Count the b'\x04' writes
# while a child (sleep) that does NOT exit on ^D lingers briefly: a few nudges, not thousands.
_eof_writes = [0]
_real_oswrite = cli.os.write
def _count_eof_write(_fd, _data):
    if _data == b'\x04':
        _eof_writes[0] += 1
    return _real_oswrite(_fd, _data)
cli.os.write = _count_eof_write
try:
    run_in_pty(['--', 'sleep', '0.3'], tty_stdin=False, close_stdin=True, settle=0.8)
finally:
    cli.os.write = _real_oswrite
ok(_eof_writes[0] <= 3,
   'COR-2: stdin EOF sends the child a few slow EOF nudges, not a 100%%-CPU flood while '
   'the child lives (no busy-loop) -- got %d b\'\\x04\' writes' % _eof_writes[0])

# COR-2 bound: a program that reads ^D as DATA (a raw-mode reader) never exits on it, so the
# re-sends are CAPPED at cli._EOF_NUDGE_MAX -- not a per-200ms ^D stream for the child's whole
# life. A child living past the ~2s budget receives at most that many nudges, then none.
_eof_bound = [0]
_real_ob = cli.os.write
def _count_bound(_fd, _data):
    if _data == b'\x04':
        _eof_bound[0] += 1
    return _real_ob(_fd, _data)
cli.os.write = _count_bound
try:
    run_in_pty(['--', 'sleep', '2.6'], tty_stdin=False, close_stdin=True, settle=0.5)
finally:
    cli.os.write = _real_ob
ok(_eof_bound[0] <= cli._EOF_NUDGE_MAX + 1,
   'COR-2: EOF nudges are capped at _EOF_NUDGE_MAX for a child that never exits on ^D (no '
   'indefinite ^D stream) -- got %d, cap %d' % (_eof_bound[0], cli._EOF_NUDGE_MAX))

# COR-2 robustness: the child can exit and close the pty between the writable check and the
# EOF write, so os.write raises OSError -- the wrapper must exit cleanly, not traceback. Force
# the nudge write to raise and assert _run still returns an int status.
_real_eofw = cli.os.write
def _raise_on_eof(_fd, _data):
    if _data == b'\x04':
        raise OSError(5, 'EIO')          # pty closed under us
    return _real_eofw(_fd, _data)
cli.os.write = _raise_on_eof
try:
    _oe2, _rce2 = run_in_pty(['--', 'sleep', '0.5'], tty_stdin=False, close_stdin=True, settle=0.5)
finally:
    cli.os.write = _real_eofw
ok(isinstance(_rce2, int),
   'COR-2: a PTY close during EOF delivery exits cleanly (no traceback)')

# --- stdin forwarding + Enter: typed input runs on the user's explicit Enter ----
# 'exit 3' is forwarded verbatim (it carries no submit byte), then a SEPARATE lone
# Enter keystroke submits it -- so an ordinary command still runs.
_o5, _rc5 = run_in_pty([], feed=b'exit 3', feed2=b'\r', settle=1.5, feed_delay=0.6)
eq(_rc5, 3, 'typed input plus a real Enter runs the command and its exit propagates')

# --- HONESTY: stdin is forwarded VERBATIM (no paste/typing heuristic) -----------
# A raw stdin stream cannot reliably tell a paste from typing: os.read() boundaries
# are scheduling artifacts, so fast typing (or SSH/TTY-coalesced keystrokes) and a
# paste arrive in the same shape -- a multi-byte read ending in a submit byte. The
# CLI therefore forwards keystrokes UNCHANGED and does NOT strip a trailing submit;
# auto-submit protection lives in the GUI. The old code shipped a burst-strip
# heuristic that BROKE normal typing: 'cmd\r' delivered in ONE read lost its Enter
# and the command never ran. This canary pins the honest behaviour and FAILS on
# that old code: 'exit 5\r' as a SINGLE burst submits (rc 5). The rescue burst
# (Ctrl-C to abort any pending line, then 'exit 7') only fires under the old
# stripping code -- there the first burst never submitted -- yielding rc 7, so the
# two behaviours are told apart with no hang and no reliance on terminal echo.
_ob, _rcb = run_in_pty([], feed=b'exit 5\r', feed2=b'\x03exit 7\r',
                       settle=1.8, feed_delay=0.6, feed2_delay=0.6)
eq(_rcb, 5, 'a single-read burst ending in Enter submits verbatim (typing is not '
            'eaten); the old submit-stripping heuristic would rescue to exit 7')

# --- #50 CLI bracketed-paste protection --------------------------------------
# Auto-submit protection reaches the CLI the way every shell already gets it: the
# wrapper enables bracketed paste (DECSET 2004) on the OUTER terminal, so a paste
# arrives wrapped in ESC[200~ .. ESC[201~ framing that TELLS it apart from typing.
# feed_stdin_paste is the pure state machine; drive its branches directly (chars
# and split boundaries) here, then the end-to-end wiring through cli.main below.


def _paste(chunks, state=(False, b'', b'')):
    """Feed each bytes chunk through feed_stdin_paste in turn; return the
    concatenated child-bound bytes and the final carried state."""
    out = b''
    for chunk in chunks:
        piece, state = cli.feed_stdin_paste(chunk, state)
        out += piece
    return out, state


# a framed paste's trailing auto-submit ('\n' -> '\r') is neutralized, and the
# 200~/201~ markers never reach the child
_p_out, _p_st = _paste([b'\x1b[200~ls -la\n\x1b[201~'])
eq(_p_out, b'ls -la',
   'a framed paste is neutralized: trailing auto-submit dropped, command waits')
ok(b'\x1b[200~' not in _p_out and b'\x1b[201~' not in _p_out,
   'the 200~/201~ paste markers are stripped from the child input')
eq(_p_st, (False, b'', b''), 'a complete framed paste leaves no carried state')

# a multi-line CLI paste strips EVERY submit -- the CLI has no hold-for-review, so an
# interior CR would auto-run the command before it (embedded-CR pastejacking). Canary:
# the child gets "ab" (no CR); "a\rb" would submit "a" the instant the paste lands.
eq(_paste([b'\x1b[200~a\nb\n\x1b[201~'])[0], b'ab',
   'a multi-line CLI paste strips EVERY submit so no interior CR auto-runs a command')

# a paste split across reads: BODY across the boundary carries correctly
eq(_paste([b'\x1b[200~echo ', b'hi\n\x1b[201~'])[0], b'echo hi',
   'a paste body split across two reads is buffered whole before neutralizing')

# a paste split across reads: the MARKER itself split across the boundary carries
eq(_paste([b'\x1b[20', b'0~echo hi\n\x1b[2', b'01~'])[0], b'echo hi',
   'a 200~/201~ marker split across two reads is carried, not leaked as text')

# typed (UNFRAMED) bytes are forwarded byte-for-byte, submit byte and all
eq(_paste([b'exit 5\r'])[0], b'exit 5\r',
   'typed (unframed) input is forwarded verbatim -- no submit strip on typing')

# a typed escape (an arrow key) is forwarded verbatim, not mistaken for a marker
eq(_paste([b'\x1b[A'])[0], b'\x1b[A',
   'a typed escape sequence is forwarded verbatim (not confused with 200~)')

# an escape INSIDE a paste body is neutralized by sanitize_paste (ESC byte dropped;
# its residual printable letters are inert -- the same as the GUI paste path)
eq(_paste([b'\x1b[200~a\x1b[31mb\x1b[201~'])[0], b'a[31mb',
   'an escape inside a paste body has its ESC control byte stripped')

# regression (reviewdrain3, SECURITY): a paste-START marker split by a read boundary as
# ESC | '[200~...' is now HELD, so it still enters paste mode and its body is neutralized.
# Pre-fix a lone ESC was forwarded inline, so the trailing '[200~echo hi\r' reached the
# child as TYPED input and the CR auto-ran it (pastejacking). Canary: the CR is stripped.
_split = _paste([b'\x1b', b'[200~echo hi\r\x1b[201~'])
eq(_split[0], b'echo hi',
   'a split ESC|[200~ paste-start marker is held and enters paste mode (body neutralized)')
ok(b'\r' not in _split[0],
   'the split paste body has its interior CR stripped -- no auto-run (pastejacking closed)')

# the lone ESC is now HELD in carry (out empty); _run flushes it to the child after a
# bounded timeout so an interactive Escape still reaches the child (end-to-end test below).
_lone = _paste([b'\x1b'])
eq(_lone[0], b'', 'a lone ESC is held (deferred), not forwarded inline')
eq(_lone[1][2], b'\x1b', 'a lone ESC is carried so a split paste-start marker can reassemble')

# regression (reviewdrain3 + ai-review): an oversized bracketed-paste frame must (a) bound
# memory and (b) NOT let its runaway tail become typed input. On overflow the buffer stops
# growing but STAYS in paste, so the tail is swallowed (never auto-runs); the close marker
# ends it and typed input recovers. Cap shrunk so the test stays tiny.
_saved_max = cli._PASTE_MAX
cli._PASTE_MAX = 8
try:
    # SECURITY: the over-cap tail (here 'echo pwned\r') must never reach the child as typed
    # input -- even when it arrives in a LATER read than the overflow (the pastejacking the
    # old drop-and-exit had). It is dropped; the close marker ends the paste; 'exit\r' after
    # the marker is ordinary typing and IS forwarded.
    _ov_out, _ov_st = _paste([b'\x1b[200~' + b'A' * 20, b'echo pwned\r', b'\x1b[201~exit\r'])
    ok(b'pwned' not in _ov_out,
       'an over-cap paste tail is dropped, NOT forwarded as typed input (no pastejacking)')
    ok(_ov_out.endswith(b'exit\r') and _ov_st[0] is False,
       'the paste closes on its end marker even after overflow; later typing recovers')
    ok(len(_ov_st[1]) <= cli._PASTE_MAX, 'the paste buffer stays bounded at the cap')
    # memory is bounded even for a never-closing flood, and it stays IN paste (tail swallowed)
    _ov2_out, _ov2_st = _paste([b'\x1b[200~' + b'A' * 5000])
    ok(_ov2_st[0] is True and len(_ov2_st[1]) <= cli._PASTE_MAX,
       'an unterminated over-cap flood stays in paste with a bounded buffer (no typed tail)')
    ok(_ov2_out == b'', 'nothing from an unterminated over-cap flood reaches the child')
finally:
    cli._PASTE_MAX = _saved_max

# END-TO-END: a framed paste through cli.main does NOT auto-submit. The paste is
# `echo N''EUT` with a trailing newline; were that newline to auto-submit, the
# command would RUN and print NEUT. Instead its trailing submit is stripped, so the
# command waits UN-run; a Ctrl-U (VKILL) then erases the pending line and `exit 9`
# terminates. The input echo shows the literal "N''EUT" (no contiguous "NEUT"), so a
# contiguous NEUT in the output can ONLY be the command's own run -- its ABSENCE is
# the proof the paste never auto-submitted. (Ctrl-C is unusable as the rescue: VINTR
# flushes the rest of the same write, taking `exit 9` with it; Ctrl-U erases only the
# pending line and leaves the following bytes.)
_pe_o, _pe_rc = run_in_pty([], feed=b"\x1b[200~echo N''EUT\n\x1b[201~",
                           feed2=b'\x15exit 9\r', settle=2.0,
                           feed_delay=0.6, feed2_delay=0.8)
eq(_pe_rc, 9, 'the rescue exit runs end to end (paste framing handled, tty restored)')
ok(b'NEUT' not in _pe_o,
   'a framed paste carrying a newline does NOT auto-submit -- the echo command never '
   'ran; an unprotected wrapper would auto-run it and print NEUT')

# END-TO-END: a paste split across two reads (body in the first, end marker in the
# second) is still held un-submitted; a following typed Enter runs it (rc 4). This
# exercises the real read loop's cross-read paste carry and the empty-forward path.
_ps_o, _ps_rc = run_in_pty([], feed=b'\x1b[200~exit 4', feed2=b'\x1b[201~\r',
                           settle=1.8, feed_delay=0.6, feed2_delay=0.6)
eq(_ps_rc, 4, 'a paste split across reads waits un-submitted; a later typed Enter '
              'runs it (rc 4)')

# END-TO-END (reviewdrain3): a lone interactive ESC is HELD, then flushed to the child
# after the bounded _ESC_HOLD_TIMEOUT when no paste continuation arrives -- so an
# interactive Escape is not swallowed and the run still completes. Exercises the _run
# ESC-hold-and-flush path (the child ignores the ESC and exits on its own).
_esc_o, _esc_rc = run_in_pty(['--', 'sh', '-c', 'sleep 0.4; exit 7'],
                             feed=b'\x1b', feed_delay=0.2, settle=1.2)
eq(_esc_rc, 7, 'a held lone ESC is flushed after the timeout; the run completes (rc 7)')

# the wrapper enables bracketed paste on a tty OUTER terminal, and disables it on
# teardown -- so a paste is framed and can be told from typing
_bp_o, _ = run_in_pty(['--', 'printf', 'x'])
ok(cli._BP_ENABLE in _bp_o,
   'on a tty the wrapper enables bracketed paste (DECSET 2004h) on the outer term')
ok(cli._BP_DISABLE in _bp_o,
   'on teardown the wrapper disables bracketed paste (DECSET 2004l)')

# a NON-tty stdin has no outer terminal to frame a paste, so 2004 is NOT enabled
# and bytes are forwarded unchanged (a legacy-console / piped-input path)
_bpn_o, _ = run_in_pty(['--', 'printf', 'x'], tty_stdin=False)
ok(cli._BP_ENABLE not in _bpn_o,
   'a non-tty stdin does not enable bracketed paste (nothing to frame)')

# --- SIGWINCH during a run drives the resize handler (window size re-pushed) ---
_o6, _rc6 = run_in_pty(['--', 'sh', '-c', 'sleep 0.6'], feed_delay=0.2,
                       send_winsize=True, settle=1.0)
eq(_rc6, 0, 'a resize signal mid-run does not disturb the exit code')

# --- Ctrl-C (SIGINT) during a run is turned into exit 130 ----------------------
_o7, _rc7 = run_in_pty(['--', 'sh', '-c', 'sleep 1'], feed_delay=0.2,
                       send_sigint=True, settle=1.0)
eq(_rc7, 130, 'a KeyboardInterrupt (Ctrl-C) mid-run returns 130')

# --- waitpid can race a reaper: with SIGCHLD ignored the kernel auto-reaps the
# --- child, so the wrapper's waitpid raises ECHILD and it falls back to exit 0 -
_prev_chld = signal.getsignal(signal.SIGCHLD)
signal.signal(signal.SIGCHLD, signal.SIG_IGN)
try:
    _o8, _rc8 = run_in_pty(['--', 'printf', 'reaped'], settle=1.0)
finally:
    signal.signal(signal.SIGCHLD, _prev_chld)
eq(_rc8, 0, 'when the child is auto-reaped (SIGCHLD ignored) the wrapper returns 0')

# --- window-size helpers ------------------------------------------------------
eq(cli._outer_winsize.__name__, '_outer_winsize', 'winsize helper present')
_r, _c = cli._outer_winsize()
ok(_r > 0 and _c > 0, 'a fallback window size is always returned')
# _set_winsize on a non-sizable fd (a pipe) must not raise
_pr, _pw = os.pipe()
try:
    cli._set_winsize(_pr, 24, 80)
    ok(True, '_set_winsize on a non-sizable fd is a no-op, not an error')
finally:
    os.close(_pr)
    os.close(_pw)

# --- BOUNDED-EXHAUSTIVE paste-FSM verification -------------------------------------------
# feed_stdin_paste is a pure state machine, and the pastejacking class (a paste's content
# reaching the child as TYPED input -- via a split marker, an interior CR, or an oversized
# frame) is a safety property over ALL inputs and ALL read-boundary splits, not something a
# handful of examples can settle. Here we EXHAUSTIVELY enumerate every bracketed-paste token
# sequence up to _FSM_TOKENS tokens (START / END / CR / X) and, for each, over EVERY
# byte-boundary split, verify two invariants:
#   (1) split-invariance -- any chunking yields the SAME bytes-to-child as the whole input
#       (a marker split across reads must behave exactly like the whole marker); and
#   (2) no paste-region CR is ever forwarded -- a carriage return inside a bracketed paste is
#       an auto-run, so the count of CRs reaching the child must equal the TYPED-CR count.
# This is a bounded proof (complete for <= _FSM_TOKENS tokens, ~10^5 split-checks), not a
# sampled test: it FAILS on the pre-fix split-marker leak and the overflow-exits-paste leak.
import itertools                                    # noqa: E402
_FSM_S, _FSM_E, _FSM_CR, _FSM_X = b'\x1b[200~', b'\x1b[201~', b'\r', b'x'
_FSM_TOKENS = 6


def _fsm_feed(chunks):
    _out = b''
    _st = (False, b'', b'')
    for _c in chunks:
        _p, _st = cli.feed_stdin_paste(_c, _st)
        _out += _p
    return _out


def _fsm_typed_cr(seq):
    """Reference oracle: CRs OUTSIDE a complete bracketed-paste frame -- the only CRs allowed
    to reach the child."""
    n = 0
    i = 0
    inp = False
    while i < len(seq):
        if not inp and seq[i:i + 6] == _FSM_S:
            inp = True
            i += 6
        elif inp and seq[i:i + 6] == _FSM_E:
            inp = False
            i += 6
        else:
            if seq[i:i + 1] == _FSM_CR and not inp:
                n += 1
            i += 1
    return n


_fsm_bad = None
for _fsm_r in range(_FSM_TOKENS + 1):
    for _fsm_combo in itertools.product((_FSM_S, _FSM_E, _FSM_CR, _FSM_X), repeat=_fsm_r):
        _fsm_seq = b''.join(_fsm_combo)
        _fsm_whole = _fsm_feed([_fsm_seq]) if _fsm_seq else b''
        _fsm_splits = [[_fsm_seq[:_k], _fsm_seq[_k:]] for _k in range(1, len(_fsm_seq))]
        if _fsm_seq:
            _fsm_splits.append([bytes([_b]) for _b in _fsm_seq])   # the all-single-byte split
        for _fsm_sp in _fsm_splits:
            if _fsm_feed(_fsm_sp) != _fsm_whole:
                _fsm_bad = ('split-invariance', _fsm_seq, _fsm_sp)
                break
        if _fsm_bad is None and _fsm_whole.count(_FSM_CR) != _fsm_typed_cr(_fsm_seq):
            _fsm_bad = ('paste-CR-forwarded', _fsm_seq, _fsm_whole)
        if _fsm_bad:
            break
    if _fsm_bad:
        break
ok(_fsm_bad is None,
   'paste-FSM bounded-exhaustive: split-invariance + no paste-CR forwarded over every token '
   'sequence up to %d tokens and every split (%r)' % (_FSM_TOKENS, _fsm_bad))

# The OVERFLOW class needs a body past _PASTE_MAX; shrink the cap and verify that an over-cap
# paste never lets its tail reach the child as typed input, across every read-boundary split.
_fsm_ov_saved = cli._PASTE_MAX
cli._PASTE_MAX = 4
try:
    _fsm_ov_bad = None
    for _fsm_tail in (b'A' * 10 + b'echo pwned\r', b'echo pwned\r' + b'A' * 10):
        _fsm_s = _FSM_S + b'A' * 10 + _fsm_tail + _FSM_E + b'q\r'
        for _fsm_k in range(1, len(_fsm_s)):
            if b'pwned' in _fsm_feed([_fsm_s[:_fsm_k], _fsm_s[_fsm_k:]]):
                _fsm_ov_bad = _fsm_k
                break
        if _fsm_ov_bad:
            break
    ok(_fsm_ov_bad is None,
       'paste-FSM overflow: an over-cap paste tail never reaches the child as typed input')
finally:
    cli._PASTE_MAX = _fsm_ov_saved

if _failures:
    print('secure-terminal-tests(cli): %d passed, %d failed' % (_passed, _failures))
else:
    print('secure-terminal-tests(cli): all passed')
sys.exit(1 if _failures else 0)
