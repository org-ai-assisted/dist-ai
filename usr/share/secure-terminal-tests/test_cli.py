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
except Exception as exc:                                       # pragma: no cover
    sys.stderr.write('secure-terminal-tests: SKIP (cannot import '
                     'secure_terminal.cli: %s)\n' % exc)
    sys.exit(77)

os.environ['SHELL'] = '/bin/sh'          # deterministic default-shell path

_failures = 0


def ok(cond, msg):
    global _failures
    if cond:
        print('ok   %s' % msg)
    else:
        _failures += 1
        print('FAIL: %s' % msg)


def eq(got, want, msg):
    ok(got == want, '%s (got %r, want %r)' % (msg, got, want))


def _set_winsize(fd, rows, cols):
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
    except OSError:
        pass


def run_in_pty(argv, feed=b'', tty_stdin=True, settle=0.8, feed_delay=0.0,
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
                pass
        if close_stdin and not tty_stdin:
            try:
                os.close(in_w)                 # EOF on the wrapper's stdin
            except OSError:
                pass
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
                pass
        try:
            signal.signal(signal.SIGWINCH, prev_winch)
        except (OSError, ValueError, TypeError):
            pass
        for fd in (out_master, out_slave, in_r, in_w):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
    return b''.join(chunks), rc


# --- output is sanitized: escapes stripped, non-ASCII neutralised --------------
_out, _rc = run_in_pty(['--', 'printf',
                        'a\x1b[31mRED\x1b]0;title\x07b\xc2\xa0c'], winsize=(30, 100))
ok(b'\x1b' not in _out, 'CLI output carries no escape byte (ANSI/OSC stripped)')
ok(b'RED' in _out and b'title' not in _out,
   'the SGR colour text shows; the OSC title payload is stripped')
ok(b'\xc2\xa0' not in _out, 'a non-ASCII byte is neutralised (not passed through)')
eq(_rc, 0, 'a command that exits cleanly returns 0')

# --- display modes ------------------------------------------------------------
_o2, _ = run_in_pty(['--mode', 'reveal', '--', 'printf', 'x\u200by'])
ok(b'<U+200B>' in _o2, 'reveal mode shows the <U+XXXX> badge for a zero-width space')
_o3, _ = run_in_pty(['--mode', 'strip', '--', 'printf', 'x\u200by'])
ok(b'x_y' in _o3, 'strip mode maps the neutralised byte to _')

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

# --- stdin forwarding + EOF: a shell reads our keystrokes and exits ------------
_o5, _rc5 = run_in_pty([], feed=b'exit 3\n', settle=1.2, feed_delay=0.6)
eq(_rc5, 3, 'the default shell runs, reads forwarded input, and its exit propagates')

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

print('secure-terminal-tests(cli): %d passed, %d failed'
      % (0, _failures) if _failures else
      'secure-terminal-tests(cli): all passed')
sys.exit(1 if _failures else 0)
