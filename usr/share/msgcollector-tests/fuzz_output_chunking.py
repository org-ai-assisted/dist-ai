#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Randomized in-process fuzzer for msgcollector's output_func chunking.

msgdispatcher_run_check's output_func() splits a message into chunks no larger
than arg_max_bytes, breaking only at newline boundaries, before handing each
chunk to the msgcollector CLI. It runs over attacker-influenceable content
(systemcheck feeds it journal lines, Tor control output, package names, ...), so
a crafted message must never make it hang, crash, lose or reorder data, or emit
an over-sized argument.

The function is extracted and driven in isolation with a stub output_func_core
that records each chunk (NUL-delimited, so a chunk may contain any byte but NUL,
which a bash argument cannot carry anyway).

Differential oracle. Exactly which inputs output_func can chunk is subtle (an
empty line can consume the byte a break needs, so the effective per-line bound is
not simply arg_max_bytes-1), so we do NOT predict success. Instead, per fuzzed
message:

  * TERMINATES within a timeout          -- the loop-guard bug we fear most
  * WHEN it succeeds (rc 0):
      - every chunk is <= arg_max_bytes  -- the whole point of chunking
      - chunks reassemble to the input   -- '\\n'.join(chunks) == message
                                            (breaks drop exactly the boundary
                                            newline; no other data is lost)
  * WHEN it declines (rc != 0):
      - it declines CLEANLY (rc 1, the documented "cannot break" / loop-guard
        path), never a crash, an unbound-variable abort, or a silent truncation

A chunking bug that keeps rc 0 while dropping or duplicating bytes is caught by
the reassembly check; a hang by the timeout; a crash by the clean-decline check.

Run: fuzz_output_chunking.py [--iterations N] [--seed N]. On failure it prints
the seed and the offending (arg_max_bytes, message) so the case replays
deterministically.
"""

import argparse
import os
import random
import subprocess
import sys

import msgcollector_testlib as T

## Line content: printable ASCII minus newline (which delimits lines) and NUL
## (the chunk delimiter). A few shell-significant bytes are included so argument
## passing through the driver is exercised too.
_SAFE_CHARS = [
    chr(c) for c in range(0x20, 0x7F)
] + ['\t']


def run_check_script() -> str:
    """Absolute path of msgdispatcher_run_check, a sibling of the msgcollector
    script under test."""
    return os.path.join(os.path.dirname(T.msgcollector_script()),
                        'msgdispatcher_run_check')


def gen_case(rng: random.Random):
    """Return (arg_max_bytes, message).

    Two shapes, both interesting: a single over-long newline-free segment (forces
    the "cannot break" path), and a run of lines each <= arg_max_bytes-1 with
    internal empty lines (mostly chunkable, and near the break boundary). The
    oracle does not assume which one succeeds -- see the module docstring."""
    amb = rng.choice([8, 16, 32, 64])
    ## Occasionally: one segment longer than arg_max_bytes with no newline at
    ## all -- output_func cannot break it.
    if rng.random() < 0.15:
        length = amb + rng.randint(1, 40)
        return amb, ''.join(rng.choice(_SAFE_CHARS) for _ in range(length))
    ## Lines each <= arg_max_bytes-1; line count well under output_func's
    ## max_loop_count (100). The LAST line is non-empty so the message never ends
    ## in a newline (a trailing newline is dropped by the final-chunk handling,
    ## which would make an rc-0 reassembly check inexact). Internal empty lines
    ## are exercised deliberately -- they are the subtle break-boundary case.
    n_lines = rng.randint(1, 40)
    lines = []
    for idx in range(n_lines):
        low = 1 if idx == n_lines - 1 else 0
        length = rng.randint(low, amb - 1)
        lines.append(''.join(rng.choice(_SAFE_CHARS) for _ in range(length)))
    return amb, '\n'.join(lines)


## Populated by main() with the REAL is_whole_number extracted from the current
## helper-scripts strings.bsh (a reimplementation drifts -- the real one rejects
## leading zeros). output_func_core is a sink stub recording each chunk
## NUL-delimited (a bash argument never contains NUL).
_DRIVER_HEAD = ''


def run(func_def: str, amb: int, message: str, timeout: float = 5.0):
    """Drive output_func on `message` with arg_max_bytes=amb. Returns
    (rc, chunks). Raises subprocess.TimeoutExpired on a hang."""
    script = (
        _DRIVER_HEAD
        + f'arg_max_bytes={amb}\n'
        + func_def
        + '\noutput_func --setting "$1"\n'
    )
    proc = subprocess.run(
        ['bash', '-c', script, 'bash', message],
        capture_output=True, timeout=timeout)
    ## Chunks are NUL-terminated; the trailing element after the last NUL is
    ## empty and dropped. A message byte is never NUL (bash args are C strings).
    raw = proc.stdout.split(b'\0')
    chunks = [c.decode('utf-8', 'surrogateescape') for c in raw[:-1]]
    return proc.returncode, chunks


def check(func_def: str, amb: int, message: str) -> None:
    """Raise AssertionError (or let TimeoutExpired propagate) on a violation."""
    rc, chunks = run(func_def, amb, message)
    if rc == 0:
        for idx, chunk in enumerate(chunks):
            assert len(chunk) <= amb, (
                f"chunk {idx} is {len(chunk)} bytes > arg_max_bytes {amb}")
        assert '\n'.join(chunks) == message, \
            'chunks do not reassemble to the input'
    else:
        ## Declined: must be the clean documented failure, not a crash or an
        ## unbound-variable abort (which would exit with a different code).
        assert rc == 1, f"unexpected non-clean failure exit {rc}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--iterations', type=int, default=3000)
    parser.add_argument('--seed', type=int, default=None)
    args = parser.parse_args()

    seed = args.seed if args.seed is not None else random.randrange(2**32)
    rng = random.Random(seed)
    print(f"fuzz_output_chunking: seed={seed} iterations={args.iterations}",
          file=sys.stderr)

    subject = run_check_script()
    if not os.path.isfile(subject):
        print(f"SKIP: msgdispatcher_run_check not found at {subject!r}",
              file=sys.stderr)
        return 77
    try:
        func_def = T.extract_bash_function(subject, 'output_func')
    except LookupError as exc:
        print(f"SKIP: {exc}", file=sys.stderr)
        return 77

    strings_bsh = (os.environ.get('HELPER_SCRIPTS_PATH', '')
                   + '/usr/libexec/helper-scripts/strings.bsh')
    try:
        is_whole_number = T.extract_bash_function(strings_bsh, 'is_whole_number')
    except (LookupError, OSError) as exc:
        print(f"SKIP: {exc}", file=sys.stderr)
        return 77
    global _DRIVER_HEAD
    _DRIVER_HEAD = (is_whole_number
                    + "\noutput_func_core() { printf '%s\\0' \"${@: -1}\"; }\n")

    for i in range(args.iterations):
        amb, message = gen_case(rng)
        try:
            check(func_def, amb, message)
        except subprocess.TimeoutExpired:
            print(f"FAIL (hang): seed={seed} i={i} amb={amb} "
                  f"message={message!r}", file=sys.stderr)
            return 1
        except AssertionError as exc:
            print(f"FAIL: {exc}: seed={seed} i={i} amb={amb} "
                  f"message={message!r}", file=sys.stderr)
            return 1
    print('ok', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
