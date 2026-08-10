#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Property tests for msgcollector's output_func chunking (msgdispatcher_run_check).

output_func splits a message into chunks no larger than arg_max_bytes, breaking
only at newlines, over attacker-influenceable content. Complements the randomized
in-process fuzzer (fuzz_output_chunking.py) with hypothesis' structured input
generation and shrinking. Same differential oracle: success is not predicted --
on rc 0 the chunks must reassemble and stay within the bound; on rc != 0 the
function must decline cleanly (rc 1), never crash or hang.

Measured and asserted in BYTES: arg_max_bytes is a byte budget (ARG_MAX), so the
driver runs under LC_ALL=C (bash counts and slices bytes, not multibyte
characters) and chunk sizes are the raw byte lengths -- a code-point count would
pass on multibyte input that overruns the byte budget.
"""

import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import msgcollector_testlib as T


def _run_check_script() -> str:
    return os.path.join(os.path.dirname(T.msgcollector_script()),
                        'msgdispatcher_run_check')


## Resolve the subject at import. Check the file exists FIRST: on an older
## checkout msgdispatcher_run_check may be absent, and letting
## extract_bash_function raise OSError at module level would crash pytest
## collection for the whole suite instead of skipping just this module.
_SUBJECT = _run_check_script()
if not os.path.isfile(_SUBJECT):
    pytest.skip('msgdispatcher_run_check not available', allow_module_level=True)
try:
    OUTPUT_FUNC = T.extract_bash_function(_SUBJECT, 'output_func')
except (LookupError, OSError, SystemExit):
    pytest.skip('output_func not available', allow_module_level=True)

## Stub is_whole_number (from strings.bsh) and output_func_core: the latter
## records each chunk NUL-delimited (a bash argument never contains NUL).
_DRIVER = (
    "is_whole_number() { case \"$1\" in ''|*[!0-9]*) return 1 ;; "
    "*) return 0 ;; esac; }\n"
    "output_func_core() { printf '%s\\0' \"${@: -1}\"; }\n"
)


def _run(amb: int, message: str):
    """Drive output_func with arg_max_bytes=amb. Returns (rc, chunks) where
    chunks is a list of raw byte strings. LC_ALL=C so bash chunks by bytes."""
    script = (_DRIVER + f"arg_max_bytes={amb}\n" + OUTPUT_FUNC
              + '\noutput_func --setting "$1"\n')
    proc = subprocess.run(
        ['bash', '-c', script, 'bash', message],
        capture_output=True, timeout=5, env={**os.environ, 'LC_ALL': 'C'})
    ## Chunks are NUL-terminated; the trailing element after the last NUL is
    ## empty and dropped. A message byte is never NUL (bash args are C strings).
    return proc.returncode, proc.stdout.split(b'\0')[:-1]


def _assert_oracle(amb: int, message: str) -> None:
    rc, chunks = _run(amb, message)
    if rc == 0:
        for idx, chunk in enumerate(chunks):
            assert len(chunk) <= amb, \
                f"chunk {idx} is {len(chunk)} bytes > arg_max_bytes {amb}"
        ## Breaks drop exactly the boundary newline, and the final-chunk handling
        ## drops one trailing newline if present; nothing else is lost.
        expected = message.encode('utf-8', 'surrogateescape')
        if expected.endswith(b'\n'):
            expected = expected[:-1]
        assert b'\n'.join(chunks) == expected, 'chunks do not reassemble'
    else:
        assert rc == 1, f"unexpected non-clean failure exit {rc}"


## ---------------------------------------------------------------------------
## Concrete examples (always run, no hypothesis needed).
## ---------------------------------------------------------------------------

def test_chunking_reassembles_multiline() -> None:
    rc, chunks = _run(8, 'abc\ndef\nghi')
    assert rc == 0
    assert b'\n'.join(chunks) == b'abc\ndef\nghi'
    assert all(len(c) <= 8 for c in chunks)


def test_overlong_line_declines_cleanly() -> None:
    ## A single newline-free segment longer than arg_max_bytes cannot be broken.
    rc, _chunks = _run(8, 'a' * 20)
    assert rc == 1


def test_trailing_newline_dropped() -> None:
    rc, chunks = _run(8, 'abc\n')
    assert rc == 0
    assert b'\n'.join(chunks) == b'abc'


def test_multibyte_chunk_stays_within_byte_budget() -> None:
    ## Each 'e-acute' (U+00E9) is two UTF-8 bytes; a code-point count would
    ## wrongly accept an over-budget chunk. Under LC_ALL=C output_func breaks by
    ## bytes. chr(0xe9) keeps the source ASCII.
    message = chr(0xe9) * 3 + chr(10) + chr(0xe9) * 2
    rc, chunks = _run(8, message)
    assert rc == 0
    assert all(len(c) <= 8 for c in chunks)
    assert b'\n'.join(chunks) == message.encode('utf-8')


## ---------------------------------------------------------------------------
## Property-based invariants (needs python3-hypothesis). Skipped cleanly when
## hypothesis is absent, so a plain 'pytest' still runs the concrete examples.
## ---------------------------------------------------------------------------

try:
    from hypothesis import given, settings, strategies as st
    _HAVE_HYPOTHESIS = True
except ImportError:  # pragma: no cover
    _HAVE_HYPOTHESIS = False

if _HAVE_HYPOTHESIS:
    ## Arbitrary text including the newline (the break character) and control /
    ## non-ASCII bytes. Exclude NUL and lone surrogates: a bash argument cannot
    ## carry them, so generating them only errors in subprocess. max_size is
    ## bounded so the chunk count stays under output_func's max_loop_count (100)
    ## even at the smallest arg_max_bytes.
    _MESSAGE = st.text(
        alphabet=st.characters(min_codepoint=1, exclude_categories=('Cs',)),
        min_size=1, max_size=60)
    _AMB = st.sampled_from([8, 16, 32])

    @settings(max_examples=400, deadline=None)
    @given(_AMB, _MESSAGE)
    def test_chunking_invariants(amb: int, message: str) -> None:
        _assert_oracle(amb, message)
