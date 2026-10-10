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
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import msgcollector_testlib as T


_SUBJECT = T.run_check_script()

## Sourcing the subject also sources the REAL helper-scripts strings.bsh
## (HELPER_SCRIPTS_PATH, else installed), so output_func validates
## arg_max_bytes with the production is_whole_number. output_func_core is
## redefined after sourcing as a sink that records each chunk NUL-delimited (a
## bash argument never contains NUL).
_BODY = (
    "output_func_core() { printf '%s\\0' \"${@: -1}\"; }\n"
    'arg_max_bytes="$1"\n'
    'output_func --setting "$2"'
)


def _run(amb: int, message: str):
    """Drive output_func with arg_max_bytes=amb. Returns (rc, chunks) where
    chunks is a list of raw byte strings. LC_ALL=C so bash chunks by bytes."""
    proc = T.run_sourced(_SUBJECT, ('output_func', 'is_whole_number'),
                         _BODY, str(amb), message, text=False,
                         env={**os.environ, 'LC_ALL': 'C'})
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
