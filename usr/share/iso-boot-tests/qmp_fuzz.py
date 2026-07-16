#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Fuzz the QMP handling code in iso_boot_lib.QMPClient.

QMP is line-delimited JSON read off a socket. A hostile or wedged qemu (or anything else bound
to the socket) could send non-JSON, JSON that is not an object, a non-dict 'data', a huge line
with no newline, or a deeply nested payload. This fuzzer hammers the three parsing surfaces with
adversarial input and asserts the client NEVER raises anything other than the intended QMPError
and never hangs -- it must degrade to a clean failure:

  1. QMPClient._parse_line(str)   -> a dict, or QMPError; never a bare JSONDecodeError etc.
  2. QMPClient._record_event(dict)-> never raises, even when 'data' is not an object.
  3. execute()/wait_for_shutdown() over a fake finite stream of adversarial lines -> a dict or
     None; never a crash, never an unbounded read (the finite stream also proves no hang).

Run: qmp_fuzz.py [--iterations N] [--seed N]. No root, no network, no real qemu.
"""

import argparse
import io
import json
import os
import sys

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from iso_boot_lib import QMPClient, QMPError  # noqa: E402


## JSON values of any shape (objects, arrays, scalars, nested) rendered to a line, mixed with
## arbitrary text and bytes-decoded noise -- so the parser sees both valid-JSON-non-object and
## outright garbage.
_json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=True, allow_infinity=True)
    | st.text(),
    lambda children: st.lists(children) | st.dictionaries(st.text(), children),
    max_leaves=25,
)
_lines = st.one_of(
    st.text(),
    _json_values.map(lambda v: json.dumps(v)),
    st.binary().map(lambda b: b.decode("utf-8", "replace")),
)
## Arbitrary JSON objects to stand in for parsed QMP events.
_objects = st.dictionaries(st.text(), _json_values, max_size=8)


class _DummySock:
    """Stand-in for the QMP socket: swallow sends and timeout changes so execute() can run
    against a fake in-memory line stream with no real I/O."""

    def sendall(self, _data):
        pass

    def settimeout(self, _timeout):
        pass


def _client_over(text):
    """A QMPClient whose reads come from a finite in-memory stream (so no hang is possible)."""
    client = QMPClient("/nonexistent.sock")
    client._sock = _DummySock()
    client._rfile = io.StringIO(text)
    return client


@given(_lines)
def parse_line_never_leaks(line):
    try:
        result = QMPClient._parse_line(line)
    except QMPError:
        return  ## the ONE acceptable exception
    assert isinstance(result, dict), "parse_line returned a non-dict without raising QMPError"


@given(_objects)
def record_event_never_raises(event):
    client = QMPClient("/nonexistent.sock")
    ## _record_event must tolerate any object shape (missing/non-dict 'data', odd 'event').
    client._record_event(event)


@given(st.lists(_lines, max_size=40))
def read_stream_never_crashes(lines):
    stream = "".join(line.replace("\n", " ") + "\n" for line in lines)
    ## execute(): reads until a non-event reply, EOF, or a malformed line -> dict or None.
    result = _client_over(stream).execute("query-status", timeout=1)
    assert result is None or isinstance(result, dict)
    ## wait_for_shutdown(): consumes events until SHUTDOWN/EOF/garbage -> reason string or None.
    reason = _client_over(stream).wait_for_shutdown(timeout=1)
    assert reason is None or isinstance(reason, str)


_FUZZERS = (parse_line_never_leaks, record_event_never_raises, read_stream_never_crashes)


def main():
    parser = argparse.ArgumentParser(description="Fuzz the QMP parser in iso_boot_lib.")
    parser.add_argument("--iterations", type=int, default=500,
                        help="hypothesis examples per fuzzer (default 500)")
    parser.add_argument("--seed", type=int, default=None, help="derandomize with a fixed seed")
    args = parser.parse_args()

    profile = settings(
        max_examples=args.iterations,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
        derandomize=args.seed is not None,
    )
    failed = 0
    for fuzzer in _FUZZERS:
        print("fuzzing: %s (%d examples)" % (fuzzer.__name__, args.iterations), flush=True)
        try:
            profile(fuzzer)()
        except AssertionError as exc:
            print("  FAIL: %s: %s" % (fuzzer.__name__, exc), flush=True)
            failed += 1
        except Exception as exc:  # noqa: BLE001 -- a leaked non-QMPError IS the bug we hunt
            print("  FAIL (unexpected %s): %s: %s"
                  % (type(exc).__name__, fuzzer.__name__, exc), flush=True)
            failed += 1
        else:
            print("  PASS: %s" % fuzzer.__name__, flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
