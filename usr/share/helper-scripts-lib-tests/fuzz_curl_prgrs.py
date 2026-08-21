#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris (libFuzzer) coverage-guided fuzz harness for curl-prgrs' pure decision
functions.

curl-prgrs is a bash script and Atheris instruments PYTHON, not bash, so this
harness fuzzes a Python PORT of the three pure, parser-like functions. The port
is NOT an independent oracle: its faithfulness to the bash is enforced by the
sibling suite curl_prgrs_test.sh, which drives the REAL bash functions over the
SAME invariants plus a randomized differential (curl_prgrs_fuzz.sh). Treat that
bash property fuzz as the no-dependency, real-code counterpart; this harness
adds Atheris' structured input generation and coverage-guided exploration.

Invariants (a violation raises, which Atheris reports as a finding):
  - compute_percent, given contract inputs (non-negative whole numbers), always
    returns an int in 0..100 -- never a crash, never out of range.
  - classify_download_size returns exactly one of {0, 81, 113, 114}.
  - remove_argument_for_header_request only ever removes elements (its output is
    a subsequence of its input) and never invents or reorders an argument.

Run via the dist-ai entrypoint (60s default budget):
    helper-scripts-lib-tests-fuzz-atheris
    helper-scripts-lib-tests-fuzz-atheris -max_total_time=600
Or directly (needs `pip install atheris`):
    python3 -m atheris fuzz_curl_prgrs.py -max_total_time=300
Without Atheris the harness reports a clean SKIP (exit 77); use
curl_prgrs_fuzz.sh (driven by curl_prgrs_test.sh) for a no-dependency run.
"""

import os
import re
import sys


def _subject() -> str | None:
    """The curl-prgrs the ported logic mirrors. Present it as the fuzz subject so
    the suite SKIPs (not fails) when helper-scripts is absent, matching the rest
    of the dist-ai suites."""
    repo = os.environ.get("HELPER_SCRIPTS_REPO")
    base = os.path.join(repo, "usr/libexec/helper-scripts") if repo else "/usr/libexec/helper-scripts"
    candidate = os.path.join(base, "curl-prgrs")
    return candidate if os.path.isfile(candidate) else None


_SUBJECT: str | None = _subject()

try:
    import atheris  # type: ignore

    _HAVE_ATHERIS: bool = True
except ImportError:
    _HAVE_ATHERIS = False


## is_whole_number from helper-scripts strings.bsh: ^(0|[1-9][0-9]*)$ -- a
## non-negative decimal with no leading zero (except "0" itself).
_WHOLE_NUMBER = re.compile(r"(?:0|[1-9][0-9]*)\Z")


def is_whole_number(value: str) -> bool:
    return _WHOLE_NUMBER.match(value) is not None


def compute_percent(bytes_str: str, length_str: str) -> int:
    """Port of curl-prgrs compute_percent. Contract: already-validated
    non-negative whole numbers. A length of 0 maps to 100 (nothing to fetch)
    rather than dividing by zero."""
    length = int(length_str)
    downloaded = int(bytes_str)
    if length <= 0:
        return 100
    percent = downloaded * 100 // length
    if percent >= 100:
        percent = 100
    return percent


def classify_download_size(downloaded: str, max_bytes: str, content_length: str) -> int:
    """Port of curl-prgrs classify_download_size. 'downloaded' may be any
    string (it stands in for a 'stat' reading); the ceilings are whole numbers."""
    if not is_whole_number(downloaded):
        return 113
    downloaded_int = int(downloaded)
    if downloaded_int > int(max_bytes):
        return 81
    if downloaded_int > int(content_length):
        return 114
    return 0


_STRIP_FLAGS = ("--continue-at", "-C", "--output", "-o")


def remove_argument_for_header_request(args):
    """Port of curl-prgrs remove_argument_for_header_request: drop each
    output/resume flag together with the value that follows it."""
    out = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in _STRIP_FLAGS:
            skip_next = True
            continue
        out.append(arg)
    return out


def _is_subsequence(sub, whole) -> bool:
    it = iter(whole)
    return all(item in it for item in sub)


## Instrument the ported decision functions so libFuzzer gets coverage feedback
## through their branches (atheris.instrument_imports only covers IMPORTED
## modules; these are defined here). Guarded so the module still imports for the
## clean SKIP when Atheris is absent.
if _HAVE_ATHERIS:
    is_whole_number = atheris.instrument_func(is_whole_number)
    compute_percent = atheris.instrument_func(compute_percent)
    classify_download_size = atheris.instrument_func(classify_download_size)
    remove_argument_for_header_request = atheris.instrument_func(
        remove_argument_for_header_request
    )


## curl-prgrs bounds an advertised Content-Length to 16 digits and derives every
## other size from it or a sane caller cap, so the real functions only ever see
## values in Bash's signed-64-bit-safe range. Fuzzing beyond that would compare a
## Python bignum against Bash's overflow (e.g. compute_percent(2**63-1, 1) is 100
## in Python but -100 after Bash wraps) -- a divergence outside the production
## domain, not a real defect. Stay within the same 16-digit bound.
_MAX_SIZE = 10 ** 16 - 1


def _check_one(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    ## compute_percent: contract inputs are non-negative whole numbers.
    downloaded = fdp.ConsumeIntInRange(0, _MAX_SIZE)
    length = fdp.ConsumeIntInRange(0, _MAX_SIZE)
    percent = compute_percent(str(downloaded), str(length))
    if not (isinstance(percent, int) and 0 <= percent <= 100):
        raise RuntimeError(
            f"compute_percent out of range: bytes={downloaded} length={length} -> {percent}"
        )

    ## classify_download_size: 'downloaded' may be arbitrary text; ceilings are
    ## whole numbers.
    if fdp.ConsumeBool():
        size = str(fdp.ConsumeIntInRange(0, _MAX_SIZE))
    else:
        size = fdp.ConsumeUnicodeNoSurrogates(32)
    max_bytes = fdp.ConsumeIntInRange(0, _MAX_SIZE)
    content_length = fdp.ConsumeIntInRange(0, _MAX_SIZE)
    verdict = classify_download_size(size, str(max_bytes), str(content_length))
    if verdict not in (0, 81, 113, 114):
        raise RuntimeError(
            f"classify_download_size bad verdict: size={size!r} max={max_bytes} "
            f"cl={content_length} -> {verdict}"
        )

    ## remove_argument_for_header_request: output must be a subsequence of input.
    count = fdp.ConsumeIntInRange(0, 12)
    args = [fdp.ConsumeUnicodeNoSurrogates(16) for _ in range(count)]
    stripped = remove_argument_for_header_request(args)
    if not _is_subsequence(stripped, args):
        raise RuntimeError(
            f"remove_argument_for_header_request not a subsequence: "
            f"in={args!r} out={stripped!r}"
        )


def TestOneInput(data: bytes) -> None:  # noqa: N802 (Atheris contract name)
    _check_one(data)


def main() -> None:
    if _SUBJECT is None:
        print("SKIP: curl-prgrs not found.")
        print("      set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install it.")
        raise SystemExit(77)
    if not _HAVE_ATHERIS:
        print("SKIP: atheris is not installed (pip install atheris).")
        print("      this is the coverage-guided harness; for a no-dependency real-bash")
        print("      run use curl_prgrs_fuzz.sh (driven by curl_prgrs_test.sh).")
        raise SystemExit(77)
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
