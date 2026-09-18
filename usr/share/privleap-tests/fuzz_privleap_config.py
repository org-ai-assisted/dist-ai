#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris coverage-guided harness for privleap's config-file CONTENT parser
(PrivleapCommon.parse_config_file). Config files live in root-owned conf.d
directories, so this is not an unprivileged-client surface, but a malformed
config must fail CLOSED -- return an error string -- rather than crash the
daemon on load or reload. This harness asserts the parser returns its declared
ConfigData tuple or an error string for any input, never raising: an uncaught
exception here is a daemon-startup / reload DoS.

parse_config_file first gates on the file's ownership/mode (a separate concern,
tested in config_test.py); this harness patches that gate open so the fuzzer
explores the line-by-line PARSER, and feeds the input as valid UTF-8 so the
target is the parser, not the file's text decode.

Runs both in-process (privleap-tests-fuzz-atheris, PRIVLEAP_REPO) and as a
ClusterFuzzLite pyinstaller onefile (privleap bundled) -- see the import note in
fuzz_privleap.py.
"""

import os
import sys
import tempfile
from typing import Any
from pathlib import Path

HERE: str = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# pylint: disable=wrong-import-position
from pl_testlib import _dist_packages_dir, _skip_not_found  # noqa: E402

_PARENT: str | None = _dist_packages_dir()
if _PARENT is not None and _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

try:
    import atheris  # type: ignore

    _HAVE_ATHERIS: bool = True
except ImportError:
    _HAVE_ATHERIS = False


def _load_privleap() -> Any:
    """Import privleap for both the onefile and in-process; see fuzz_privleap."""
    try:
        if _HAVE_ATHERIS:
            with atheris.instrument_imports():
                from privleap import privleap as _pl  # noqa: E402
        else:
            from privleap import privleap as _pl  # noqa: E402
    except ImportError:
        return None
    return _pl


pl: Any = _load_privleap()

if pl is not None:
    ## Focus the fuzzer on the content parser, not the ownership/mode gate.
    pl.PrivleapCommon.check_secure_file_permissions = staticmethod(
        lambda *args, **kwargs: True
    )


def TestOneInput(data: bytes) -> None:  # noqa: N802 (Atheris contract name)
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(2 ** 16)
    handle_fd, path = tempfile.mkstemp(suffix=".conf")
    try:
        with os.fdopen(handle_fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        result = pl.PrivleapCommon.parse_config_file(Path(path))
        ## Declared return type: a ConfigData tuple on success, or an error
        ## string. Anything else -- or an exception -- is a finding.
        if not isinstance(result, (tuple, str)):
            raise RuntimeError("parse_config_file returned %r" % (result,))
    finally:
        os.unlink(path)


def main() -> None:
    if pl is None:
        _skip_not_found("privleap library")
    if not _HAVE_ATHERIS:
        print("SKIP: atheris is not installed (pip install atheris).")
        ## style-ok: allow-skip: atheris optional fuzzing dep not installed
        raise SystemExit(77)
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
