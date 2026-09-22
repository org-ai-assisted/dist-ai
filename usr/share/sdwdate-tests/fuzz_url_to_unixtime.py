#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris coverage-guided harness for url_to_unixtime's HTTP Date header parser.

A hostile time server controls the Date header sdwdate parses. The parser must
reject any value cleanly (return, or sys.exit(2/4/6) == SystemExit), never
raise another exception -- an uncaught crash here is the time daemon dying on a
hostile server response. This harness asserts that invariant for arbitrary
inputs.

dateutil.parser.parse does the real parsing work, so it is imported under
atheris.instrument_imports() BEFORE the real url_to_unixtime script loads; the
script then reuses that already-instrumented dateutil from sys.modules, so the
parser is coverage-instrumented without reimplementing the subject.

Runs both in-process (sdwdate-tests-fuzz-atheris, SDWDATE_REPO) and as a
ClusterFuzzLite build (sdwdate bundled).
"""

import contextlib
import importlib.machinery
import importlib.util
import os
import sys
from typing import Any

## The subject prints multi-line rejection diagnostics on its sys.exit paths.
## libFuzzer calls TestOneInput millions of times, so that output must be
## silenced in the hot path or it floods the log and throttles fuzzing on I/O.
## A real finding surfaces through the propagated exception (streams restored by
## the context manager first), which atheris/libFuzzer reports itself.
_DEVNULL = open(os.devnull, 'w')  # noqa: SIM115 (lives for the fuzz process)

try:
    import atheris  # type: ignore

    _HAVE_ATHERIS: bool = True
except ImportError:
    _HAVE_ATHERIS = False


def _url_to_unixtime_path():
    ## A set-but-unresolved SDWDATE_REPO must not fall back to installed sdwdate.
    repo = os.environ.get('SDWDATE_REPO')
    if repo is not None:
        repo = repo.strip()
        if not repo:
            return None
        path = os.path.join(repo, 'usr', 'bin', 'url_to_unixtime')
        return path if os.path.exists(path) else None
    ## ClusterFuzzLite onefile: the run container has no sdwdate checkout, so
    ## build.sh bundles the REAL script as data under _MEIPASS/sdwdate_bin/ (see
    ## .clusterfuzzlite/build.sh in the sdwdate repo). Still the real subject,
    ## never a reimplementation.
    meipass = getattr(sys, '_MEIPASS', None)
    if meipass is not None:
        bundled = os.path.join(meipass, 'sdwdate_bin', 'url_to_unixtime')
        if os.path.exists(bundled):
            return bundled
    path = '/usr/bin/url_to_unixtime'
    return path if os.path.exists(path) else None


def _load_url_to_unixtime() -> Any:
    path = _url_to_unixtime_path()
    if path is None:
        return None
    try:
        if _HAVE_ATHERIS:
            ## Instrument the heavy parser first; url_to_unixtime picks up this
            ## cached, instrumented dateutil when it imports it.
            with atheris.instrument_imports():
                import dateutil.parser  # noqa: F401
                import requests  # noqa: F401
        loader = importlib.machinery.SourceFileLoader('url_to_unixtime', path)
        spec = importlib.util.spec_from_loader('url_to_unixtime', loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
    except ImportError:
        return None
    return module


u2u: Any = _load_url_to_unixtime()


class _FakeResponse:
    """Minimal stand-in for the requests.Response the parser reads."""

    def __init__(self, date_value):
        self.headers = {'Date': date_value}

    def __str__(self):
        return '<FakeResponse Date=%r>' % self.headers.get('Date')


def _reject_ok(call) -> None:
    ## A clean return or a controlled SystemExit is the parser accepting or
    ## rejecting input; anything else propagates so Atheris reports a crash. The
    ## subject's rejection prints are routed to devnull (see _DEVNULL above).
    try:
        with contextlib.redirect_stdout(_DEVNULL), \
                contextlib.redirect_stderr(_DEVNULL):
            call()
    except SystemExit:
        pass


def TestOneInput(data: bytes) -> None:  # noqa: N802 (Atheris contract name)
    fdp = atheris.FuzzedDataProvider(data)
    http_time = fdp.ConsumeUnicodeNoSurrogates(120)
    parsed = fdp.ConsumeUnicodeNoSurrogates(16)
    resp = _FakeResponse(http_time)
    _reject_ok(lambda: u2u.data_to_http_time(resp))
    _reject_ok(lambda: u2u.http_time_to_parsed_unixtime(resp, http_time))
    _reject_ok(lambda: u2u.unixtime_sanity_check(resp, http_time, parsed))


def main() -> None:
    if u2u is None:
        print(
            'SKIP: url_to_unixtime not found -- install sdwdate or set '
            'SDWDATE_REPO (needs python3-requests, python3-dateutil)',
            file=sys.stderr,
        )
        ## style-ok: allow-skip: sdwdate subject or its deps not available
        raise SystemExit(77)
    if not _HAVE_ATHERIS:
        print('SKIP: atheris is not installed (pip install atheris).')
        ## style-ok: allow-skip: atheris optional fuzzing dep not installed
        raise SystemExit(77)
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
