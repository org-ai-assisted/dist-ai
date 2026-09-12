#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression probe for fuzz_privleap._drive: a `raw` larger than the socket buffer
## must NOT deadlock. The server reads at most one capped frame and never drains a
## huge send, so an unbounded blocking sendall waits forever for buffer space that
## never frees (masked in normal fuzzing only by libFuzzer's max_len -- a raised
## max_len would hang the fuzzer). Drives the REAL shipped _drive (no copy): only
## the atheris FUZZING FRAMEWORK is shimmed (it drives the loop, it is not the code
## under test), while privleap and the socket handling are exercised for real.
## An os.alarm bounds the probe so a genuine deadlock is caught as a FAIL, not a hang.
## Env override FUZZ_PRIVLEAP selects the module (for canary runs). Used by
## test_fuzz_privleap_deadlock.sh.

import os
import signal
import sys
import types


class _NoOp:
    ## Callable AND a context manager, so both atheris.X(...) and
    ## `with atheris.instrument_imports():` (used at module import) are no-ops.
    def __call__(self, *args, **kwargs):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _AtherisShim(types.ModuleType):
    ## Any atheris.X resolves to a no-op: the harness's module-level / __main__ use
    ## of atheris must not fail the import, but _drive never touches atheris.
    def __getattr__(self, _name):
        return _NoOp()


sys.modules.setdefault("atheris", _AtherisShim("atheris"))

_here = os.path.dirname(os.path.realpath(__file__))
_module_path = os.environ.get("FUZZ_PRIVLEAP") or os.path.join(_here, "fuzz_privleap.py")
if not os.path.isfile(_module_path):
    print("FATAL: fuzz_privleap.py not found at %s (set FUZZ_PRIVLEAP)" % _module_path)
    sys.exit(1)

_ns = {"__name__": "fuzz_privleap_under_test", "__file__": _module_path}
try:
    with open(_module_path, encoding="utf-8") as _fh:
        exec(compile(_fh.read(), _module_path, "exec"), _ns)  # noqa: S102
except ModuleNotFoundError as _exc:
    ## A required module (privleap, pl_testlib) is absent: fail LOUDLY, never a
    ## silent skip -- privleap-tests requires the real package to be present.
    print("FATAL: fuzz_privleap import needs a missing module (%s)" % _exc)
    sys.exit(1)

_drive = _ns["_drive"]

## A payload comfortably larger than any default AF_UNIX SOCK_STREAM send buffer, so
## an unbounded sendall would block on it.
_BIG = b"A" * (8 * 1024 * 1024)


class _Deadline(Exception):
    ## NOT an OSError/ValueError/socket.timeout, so _drive's own except handlers
    ## cannot swallow it -- socket.timeout is an alias for TimeoutError (an OSError
    ## subclass) on Python 3.10+, so a TimeoutError alarm WOULD be caught by _drive's
    ## `except OSError` and mask the very deadlock this probe must observe.
    pass


def _deadline(_signum, _frame):
    raise _Deadline("_drive did not return -- deadlock on a >buffer payload")


signal.signal(signal.SIGALRM, _deadline)
signal.alarm(25)
try:
    ## A control session takes user_name=None, so the probe needs no real system user.
    _drive(_BIG, control=True)
    signal.alarm(0)
    print("PASS: _drive returned on a >buffer payload (no deadlock)")
except _Deadline as exc:
    print("FAIL: %s" % exc)
    sys.exit(1)
except Exception as exc:  # noqa: BLE001
    ## A parser finding / RuntimeError is a different outcome, not the deadlock this
    ## probe guards -- surface it rather than masking a hang as a pass.
    signal.alarm(0)
    print("FAIL: _drive raised %s: %s" % (type(exc).__name__, exc))
    sys.exit(1)
print("")
print("OK")
