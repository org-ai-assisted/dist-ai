#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris coverage-guided harness for privleap's AUTHORIZATION engine -- the
decision that gates whether a requested action runs. An action runs an
arbitrary root-configured command, so an authorization bypass here is code
execution as root: the crown-jewel invariant.

It fuzzes the authorized-user / authorized-group NAME lists an admin's config
supplies, builds a REAL privleapd PrivleapAction from them (exercising
normalize_user_id / normalize_group_id against the live account database), and
runs the REAL privleapd.authorize_user for the fuzzer's own uid. It then asserts
the ANTI-ACE invariant directly: a non-root caller may be AUTHORIZED for a
restricted action ONLY when it is named in the action's resolved uid list or is
a member of one of the action's resolved groups. A grant without such a rule is
raised as a finding.

The coverage-guided counterpart to authorizer_test.py's randomized property
matrix. Runs both in-process (privleap-tests-fuzz-atheris) and as a
ClusterFuzzLite pyinstaller onefile -- see the import note in fuzz_privleap.py.
"""

import os
import pwd
import sys
from typing import Any

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
    """Import the privleap library; None ONLY when privleap itself is absent
    (a genuine "not configured" run, which main() maps to skip-vs-FATAL)."""
    ## A set-but-unresolved PRIVLEAP_REPO must not fall back to installed privleap.
    if os.environ.get("PRIVLEAP_REPO") is not None and _PARENT is None:
        return None
    try:
        if _HAVE_ATHERIS:
            with atheris.instrument_imports():
                from privleap import privleap as _pl  # noqa: E402
        else:
            from privleap import privleap as _pl  # noqa: E402
    except ImportError:
        return None
    return _pl


def _load_privleapd() -> Any:
    """Import privleapd (the daemon). A failure HERE while privleap itself is
    present is a BROKEN environment (e.g. python3-sdnotify missing), not a
    reason to skip -- let the ImportError propagate so it surfaces as a hard
    failure rather than a silent 77."""
    if _HAVE_ATHERIS:
        with atheris.instrument_imports():
            from privleap import privleapd as _d  # noqa: E402
    else:
        from privleap import privleapd as _d  # noqa: E402
    return _d


pl: Any = _load_privleap()
privleapd: Any = _load_privleapd() if pl is not None else None

## The fuzzer's own identity is the caller under test: it exists (so the
## decision is never a trivial USER_MISSING) and its real group membership is
## the ground truth the anti-ACE check compares against.
_UID: int = os.getuid()
_PW: pwd.struct_passwd | None
try:
    _PW = pwd.getpwuid(_UID)
    _GROUPS = set(os.getgrouplist(_PW.pw_name, _PW.pw_gid))
except (KeyError, OSError):
    _PW = None
    _GROUPS = set()


def TestOneInput(data: bytes) -> None:  # noqa: N802 (Atheris contract name)
    if _PW is None:
        return
    fdp = atheris.FuzzedDataProvider(data)
    n_users = fdp.ConsumeIntInRange(0, 4)
    users = [fdp.ConsumeUnicodeNoSurrogates(32) for _ in range(n_users)]
    n_groups = fdp.ConsumeIntInRange(0, 4)
    groups = [fdp.ConsumeUnicodeNoSurrogates(32) for _ in range(n_groups)]

    try:
        action = pl.PrivleapAction(
            action_name="fuzz-authz",
            action_command="echo hi",
            auth_user_ids=users or None,
            auth_group_ids=groups or None,
        )
    except ValueError:
        ## No auth lists at all, or an invalid action name: not an action the
        ## authorizer would ever see, so not an authorization finding.
        return

    status = privleapd.authorize_user(action, _UID)
    if (
        status is privleapd.PrivleapdAuthStatus.AUTHORIZED
        and _UID != 0
        and action.auth_restricted
    ):
        ## Anti-ACE: a grant to a non-root caller on a restricted action must be
        ## backed by a matching uid rule or a group the caller is really in.
        if _UID not in action.auth_uids and _GROUPS.isdisjoint(
            action.auth_gids
        ):
            raise RuntimeError(
                "anti-ACE violation: authorize_user granted uid %d with no "
                "matching rule; auth_uids=%r auth_gids=%r from users=%r "
                "groups=%r" % (_UID, action.auth_uids, action.auth_gids, users, groups)
            )


def main() -> None:
    if pl is None:
        _skip_not_found("privleap library")
    if not _HAVE_ATHERIS:
        print("SKIP: atheris is not installed (pip install atheris).")
        ## style-ok: allow-skip: atheris optional fuzzing dep not installed
        raise SystemExit(77)
    if _PW is None:
        ## Without a resolvable caller identity every input returns immediately
        ## and the anti-ACE oracle never runs. Skip loudly rather than report a
        ## no-op fuzz as a clean pass (a passwd-less numeric uid in a container).
        print(
            "SKIP: the fuzzer's own uid (%d) has no passwd entry; the "
            "authorization oracle needs a resolvable caller." % _UID
        )
        ## style-ok: allow-skip: no resolvable caller identity to fuzz against
        raise SystemExit(77)
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
