#!/usr/bin/env python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
In-process property test / fuzzer for privleap's AUTHORIZATION engine -- the
decision that gates whether a requested action runs. Because a privleap
action runs an arbitrary root-configured command, an authorization bypass
here is arbitrary code execution as root (or as the action's target user).
This harness therefore treats the authorizer as the crown-jewel surface.

It drives the REAL privleapd.authorize_user / auth_signal_request /
is_user_allowed against PrivleapAction objects built from the system's
actual account database, and checks, over a large randomized matrix:

  Equivalence: authorize_user agrees with an independently written reference
  model of the documented rule (root always allowed; an unrestricted action
  allowed; otherwise allowed iff the calling user is a named authorized user
  or is a member of a named authorized group; a missing user is reported as
  such).

  Security properties (stated in terms of intent, not the implementation):
    P1  No grant without a matching rule: a non-root user who is neither a
        named authorized user nor in any authorized group of a restricted
        action is NEVER authorized.  (the anti-ACE invariant)
    P2  Root is always authorized.
    P3  An unrestricted action is authorized for any existing user.
    P4  Group grants are honoured: a user in a named authorized group is
        authorized.
    P5  Robustness: nonexistent authorized users/groups are skipped, not
        fatal; a nonexistent caller yields USER_MISSING, not a crash.

  Oracle hardening: auth_signal_request returns None both for an action that
  does not exist and for one the user may not run -- the two are
  indistinguishable to the caller (no action-enumeration oracle).

No root, no network, no live privleapd.
"""

# pylint: disable=too-many-locals,too-many-branches,too-many-statements

import argparse
import grp
import logging
import os
import pwd
import random
import sys
from types import ModuleType
from typing import Any

HERE: str = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# pylint: disable=wrong-import-position
from pl_testlib import Results, import_privleap, import_privleapd  # noqa: E402

pl: ModuleType = import_privleap()
d: ModuleType = import_privleapd()

## privleapd logs expected WARNING lines for the denied/unknown actions this
## test deliberately provokes; they are not assertions, so quiet them.
logging.disable(logging.WARNING)


# ---------------------------------------------------------------------------
# System account helpers.
# ---------------------------------------------------------------------------


def real_usernames() -> list[str]:
    return [p.pw_name for p in pwd.getpwall()]


def real_groupnames() -> list[str]:
    return [g.gr_name for g in grp.getgrall()]


def user_group_names(user: str) -> set[str]:
    """The set of group names a user currently belongs to (primary + extra)."""

    info: pwd.struct_passwd = pwd.getpwnam(user)
    return {
        grp.getgrgid(gid).gr_name
        for gid in os.getgrouplist(user, info.pw_gid)
    }


def make_action(
    auth_users: list[str] | None,
    auth_groups: list[str] | None,
    target_user: str | None = None,
    target_group: str | None = None,
) -> Any:
    """Build a real PrivleapAction with a harmless command."""

    return pl.PrivleapAction(
        action_name="test-act",
        action_command="echo authorized",
        auth_users=auth_users,
        auth_groups=auth_groups,
        target_user=target_user,
        target_group=target_group,
    )


# ---------------------------------------------------------------------------
# Independent reference model of the documented authorization rule.
# ---------------------------------------------------------------------------


def ref_authorize(action: Any, user: str) -> Any:
    """
    Reference decision, written from the spec rather than copied from the
    implementation. Reads the action's already-normalized authorized lists
    (normalization is exercised separately) and applies the rule directly.
    """

    status = d.PrivleapdAuthStatus
    try:
        info: pwd.struct_passwd = pwd.getpwnam(user)
    except KeyError:
        return status.USER_MISSING
    if info.pw_uid == 0:
        return status.AUTHORIZED
    if not action.auth_restricted:
        return status.AUTHORIZED
    if user in action.auth_users:
        return status.AUTHORIZED
    if user_group_names(user) & set(action.auth_groups):
        return status.AUTHORIZED
    return status.UNAUTHORIZED


# ---------------------------------------------------------------------------
# Phases.
# ---------------------------------------------------------------------------


def phase_named_properties(results: Results) -> None:
    """Deterministic, human-named checks of P1-P5 against concrete accounts."""

    print("== named security properties (P1-P5) ==")
    status = d.PrivleapdAuthStatus
    users: list[str] = real_usernames()

    ## A non-root target user that actually exists.
    target: str | None = None
    for candidate in (os.environ.get("SUDO_USER") or "", "user"):
        if candidate in users and pwd.getpwnam(candidate).pw_uid != 0:
            target = candidate
            break
    if target is None:
        for name in users:
            if pwd.getpwnam(name).pw_uid not in (0,):
                target = name
                break
    assert target is not None
    target_groups: set[str] = user_group_names(target)
    all_groups: list[str] = real_groupnames()
    in_group: str | None = next(iter(target_groups), None)
    out_group: str | None = next(
        (g for g in all_groups if g not in target_groups), None
    )

    ## P2: root always authorized, even for a tightly restricted action.
    act_root_only: Any = make_action(["root"], None)
    results.expect_eq(
        "P2 root authorized for root-only action",
        d.authorize_user(act_root_only, "root"),
        status.AUTHORIZED,
    )

    ## P1: a non-root user not named and not in any authorized group is denied.
    results.expect_eq(
        f"P1 '{target}' denied by root-only action",
        d.authorize_user(act_root_only, target),
        status.UNAUTHORIZED,
    )
    if out_group is not None:
        act_outgroup: Any = make_action(None, [out_group])
        results.expect_eq(
            f"P1 '{target}' denied by group '{out_group}' they lack",
            d.authorize_user(act_outgroup, target),
            status.UNAUTHORIZED,
        )

    ## P3: an unrestricted action authorizes any existing user. An action
    ## built normally is always restricted, so construct a bare object to
    ## exercise the unrestricted branch the code still contains.
    bare: Any = pl.PrivleapAction.__new__(pl.PrivleapAction)
    bare.action_name = "unrestricted"
    bare.action_command = "echo x"
    bare.auth_users = []
    bare.auth_groups = []
    bare.target_user = None
    bare.target_group = None
    bare.auth_restricted = False
    results.expect_eq(
        f"P3 unrestricted action authorizes '{target}'",
        d.authorize_user(bare, target),
        status.AUTHORIZED,
    )

    ## P4: a user in a named authorized group is authorized.
    if in_group is not None:
        act_ingroup: Any = make_action(None, [in_group])
        results.expect_eq(
            f"P4 '{target}' authorized via group '{in_group}'",
            d.authorize_user(act_ingroup, target),
            status.AUTHORIZED,
        )
    ## P4b: a user named directly is authorized.
    act_named: Any = make_action([target], None)
    results.expect_eq(
        f"P4b '{target}' authorized when named directly",
        d.authorize_user(act_named, target),
        status.AUTHORIZED,
    )

    ## P5: nonexistent authorized names are skipped (not fatal); a nonexistent
    ## caller is reported missing rather than crashing.
    act_with_ghost: Any = make_action(
        ["definitely-no-such-user-zzz", target], ["no-such-group-zzz"]
    )
    results.expect_eq(
        "P5 nonexistent authorized user skipped, real one still works",
        d.authorize_user(act_with_ghost, target),
        status.AUTHORIZED,
    )
    results.expect_eq(
        "P5 nonexistent caller -> USER_MISSING",
        d.authorize_user(act_root_only, "definitely-no-such-user-zzz"),
        status.USER_MISSING,
    )


def phase_oracle_hardening(results: Results) -> None:
    """auth_signal_request must not let a caller distinguish 'no such action'
    from 'not allowed': both return None."""

    print("== oracle hardening: unknown action vs forbidden action ==")
    status_users: list[str] = real_usernames()
    target: str = "user" if "user" in status_users else status_users[-1]

    act: Any = make_action(["root"], None)  # only root may run it
    act.action_name = "secret-action"
    saved: list[Any] = d.PrivleapdGlobal.action_list
    try:
        d.PrivleapdGlobal.action_list = [act]
        forbidden: Any = d.auth_signal_request(
            "test", "secret-action", target
        )
        unknown: Any = d.auth_signal_request("test", "no-such-action", target)
        results.check(
            "forbidden existing action returns None", forbidden is None
        )
        results.check(
            "unknown action returns None (indistinguishable)", unknown is None
        )
        ## And an authorized caller does get the action object back.
        allowed: Any = d.auth_signal_request("test", "secret-action", "root")
        results.check(
            "authorized caller receives the action", allowed is act
        )
    finally:
        d.PrivleapdGlobal.action_list = saved


def phase_is_user_allowed(results: Results) -> None:
    """is_user_allowed honours the configured allowed user/group lists."""

    print("== is_user_allowed: allow-list and group membership ==")
    users: list[str] = real_usernames()
    target: str = "user" if "user" in users else users[-1]
    target_groups: set[str] = user_group_names(target)
    out_group: str | None = next(
        (g for g in real_groupnames() if g not in target_groups), None
    )
    in_group: str | None = next(iter(target_groups), None)

    saved_u: list[str] = d.PrivleapdGlobal.allowed_user_list
    saved_g: list[str] = d.PrivleapdGlobal.allowed_group_list
    try:
        d.PrivleapdGlobal.allowed_user_list = []
        d.PrivleapdGlobal.allowed_group_list = []
        results.check(
            "empty allow-lists deny target", not d.is_user_allowed(target)
        )
        d.PrivleapdGlobal.allowed_user_list = [target]
        results.check(
            "named user is allowed", d.is_user_allowed(target)
        )
        d.PrivleapdGlobal.allowed_user_list = []
        if in_group is not None:
            d.PrivleapdGlobal.allowed_group_list = [in_group]
            results.check(
                f"user in allowed group '{in_group}' is allowed",
                d.is_user_allowed(target),
            )
        if out_group is not None:
            d.PrivleapdGlobal.allowed_group_list = [out_group]
            results.check(
                f"user not in group '{out_group}' is denied",
                not d.is_user_allowed(target),
            )
        ## A configured allowed group that no longer exists must not crash.
        d.PrivleapdGlobal.allowed_group_list = ["no-such-group-zzz"]
        results.check(
            "vanished allowed group handled gracefully",
            not d.is_user_allowed(target),
        )
    finally:
        d.PrivleapdGlobal.allowed_user_list = saved_u
        d.PrivleapdGlobal.allowed_group_list = saved_g


def phase_random_equivalence(
    results: Results, rng: random.Random, iterations: int
) -> None:
    """Random actions x callers: authorize_user must match the reference, and
    must never grant a non-root caller without a matching rule (P1)."""

    print(f"== randomized equivalence + P1: {iterations} action/caller pairs ==")
    status = d.PrivleapdAuthStatus
    users: list[str] = real_usernames()
    groups: list[str] = real_groupnames()
    uids: list[str] = [str(p.pw_uid) for p in pwd.getpwall()]
    gids: list[str] = [str(g.gr_gid) for g in grp.getgrall()]
    ghosts_u: list[str] = ["no-user-aaa", "no-user-bbb"]
    ghosts_g: list[str] = ["no-group-aaa", "no-group-bbb"]

    ## Candidate callers: a spread of real accounts plus a nonexistent one.
    caller_pool: list[str] = [
        name
        for name in ("root", "user", "daemon", "bin", "nobody", "sys")
        if name in users
    ]
    if not caller_pool:
        caller_pool = users[:5]
    ## Add a nonexistent caller to exercise the USER_MISSING path. Appended
    ## after the emptiness fallback so the fallback stays reachable.
    caller_pool.append("no-such-caller-zzz")

    mismatches: int = 0
    p1_violations: int = 0
    errors: int = 0

    def pick(pool: list[str], rng_: random.Random) -> list[str] | None:
        if rng_.random() < 0.2:
            return None
        count: int = rng_.randint(1, 3)
        return [rng_.choice(pool) for _ in range(count)]

    for _ in range(iterations):
        user_pool: list[str] = rng.choice([users, uids]) + ghosts_u
        group_pool: list[str] = rng.choice([groups, gids]) + ghosts_g
        au: list[str] | None = pick(user_pool, rng)
        ag: list[str] | None = pick(group_pool, rng)
        if au is None and ag is None:
            ag = [rng.choice(group_pool)]
        try:
            action: Any = make_action(au, ag)
        except ValueError:
            ## Constructor rejected the combination (e.g. both empty); skip.
            continue

        caller: str = rng.choice(caller_pool)
        try:
            got: Any = d.authorize_user(action, caller)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            errors += 1
            if errors <= 10:
                print(
                    f"  FINDING: authorize_user raised {type(exc).__name__}: "
                    f"{exc}\n    au={au} ag={ag} caller={caller!r}"
                )
            continue

        want: Any = ref_authorize(action, caller)
        if got != want:
            mismatches += 1
            if mismatches <= 10:
                print(
                    f"  MISMATCH: caller={caller!r} au={au} ag={ag}: "
                    f"got {got}, ref {want}"
                )

        ## P1 invariant, checked directly and independently of the reference.
        if got == status.AUTHORIZED and caller != "no-such-caller-zzz":
            info_uid: int = pwd.getpwnam(caller).pw_uid
            if info_uid != 0 and action.auth_restricted:
                named: bool = caller in action.auth_users
                grouped: bool = bool(
                    user_group_names(caller) & set(action.auth_groups)
                )
                if not named and not grouped:
                    p1_violations += 1
                    print(
                        f"  P1 VIOLATION (privilege without grant): "
                        f"caller={caller!r} au={action.auth_users} "
                        f"ag={action.auth_groups}"
                    )

    results.check(f"no authorize_user crashes over {iterations} pairs",
                  errors == 0)
    results.check("authorize_user matches reference model", mismatches == 0)
    results.check("P1 holds: no privilege without a matching rule",
                  p1_violations == 0)


def run(seed: int, iterations: int, results: Results) -> None:
    """Run all authorizer phases."""

    rng: random.Random = random.Random(seed)
    phase_named_properties(results)
    phase_oracle_hardening(results)
    phase_is_user_allowed(results)
    phase_random_equivalence(results, rng, iterations)


def main() -> int:
    """Standalone entry point."""

    parser = argparse.ArgumentParser(
        description="privleap authorization-engine property test / fuzzer"
    )
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--iterations", type=int, default=3000)
    args = parser.parse_args()

    seed: int = (
        args.seed if args.seed is not None else random.randrange(1 << 30)
    )
    print(f"privleap authorizer test: seed={seed} iterations={args.iterations}")
    results: Results = Results()
    run(seed, args.iterations, results)
    print()
    code: int = results.report("authorizer test")
    if code != 0:
        print(f"REPRODUCE: --seed {seed} --iterations {args.iterations}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
