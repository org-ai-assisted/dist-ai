#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Structural regression tests for the PAM session hook tb-home-remount-exec.

The hook hardcodes /home/<user> and overrides PATH, so a faithful end-to-end
drive is left to the sandbox e2e. These pin the two security properties that
must never silently regress (both FAIL against the pre-guard hook):

  * NAMESPACE GUARD: the hook remounts ONLY when its mount namespace is unshared
    from init (pam_namespace active). Without it, pam_exec runs in the init
    namespace and the bind-remount is system-wide and permanent (close_session
    does not umount), and a user-planted symlink could make an arbitrary noexec
    path exec for the whole system. The guard (compare /proc/self/ns/mnt to
    /proc/1/ns/mnt, exit on equal) must sit BEFORE any remount.
  * The hook must create via the shared helper's prepare_owner (privilege-
    dropped creation, pinned behaviorally in test_remount_exec_lib.py), never a
    direct root mkdir/chown in the hook itself.
"""

import re

import tb_updater_testlib as T

## The ns guard OPENER: if [ "$(readlink .../self/ns/mnt)" =
## "$(readlink .../1/ns/mnt)" ]; then. The matching 'fi' is found by if/fi depth
## counting (not a non-greedy '.*?fi'), so a nested conditional in the guard
## body cannot close the block early and let a remount still inside the
## equal-namespace branch read as after the guard.
_GUARD_OPEN_RE = re.compile(
    r"if\s*\[\s*\"\$\(\s*readlink[^\n]*/proc/self/ns/mnt[^\n]*\)\"\s*=\s*"
    r"\"\$\(\s*readlink[^\n]*/proc/1/ns/mnt[^\n]*\)\"\s*\][^\n]*;\s*then"
)
_IF_FI_RE = re.compile(r"\b(if|fi)\b")
_APPLY_RE = re.compile(r"\btb_remount_exec_apply\b")
_PROP_RE = re.compile(r"mount\s+--make-r?(?:slave|private)\b")


def _strip_comments(text: str) -> str:
    ## Drop full-line '##'/'#' comments so a property is asserted on code, not a
    ## comment that merely mentions it.
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        out.append(line)
    return "\n".join(out)


def _hook_code() -> str:
    ## Read the REAL hook lazily (not at import): a missing required hook must
    ## fail these structural checks loudly (the resolver exits 1), never turn
    ## into a module-level skip that silently drops the regression coverage.
    return _strip_comments(T.read(T.home_remount_hook()))


def _guard_block(code: str):
    """(body_start, block_end) of the ns guard: the index just after its
    'if ... ; then' opener and the index just past its MATCHING 'fi', located by
    if/fi depth counting. None if there is no guard."""
    opener = _GUARD_OPEN_RE.search(code)
    if opener is None:
        return None
    depth = 1
    for token in _IF_FI_RE.finditer(code, opener.end()):
        if token.group(1) == "fi":
            depth -= 1
            if depth == 0:
                return opener.end(), token.end()
        else:
            depth += 1
    return None


def _guard_then_remount_ok(code: str) -> bool:
    """True iff a COMPLETE ns guard ('if ... exit 0 ... fi') closes BEFORE the
    propagation hardening and the first remount. Keyed on the guard's matching
    'fi' (depth-counted), so a remount placed INSIDE the equal-namespace branch
    -- which runs in init's namespace -- is rejected even behind a nested
    conditional. A pure predicate so it can be canaried against crafted hooks."""
    block = _guard_block(code)
    if block is None:
        return False
    body_start, block_end = block
    if not re.search(r"\bexit\s+0\b", code[body_start:block_end]):
        return False
    apply_at = _APPLY_RE.search(code)
    prop = _PROP_RE.search(code)
    if apply_at is None or prop is None:
        return False
    return block_end <= prop.start() < apply_at.start()


def test_ns_guard_compares_self_to_init_and_exits():
    ## readlink of both namespace links, compared, with an exit in the equal arm.
    code = _hook_code()
    assert re.search(r"readlink\b[^\n]*/proc/self/ns/mnt", code), code
    assert re.search(r"readlink\b[^\n]*/proc/1/ns/mnt", code), code
    block = _guard_block(code)
    assert block is not None, "ns guard 'if ... fi' not found in hook code"
    body_start, block_end = block
    assert re.search(r"\bexit\s+0\b", code[body_start:block_end]), code


def test_ns_guard_precedes_the_remount():
    ## The complete guard must CLOSE before the remount: its 'exit 0' skip arm
    ## and matching 'fi' precede the first tb_remount_exec_apply. Checking only
    ## that the first ns reference precedes the remount would pass a hook that
    ## remounts inside the equal-namespace branch (a system-wide remount in
    ## init's ns).
    code = _hook_code()
    block = _guard_block(code)
    assert block is not None, "ns guard 'if ... fi' not found in hook code"
    apply_at = _APPLY_RE.search(code)
    assert apply_at is not None, "hook never calls tb_remount_exec_apply"
    assert apply_at.start() > block[1], (
        "remount must come after the ns guard closes (its 'fi'), not inside "
        "the equal-namespace branch"
    )


def test_propagation_hardened_between_guard_and_remount():
    ## An unshared namespace is necessary but not sufficient: unshare keeps each
    ## mount's propagation type, so the hook must detach this session's tree from
    ## init's peer group (make-rslave / make-private) or the exec remount
    ## propagates back to init. It must sit AFTER the guard closes and BEFORE the
    ## remount.
    code = _hook_code()
    block = _guard_block(code)
    assert block is not None, "ns guard 'if ... fi' not found in hook code"
    prop = _PROP_RE.search(code)
    assert prop is not None, "no propagation hardening (make-rslave/make-private)"
    apply_at = _APPLY_RE.search(code)
    assert apply_at is not None, "hook never calls tb_remount_exec_apply"
    assert block[1] <= prop.start() < apply_at.start(), (
        "propagation hardening must sit after the ns guard closes and before "
        "the remount"
    )


def test_ordering_predicate_rejects_remount_in_equal_ns_branch():
    ## Canary: the finding's counterexample -- make-rslave + apply + exit 0 all
    ## INSIDE the equal-namespace branch -- must be rejected. The pre-fix
    ## first-ns-index check accepted it.
    bad = _strip_comments(
        '#!/bin/bash\n'
        'if [ "$(readlink -f /proc/self/ns/mnt)" = '
        '"$(readlink -f /proc/1/ns/mnt)" ]; then\n'
        '    mount --make-rslave /\n'
        '    tb_remount_exec_apply /home/user\n'
        '    exit 0\n'
        'fi\n'
    )
    assert not _guard_then_remount_ok(bad)


def test_ordering_predicate_rejects_remount_after_nested_fi_in_branch():
    ## Canary: a nested conditional inside the equal-namespace branch must not
    ## close the guard early. Here 'exit 0' sits in an inner 'if false; then ...
    ## fi' and the remount is still inside the outer branch -- a non-greedy
    ## match to the FIRST 'fi' accepted it; the depth-counted block end rejects.
    bad = _strip_comments(
        '#!/bin/bash\n'
        'if [ "$(readlink -f /proc/self/ns/mnt)" = '
        '"$(readlink -f /proc/1/ns/mnt)" ]; then\n'
        '    if false; then\n'
        '        exit 0\n'
        '    fi\n'
        '    mount --make-rslave /\n'
        '    tb_remount_exec_apply /home/user\n'
        'fi\n'
    )
    assert not _guard_then_remount_ok(bad)


def test_ordering_predicate_accepts_guard_then_harden_then_remount():
    ## Canary: the intended sequence -- guard exits in the equal-ns branch, then
    ## propagation hardening, then the remount -- must be accepted.
    good = _strip_comments(
        '#!/bin/bash\n'
        'if [ "$(readlink -f /proc/self/ns/mnt)" = '
        '"$(readlink -f /proc/1/ns/mnt)" ]; then\n'
        '    exit 0\n'
        'fi\n'
        'mount --make-rslave /\n'
        'tb_remount_exec_apply /home/user\n'
    )
    assert _guard_then_remount_ok(good)


def test_creation_goes_through_prepare_owner_not_direct_root():
    ## Creation is delegated to the shared helper (privilege-dropped there); the
    ## hook must not add its own root mkdir/chown back in.
    code = _hook_code()
    assert "tb_remount_exec_prepare_owner" in code, code
    assert not re.search(r"(^|\s)mkdir\b", code), "hook must not mkdir directly"
    assert not re.search(r"(^|\s)chown\b", code), "hook must not chown directly"
