## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Shared systemd W^X seccomp-filter policy model for the dist-ai test suites.

SINGLE source of the `.service` SystemCallFilter model used by the W^X hardening
lints: the memfd_create DENYLIST classifier (privleap-tests/service_hardening_test.py,
systemcheck-tests/test_wx_seccomp_filter.py, and the per-daemon lints via
dist_ai_wx_lint) AND the ALLOWLIST model (sdwdate-tests/test_seccomp_filter.py,
onion-grater via dist_ai_wx_lint). Each suite imports it via a `__file__`-relative
sys.path.insert of this dist-packages dir (the dm_test_results idiom), so there is
ONE implementation -- no hand-sync, no drift.

Models systemd's effective-policy semantics: [Service]-section only, SystemCallFilter=
empty-reset, a per-syscall ':' action that overrides the global SystemCallErrorNumber,
and errno validity -- a lint fooled by any of those would report a confident wrong pass.
"""

import errno

## systemd accepts an errno name or a number 1..4095; anything else (empty,
## 'kill', 0, out of range, junk) is NOT a soft-fail errno.
_ERRNO_MIN, _ERRNO_MAX = 1, 4095
## Retryable errnos are a BAD soft-deny: the caller re-issues the blocked syscall
## in a tight loop instead of giving up, so memfd_create never settles. Reject them
## by name (the form units use); a real soft deny is a terminal errno like EPERM.
_RETRYABLE_ERRNOS = {
    'EINTR', 'EAGAIN', 'EWOULDBLOCK',
    'ERESTART', 'ERESTARTSYS', 'ERESTARTNOINTR', 'ERESTARTNOHAND',
}
## A real errno name. systemd IGNORES an unknown name (e.g. EBOGUS) and keeps the
## default KILL action, so an invalid name is NOT a soft deny -- reporting 'soft'
## for it is a false pass. Enumerate every E* constant (not errorcode.values(),
## which keeps ONE name per number and so DROPS systemd-valid aliases that share a
## number -- EOPNOTSUPP/ENOTSUP, EDEADLOCK/EDEADLK; a unit using the dropped alias
## would be mis-reported as a hard kill).
_VALID_ERRNO_NAMES = frozenset(
    name for name in dir(errno)
    if name.startswith('E') and isinstance(getattr(errno, name), int))


def service_lines(text: str) -> list:
    """Logical directive lines inside the [Service] section, '\\'-continuations
    joined. systemd ignores these directives outside [Service], so the lint must
    too."""
    out: list = []
    buf: str = ''
    in_service: bool = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            ## systemd section names are CASE-SENSITIVE: directives under a
            ## '[service]' header are ignored, so a case-insensitive match would
            ## credit hardening systemd never applies.
            in_service = stripped == '[Service]'
            continue
        ## systemd ignores lines starting with '#' OR ';' (comments).
        if not in_service or stripped.startswith('#') or stripped.startswith(';'):
            continue
        if stripped.endswith('\\'):
            buf += stripped[:-1] + ' '
        else:
            out.append((buf + stripped).strip())
            buf = ''
    if buf:
        out.append(buf.strip())
    return out


def service_values(lines: list, key: str) -> list:
    ## Split on the FIRST '=' and strip both sides: systemd ignores whitespace
    ## around '=' ("Key = value"), so a prefix-only match would miss a spaced
    ## assignment and silently under-read the effective filter.
    out: list = []
    for line in lines:
        name, sep, value = line.partition('=')
        if sep and name.strip() == key:
            out.append(value.strip())
    return out


def errno_is_soft(value: str) -> bool:
    val = value.strip()
    if not val or val.lower() == 'kill':
        return False
    if val.upper() in _RETRYABLE_ERRNOS:
        return False
    ## isascii() guard: a non-ASCII digit (e.g. U+00B2) passes isdigit() but int()
    ## then raises ValueError and crashes the lint. systemd accepts only ASCII
    ## 1..4095, so a non-ASCII digit is not a valid errno -- fall through to False.
    if val.isascii() and val.isdigit():
        return _ERRNO_MIN <= int(val) <= _ERRNO_MAX
    ## an errno NAME must be a REAL errno: systemd ignores an unknown name and keeps
    ## the KILL action, so a bogus name (EBOGUS) is not a soft deny. A real name
    ## carrying a digit (E2BIG, EL2HLT) is NOT numeric -- .isdigit() is False, so it
    ## is validated by membership here, not mis-rejected as out-of-range.
    return val in _VALID_ERRNO_NAMES


def memfd_denial(text: str) -> str:
    """'none' | 'soft' | 'kill' for memfd_create under [Service], honoring
    SystemCallFilter= empty-reset, a per-syscall ':' action (which overrides the
    global SystemCallErrorNumber), and the global SystemCallErrorNumber. A '~'
    token denies memfd_create; a later positive assignment of it re-allows it
    (last wins). A full allowlist (whitelist) that omits memfd_create is out of
    scope -- our units use the '~' denylist form."""
    lines = service_lines(text)
    effective: list = []
    for value in service_values(lines, 'SystemCallFilter'):
        if value == '':
            effective = []
        else:
            effective.append(value)
    denied = False
    per_syscall = None
    for value in effective:
        negate = value.startswith('~')
        body = value[1:] if negate else value
        tokens = body.split()
        ## A POSITIVE syscall-GROUP line (e.g. '@ipc', '@system-service' -- both
        ## CONTAIN memfd_create) re-allows syscalls this module cannot expand. Be
        ## conservative: treat memfd_create as no longer reliably denied, so the
        ## caller fails CLOSED instead of greening a unit that may permit it.
        if not negate and any(tok.startswith('@') for tok in tokens):
            denied = False
            per_syscall = None
            continue
        for token in tokens:
            if token.split(':', 1)[0] != 'memfd_create':
                continue
            if negate:
                ## '~' denylist: memfd_create is denied; ':' sets its per-syscall action.
                denied = True
                per_syscall = token.split(':', 1)[1] if ':' in token else None
            else:
                ## a later POSITIVE assignment re-allows the syscall (systemd removes
                ## it from the denylist), so it is no longer denied.
                denied = False
                per_syscall = None
    if not denied:
        return 'none'
    if per_syscall is not None:
        ## per-syscall action takes precedence over the global errno
        return 'soft' if errno_is_soft(per_syscall) else 'kill'
    errnos = service_values(lines, 'SystemCallErrorNumber')
    if errnos and errno_is_soft(errnos[-1]):
        return 'soft'
    return 'kill'


def syscall_filter_values(text: str) -> list:
    """Every SystemCallFilter= value under [Service], in order, '\\'-continuations
    joined. systemd accumulates multiple assignments; an empty one resets."""
    return service_values(service_lines(text), 'SystemCallFilter')


def _effective_filter(text: str):
    """(mode, allowset) after systemd's SystemCallFilter merge + reset semantics.

    mode is 'allow' (allowlist / default-deny), 'deny' (denylist / default-allow),
    or None (no filter). The FIRST value after the last reset sets the mode; an
    empty value resets both mode and set. systemd MERGES subsequent lines -- it
    does NOT flip the mode: in allowlist mode a positive line ADDS syscalls and a
    '~' line REMOVES them (man systemd.exec: allow 'read write', then '~write',
    leaves 'read' -- still an allowlist). In denylist mode a further line edits the
    deny set; allowset is only meaningful for an allowlist, so it stays empty there.

    Group tokens ('@ipc', ...) are kept LITERAL (not expanded) -- see
    has_syscall_group()."""
    mode = None
    allow: set = set()
    for value in syscall_filter_values(text):
        stripped = value.strip()
        if stripped == '':
            mode = None
            allow = set()
            continue
        negated = stripped.startswith('~')
        tokens = set((stripped[1:] if negated else stripped).split())
        if mode is None:
            mode = 'deny' if negated else 'allow'
            allow = set() if negated else set(tokens)
        elif mode == 'allow':
            if negated:
                allow -= tokens
            else:
                allow |= tokens
    return mode, allow


def is_allowlist(text: str) -> bool:
    """True iff the effective SystemCallFilter is an ALLOWLIST (default-deny): at
    least one value, and the FIRST one after the last reset is positive (no '~').
    systemd sets the mode from that first value; a LATER '~' line only REMOVES
    syscalls and does NOT flip to a denylist, so it stays an allowlist. A first
    '~' (or an empty-reset immediately before one) IS a denylist and fails here --
    that is the 'sandbox silently removed' regression the allowlist lint guards."""
    mode, _ = _effective_filter(text)
    return mode == 'allow'


def effective_allowset(text: str) -> set:
    """The effective allowed-syscall set of an ALLOWLIST (positive lines add, '~'
    lines remove, empty resets). Empty for a denylist (not meaningful there;
    callers check is_allowlist first).

    NOTE: syscall GROUP tokens ('@ipc', '@system-service', ...) are kept LITERAL;
    this does NOT expand them, so a membership test against this set cannot see a
    syscall hidden inside a group. Use has_syscall_group() to FAIL CLOSED."""
    _, allow = _effective_filter(text)
    return allow


def has_syscall_group(text: str) -> bool:
    """True if any SystemCallFilter value names a syscall GROUP ('@ipc', ...).

    This module does NOT expand groups (systemd ships ~30, each with many members,
    e.g. '@ipc' and '@system-service' both contain memfd_create), so a lint that
    reasons about a specific syscall (memfd_create present/absent) must FAIL CLOSED
    when a group is used rather than trust an incomplete literal token set."""
    for value in syscall_filter_values(text):
        for token in value.strip().lstrip('~').split():
            if token.startswith('@'):
                return True
    return False
