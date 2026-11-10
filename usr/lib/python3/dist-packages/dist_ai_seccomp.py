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
## for it is a false pass.
_VALID_ERRNO_NAMES = frozenset(errno.errorcode.values())


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
    if val.isdigit():
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
        for token in (value[1:] if negate else value).split():
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


def is_allowlist(text: str) -> bool:
    """True iff there is at least one SystemCallFilter= and NONE is a '~' denylist.
    An allowlist permits ONLY the named syscalls (default-deny: everything else is
    SIGSYS-killed). A single '~' directive flips it to a denylist that permits every
    UNNAMED syscall and removes the sandbox, so a stray '~' must fail the allowlist
    assertion."""
    values = syscall_filter_values(text)
    return bool(values) and all(not v.strip().startswith('~') for v in values)


def effective_allowset(text: str) -> set:
    """The effective allowed-syscall set after systemd reset semantics: an empty
    value OR a '~' value clears the set; otherwise tokens accumulate. Meaningful
    for an allowlist (is_allowlist); when a '~' is present the sandbox is a
    denylist and the returned set is only what follows the last reset."""
    effective: set = set()
    for value in syscall_filter_values(text):
        stripped = value.strip()
        if stripped == '' or stripped.startswith('~'):
            effective = set()
        else:
            effective |= set(stripped.split())
    return effective
