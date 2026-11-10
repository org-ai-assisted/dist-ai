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
import re

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

## systemd strips/splits config tokens on ASCII WHITESPACE only (src/fundamental/
## string-util.h: " \t\n\r") -- NOT \f, \v, NBSP or other Unicode whitespace that
## Python's str.strip()/str.split()/str.splitlines() ALSO treat as separators.
## Using the Python defaults lets a unit hide a directive behind a non-ASCII space
## (systemd keeps '\xa0Key' an unknown key and ignores it) while the lint reads it
## as applied -- a false "hardened" verdict. These mirror systemd's strstrip /
## extract_first_word so the lint sees the same tokens the kernel does.
_SYSTEMD_WS = ' \t\n\r'


def systemd_strip(text: str) -> str:
    return text.strip(_SYSTEMD_WS)


def systemd_fields(text: str) -> list:
    return [tok for tok in re.split('[ \t\n\r]+', text) if tok]


def _ends_continued(line: str) -> bool:
    ## systemd treats a line ending in an ODD run of backslashes as continued
    ## (parity), measured BEFORE trailing-whitespace stripping.
    count = 0
    for char in reversed(line):
        if char != '\\':
            break
        count += 1
    return count % 2 == 1


def service_lines(text: str) -> list:
    """Logical [Service] directive lines, modeling systemd's config_parse order:
    physical lines split on '\\n'; a '#'/';' comment is dropped per-PHYSICAL-line
    BEFORE any continuation join (and does NOT clear a pending continuation); a
    trailing-'\\' line (odd backslash parity) is joined to the next BEFORE the
    section-header test, so a '[Service]' that merely continues a prior value
    stays part of that value instead of opening the section; the section-header
    and directive tests run on the joined, ASCII-stripped line. systemd ignores
    directives outside [Service], so this does too."""
    out: list = []
    continuation = None
    in_service: bool = False

    def emit(logical: str) -> None:
        nonlocal in_service
        stripped = systemd_strip(logical)
        if not stripped:
            return
        if stripped.startswith('['):
            ## systemd changes section only on a well-formed '[Name]' (CASE-
            ## SENSITIVE: a '[service]' header is ignored). A '['-line not ending
            ## in ']' is an invalid header -- ignored, section left unchanged.
            if stripped.endswith(']'):
                in_service = stripped == '[Service]'
            return
        if in_service:
            out.append(stripped)

    for raw in text.split('\n'):
        ## Comment test: per physical line, leading-ASCII-ws skipped, BEFORE the
        ## join. systemd drops the comment via 'continue' WITHOUT clearing a
        ## pending continuation, so an in-progress join carries across it.
        if raw.lstrip(_SYSTEMD_WS)[:1] in ('#', ';'):
            continue
        joined = raw if continuation is None else continuation + raw
        if _ends_continued(joined):
            ## systemd replaces the final backslash with a space and accumulates.
            continuation = joined[:-1] + ' '
            continue
        continuation = None
        emit(joined)
    if continuation is not None:
        ## EOF with a dangling continuation: systemd parses the buffer once more.
        emit(continuation)
    return out


def service_values(lines: list, key: str) -> list:
    ## Split on the FIRST '=' and strip both sides: systemd ignores whitespace
    ## around '=' ("Key = value"), so a prefix-only match would miss a spaced
    ## assignment and silently under-read the effective filter. ASCII-only strip
    ## (systemd_strip): a non-ASCII space before the key leaves it an unknown
    ## directive systemd ignores, so it must NOT match here.
    out: list = []
    for line in lines:
        name, sep, value = line.partition('=')
        if sep and systemd_strip(name) == key:
            out.append(systemd_strip(value))
    return out


def errno_is_soft(value: str) -> bool:
    val = systemd_strip(value)
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
        tokens = systemd_fields(body)
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
    syscall_filter_simple()."""
    mode = None
    allow: set = set()
    for value in syscall_filter_values(text):
        stripped = systemd_strip(value)
        if stripped == '':
            mode = None
            allow = set()
            continue
        negated = stripped.startswith('~')
        tokens = set(systemd_fields(stripped[1:] if negated else stripped))
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
    syscall hidden inside a group. Use syscall_filter_simple() to FAIL CLOSED."""
    _, allow = _effective_filter(text)
    return allow


## A PLAIN syscall token: a bare name, no '@' group, no ':action' per-syscall
## errno, no '\\' escape. The membership reasoning in effective_allowset (is a
## SPECIFIC syscall present/absent) is only sound over plain tokens.
_PLAIN_SYSCALL_RE = re.compile(r'^[A-Za-z0-9_]+$')


def syscall_filter_simple(text: str) -> bool:
    """True iff every SystemCallFilter token the lint must reason about is a PLAIN
    syscall name, after reset semantics. Returns False for a syscall GROUP ('@ipc',
    which CONTAINS memfd_create), a per-syscall action ('memfd_create:EPERM'), or a
    '\\'-escaped token -- constructs this module does NOT model (modeling them means
    reimplementing systemd's group expansion and quote processing). A caller that
    reasons about a SPECIFIC syscall's presence/absence (effective_allowset
    membership) must FAIL CLOSED when this is False rather than trust an incomplete
    literal token set. Reset-aware: a construct discarded by a later empty
    'SystemCallFilter=' does not count (systemd already dropped it).

    NOTE scope: this covers the ALLOWLIST membership path. The DENYLIST path
    (memfd_denial) already models a '~memfd_create' denial, its ':action'
    per-syscall errno, and a positive '@group' re-allow, so it does not need this.
    A '\\'-escaped token crafted to EVADE the group check is an adversarial forge,
    out of scope -- no Kicksecure/Whonix unit uses one."""
    effective: list = []
    for value in syscall_filter_values(text):
        stripped = systemd_strip(value)
        if stripped == '':
            effective = []
        else:
            effective.append(stripped)
    for value in effective:
        body = value[1:] if value.startswith('~') else value
        for token in systemd_fields(body):
            if not _PLAIN_SYSCALL_RE.match(token):
                return False
    return True
