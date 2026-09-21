#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris (libFuzzer) coverage-guided fuzz harness for accountctl.sh's pure
decision functions.

accountctl.sh is bash and Atheris instruments PYTHON, not bash, so this harness
fuzzes a Python PORT of the pure, parser-like functions. The port is NOT an
independent oracle: its faithfulness to the bash is enforced by the sibling
suites that drive the REAL bash over the SAME invariants -- accountctl_test.sh
(unit), accountctl_fuzz.sh (no-dependency randomized property fuzz), and
verify_accountctl_formal.py (enumeration proof). Treat those as the real-code
counterpart; this harness adds Atheris' structured input generation and
coverage-guided exploration.

Invariants (a violation raises, which Atheris reports as a finding):
  - is_name_valid: an ACCEPTED name starts with [a-zA-Z_] and, minus an optional
    trailing '$', is entirely over the safe charset [-a-zA-Z0-9_.@] (so escape_name
    only ever faces '.' and '$').
  - escape_name: the result, with '\\.' and '\\$' removed, contains no bare '.'
    or '$' (every metacharacter escaped), and un-escaping recovers the input.
  - get_clean_pass: the result has NO leading marker char (any char in symbol)
    and is a suffix of the input.
  - get_field: returns an int for a known field and None for an unknown one --
    never a wrong-typed value or an exception.
  - group_has_nonroot_member: returns a bool; a name not starting [a-zA-Z_] is
    rejected; a True result implies a real non-root member of the fixture.

Run via the dist-ai entrypoint (60s default budget):
    helper-scripts-lib-tests-fuzz-atheris
    helper-scripts-lib-tests-fuzz-atheris -max_total_time=600
Or directly (needs `pip install atheris`):
    python3 -m atheris fuzz_accountctl.py -max_total_time=300
Without Atheris the harness reports a clean SKIP (exit 77); use accountctl_fuzz.sh
(driven by accountctl_test.sh) for a no-dependency real-bash run.
"""

import os
import re
import sys


def _subject() -> "str | None":
    repo = os.environ.get("HELPER_SCRIPTS_REPO")
    base = os.path.join(repo, "usr/libexec/helper-scripts") if repo else "/usr/libexec/helper-scripts"
    candidate = os.path.join(base, "accountctl.sh")
    return candidate if os.path.isfile(candidate) else None


_SUBJECT = _subject()

try:
    import atheris  # type: ignore
    _HAVE_ATHERIS = True
except ImportError:
    _HAVE_ATHERIS = False


## --- ports of accountctl.sh's pure functions (mirrors, anchored by the sibling
## real-bash suites) ---

_NAME_RE = re.compile(r"[a-zA-Z_][-a-zA-Z0-9_.@]*\$?\Z")
_SAFE_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.@")

_GET_FIELD = {
    "passwd": {"pass": 2, "uid": 3, "gid": 4, "comment": 5, "home": 6, "shell": 7},
    "shadow": {"pass": 2, "last-pass-change": 3, "min-pass-age": 4, "max-pass-age": 5,
               "warn-pass-period": 6, "lock-pass-period": 7, "expiration-date": 8},
    "group": {"pass": 2, "gid": 3, "members": 4},
    "gshadow": {"pass": 2, "admins": 3, "members": 4},
}


def is_name_valid(name: str) -> bool:
    return _NAME_RE.fullmatch(name) is not None


def escape_name(name: str) -> str:
    return name.replace(".", "\\.").replace("$", "\\$")


def get_clean_pass(pass_v: str, symbol: str) -> str:
    i = 0
    while i < len(pass_v) and pass_v[i] in symbol:
        i += 1
    return pass_v[i:]


def get_field(db: str, field: str):
    idx = _GET_FIELD.get(db, {}).get(field)
    return None if idx is None else idx - 1


def group_has_nonroot_member(group: str, passwd, group_db) -> bool:
    if not group or not re.match(r"[a-zA-Z_]", group):
        return False
    if group not in group_db:
        return False
    gid, members = group_db[group]
    if any(pgid == gid and name != "root" for name, pgid in passwd):
        return True
    return any(m and m != "root" for m in members)


if _HAVE_ATHERIS:
    is_name_valid = atheris.instrument_func(is_name_valid)
    escape_name = atheris.instrument_func(escape_name)
    get_clean_pass = atheris.instrument_func(get_clean_pass)
    get_field = atheris.instrument_func(get_field)
    group_has_nonroot_member = atheris.instrument_func(group_has_nonroot_member)


_SYMBOLS = ("!", "!*", "*")
_DBS = ("passwd", "shadow", "group", "gshadow", "bogus", "")
_FIELDS = ("pass", "uid", "gid", "comment", "home", "shell", "members", "admins",
           "min-pass-age", "bogus", "")


def _check_one(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    ## is_name_valid + escape_name over an arbitrary name.
    name = fdp.ConsumeUnicodeNoSurrogates(12)
    if is_name_valid(name):
        body = name[:-1] if name.endswith("$") else name
        _NAME_START = ("_", *"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
        if not name or name[0] not in _NAME_START:
            raise RuntimeError(f"is_name_valid accepted a name not starting [a-zA-Z_]: {name!r}")
        if any(c not in _SAFE_CHARS for c in body):
            raise RuntimeError(f"is_name_valid accepted an unsafe-charset name: {name!r}")
    esc = escape_name(name)
    stripped_markers = esc.replace("\\.", "").replace("\\$", "")
    if "." in stripped_markers or "$" in stripped_markers:
        raise RuntimeError(f"escape_name left a bare metacharacter: {name!r} -> {esc!r}")
    unescaped = esc.replace("\\.", ".").replace("\\$", "$")
    if unescaped != name:
        raise RuntimeError(f"escape_name does not round-trip: {name!r} -> {esc!r}")

    ## get_clean_pass over an arbitrary password + a marker symbol.
    pass_v = fdp.ConsumeUnicodeNoSurrogates(12)
    symbol = _SYMBOLS[fdp.ConsumeIntInRange(0, len(_SYMBOLS) - 1)]
    clean = get_clean_pass(pass_v, symbol)
    if clean and clean[0] in symbol:
        raise RuntimeError(f"get_clean_pass left a leading marker: {pass_v!r} sym={symbol!r} -> {clean!r}")
    if not pass_v.endswith(clean):
        raise RuntimeError(f"get_clean_pass result not a suffix: {pass_v!r} sym={symbol!r} -> {clean!r}")

    ## get_field: known -> int, unknown -> None, never an exception.
    db = _DBS[fdp.ConsumeIntInRange(0, len(_DBS) - 1)]
    field = _FIELDS[fdp.ConsumeIntInRange(0, len(_FIELDS) - 1)]
    idx = get_field(db, field)
    known = _GET_FIELD.get(db, {}).get(field) is not None
    if known and not isinstance(idx, int):
        raise RuntimeError(f"get_field known field wrong type: {db!r} {field!r} -> {idx!r}")
    if not known and idx is not None:
        raise RuntimeError(f"get_field unknown field not None: {db!r} {field!r} -> {idx!r}")

    ## group_has_nonroot_member over a small fuzzed fixture.
    group = fdp.ConsumeUnicodeNoSurrogates(8)
    gid = str(fdp.ConsumeIntInRange(0, 9))
    member = fdp.ConsumeUnicodeNoSurrogates(6)
    acct_gid = str(fdp.ConsumeIntInRange(0, 9))
    group_db = {"grp": (gid, [member] if member else [])}
    passwd = [("root", "0"), ("svc", acct_gid)]
    result = group_has_nonroot_member(group, passwd, group_db)
    if not isinstance(result, bool):
        raise RuntimeError(f"group_has_nonroot_member non-bool: {group!r} -> {result!r}")
    if result and (not group or not re.match(r"[a-zA-Z_]", group)):
        raise RuntimeError(f"group_has_nonroot_member accepted a non-name: {group!r}")


def TestOneInput(data: bytes) -> None:  # noqa: N802 (Atheris contract name)
    _check_one(data)


def main() -> None:
    if _SUBJECT is None:
        print("SKIP: accountctl.sh not found.")
        print("      set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install it.")
        raise SystemExit(77)
    if not _HAVE_ATHERIS:
        print("SKIP: atheris is not installed (pip install atheris).")
        print("      this is the coverage-guided harness; for a no-dependency real-bash")
        print("      run use accountctl_fuzz.sh (driven by accountctl_test.sh).")
        raise SystemExit(77)
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
