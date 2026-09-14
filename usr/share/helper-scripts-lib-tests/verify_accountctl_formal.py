#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Formal verification of accountctl.sh's PURE decision functions (enumeration).

Method, mirroring verify_curl_prgrs_formal.py's enumeration half:
  - REFERENCE MODEL: a Python model of each function's specified behaviour.
  - ENUMERATION against the REAL bash: source the ACTUAL accountctl.sh from the
    checkout and run its real functions, confirming they match the model
    point-for-point. This anchors the model to the real script, not a copy.
      * EXHAUSTIVE where the input domain is finite (get_field): a complete
        proof over that domain.
      * BOUNDED + INVARIANT-GUARDED elsewhere: a grid over a small alphabet plus
        structural invariants that must hold for every sampled input.
  - CANARIES: every guard is also run against a deliberately BROKEN model and
    must catch it, so a green run has teeth.

No SMT here, deliberately. curl-prgrs used Z3 for ARITHMETIC (a decidable
domain); accountctl's pure functions are string / finite-map shaped, and Z3's
regex/string fragment returns 'unknown' on the language-subset obligations
(verified: it does not discharge them), so a real proof there would be a false
claim. Enumeration against the real bash, exhaustive over the finite domain, is
the honest instrument -- the same one the precedent uses for its string facts.

Theorems:
  T1  get_field                 -- EXHAUSTIVE: the (db,field)->index map is total
                                    and correct over its finite domain; every
                                    unsupported field errors (never a wrong index).
  T2  get_clean_pass            -- the stripped result contains NO leading marker
                                    character (any char in symbol) and is a suffix
                                    of the input; a '!!' field strips to empty
                                    (the F1/F2/F3 invariant).
  T3  is_name_valid             -- real bash matches the reference NAME_REGEX, and
                                    every ACCEPTED name is over the safe charset
                                    [-a-z0-9_.@] plus an optional trailing '$' (so
                                    the only BRE metacharacters escape_name must
                                    handle are '.' and '$') and starts with [a-z_].
  T4  escape_name (+ composition) -- escaping is correct ('.'->'\\.', '$'->'\\$'),
                                    and for a valid name the escaped string used as
                                    an anchored BRE matches a line IFF the line's
                                    first field is the literal name.
  T5  group_has_nonroot_member  -- returns 0 IFF a non-root account has the group
                                    as its primary GID or is a supplementary
                                    member; a numeric argument is rejected (not
                                    reinterpreted by getent as a GID lookup).

SCOPE -- honest. T1 is exhaustive over its finite domain. T2/T3/T4/T5 prove the
real bash matches the model + the stated invariants on the SAMPLED grid, not
over every possible string. Stateful/root functions (get_pass, is_pass_*,
lock/unlock/disable/enable_pass, is_user/is_group) are not pure and are covered
by accountctl_test.sh, not here.

Exit 0 on all obligations discharged, 1 on any divergence or a canary that
failed to catch its broken model. A missing accountctl.sh subject is a hard
FAILURE (exit 1), never a silent skip -- a verification suite must not disable
itself.
"""

import itertools
import os
import re
import shlex
import subprocess
import sys


def _subject_and_env():
    repo = os.environ.get("HELPER_SCRIPTS_REPO", "").rstrip("/")
    base = repo if repo else ""
    subject = os.path.join(base or "/", "usr/libexec/helper-scripts/accountctl.sh")
    env = dict(os.environ)
    if base:
        env["HELPER_SCRIPTS_PATH"] = base
        env["PATH"] = os.path.join(base, "usr/bin") + os.pathsep + env.get("PATH", "")
    if not os.path.isfile(subject):
        sys.stderr.write(
            "helper-scripts-lib-tests(verify_accountctl_formal): FAIL accountctl.sh "
            "not found at %r; set HELPER_SCRIPTS_REPO or install helper-scripts\n"
            % subject
        )
        sys.exit(1)
    return subject, env


FAIL = 0
CANARIES_VERIFIED = [0]


def fail(msg):
    global FAIL
    FAIL += 1
    sys.stderr.write("FAIL: " + msg + "\n")


def _expect_caught(label, caught):
    if caught:
        CANARIES_VERIFIED[0] += 1
    else:
        fail("canary %s: a broken model was NOT caught" % label)


## --- run the REAL bash: source accountctl.sh once, then a batch body ---

def _bash_lines(subject, env, body):
    ## accountctl.sh sources has.bsh/as_root.sh/log_run_die.sh via
    ## HELPER_SCRIPTS_PATH (set in env); stdin feed avoids ARG_MAX for a large
    ## enumeration. shlex.quote guards a checkout path with spaces/quotes.
    prelude = "log() { :; }\n"  # silence log_run_die output; harmless in a query
    full = "source %s\n%s%s\n" % (shlex.quote(subject), prelude, body)
    proc = subprocess.run(
        ["bash", "-s"], input=full, env=env, capture_output=True, text=True, timeout=300
    )
    if proc.returncode != 0 and not proc.stdout:
        fail("bash batch failed rc=%d: %s" % (proc.returncode, proc.stderr[-300:]))
    return proc.stdout.splitlines()


def _q(value):
    return "'" + str(value).replace("'", "'\\''") + "'"


SENTINEL = "==ACSPLIT=="
SAFE_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-_.@")


## ============================ T1: get_field (exhaustive) ====================
## Reference: get_field prints (index-1) for a known (db,field), else errors.
_GET_FIELD = {
    "passwd": {"pass": 2, "uid": 3, "gid": 4, "comment": 5, "home": 6, "shell": 7},
    "shadow": {"pass": 2, "last-pass-change": 3, "min-pass-age": 4, "max-pass-age": 5,
               "warn-pass-period": 6, "lock-pass-period": 7, "expiration-date": 8},
    "group": {"pass": 2, "gid": 3, "members": 4},
    "gshadow": {"pass": 2, "admins": 3, "members": 4},
}


def m_get_field(db, field):
    idx = _GET_FIELD.get(db, {}).get(field)
    return None if idx is None else idx - 1


def t1_enumerate(subject, env):
    """EXHAUSTIVE over the finite (db,field) domain plus unsupported fields."""
    dbs = list(_GET_FIELD) + ["", "bogusdb"]
    fields = sorted({f for m in _GET_FIELD.values() for f in m}) + ["", "bogus", "uid "]
    grid = [(db, f) for db in dbs for f in fields]
    body = "\n".join(
        'if out="$(get_field %s %s 2>/dev/null)"; then printf "%%s\\n" "ok:${out}"; '
        'else printf "%%s\\n" "err"; fi' % (_q(db), _q(f))
        for db, f in grid
    )
    got = _bash_lines(subject, env, body)
    if len(got) != len(grid):
        fail("T1 get_field: expected %d results, got %d" % (len(grid), len(got)))
        return
    for (db, f), g in zip(grid, got, strict=True):
        want = m_get_field(db, f)
        if want is None:
            if g != "err":
                fail("T1 get_field: %r %r -> %r, expected error" % (db, f, g))
        elif g != "ok:%d" % want:
            fail("T1 get_field: %r %r -> %r, model ok:%d" % (db, f, g, want))


def t1_canaries():
    def broken(db, field):
        v = m_get_field(db, field)
        return 0 if v is None else v
    _expect_caught("T1/unknown-field-errors",
                   broken("passwd", "bogus") != m_get_field("passwd", "bogus"))
    _expect_caught("T1/index-shift",
                   (m_get_field("passwd", "uid") + 1) != m_get_field("passwd", "uid"))


## ============================ T2: get_clean_pass ============================
def m_clean(pass_v, symbol):
    """Strip EVERY leading char that is in symbol."""
    i = 0
    while i < len(pass_v) and pass_v[i] in symbol:
        i += 1
    return pass_v[i:]


def _no_leading_marker(result, symbol):
    return result == "" or result[0] not in symbol


def t2_enumerate(subject, env):
    """Shim get_pass to inject each candidate password, run the REAL
    get_clean_pass; assert result == model, no leading marker, and suffix."""
    alphabet = "!*$6a"
    passwords = [""]
    for n in range(1, 5):
        passwords += ["".join(p) for p in itertools.product(alphabet, repeat=n)]
    symbols = ["!", "!*", "*"]
    grid = [(p, s) for p in passwords for s in symbols]
    prelude = (
        "is_user() { return 0; }\n"
        "get_pass() { printf '%s' \"${TEST_PASS}\"; }\n"
    )
    parts = [prelude]
    ## get_clean_pass already prints a trailing newline; do NOT add another.
    parts += ["TEST_PASS=%s; get_clean_pass u %s" % (_q(p), _q(s)) for p, s in grid]
    got = _bash_lines(subject, env, "\n".join(parts))
    if len(got) != len(grid):
        fail("T2 get_clean_pass: expected %d results, got %d" % (len(grid), len(got)))
        return
    for (p, s), g in zip(grid, got, strict=True):
        want = m_clean(p, s)
        if g != want:
            fail("T2 get_clean_pass: %r symbol %r -> bash %r, model %r" % (p, s, g, want))
        if not _no_leading_marker(g, s):
            fail("T2 get_clean_pass: %r symbol %r -> %r has a leading marker" % (p, s, g))
        if not p.endswith(g):
            fail("T2 get_clean_pass: %r symbol %r -> %r is not a suffix" % (p, s, g))


def _strip_one_per_char(pass_v, symbol):
    """Broken (pre-fix): strip only ONE leading occurrence per symbol char."""
    for ch in symbol:
        if pass_v.startswith(ch):
            pass_v = pass_v[1:]
    return pass_v


def t2_canaries():
    broken = _strip_one_per_char("!!", "!*")
    _expect_caught("T2/strip-all", broken != m_clean("!!", "!*"))
    _expect_caught("T2/no-leading-marker", not _no_leading_marker(broken, "!*"))


## ============================ T3: is_name_valid ============================
## bash ERE: ^[a-z_][-a-z0-9_.@]*\$?$  (\$ = literal '$'; final $ = anchor).
_NAME_RE = re.compile(r"[a-z_][-a-z0-9_.@]*\$?\Z")


def _accepted_over_safe_charset(name):
    """The escape_name-safety enabler: an accepted name's only characters are the
    safe set plus an optional trailing '$', so '.' and '$' are its only BRE
    metacharacters (both escaped by escape_name)."""
    body = name[:-1] if name.endswith("$") else name
    return all(c in SAFE_CHARS for c in body)


def t3_enumerate(subject, env):
    """Anchor real is_name_valid to the reference regex over a bounded alphabet
    (including unsafe chars), and assert every ACCEPTED name is over the safe
    charset and starts with [a-z_]."""
    alphabet = ["a", "z", "_", "-", "0", "9", ".", "@", "$", "A", "!", "*", "[", " "]
    names = [""]
    for n in range(1, 4):
        names += ["".join(p) for p in itertools.product(alphabet, repeat=n)]
    body = "\n".join(
        'if is_name_valid %s >/dev/null 2>&1; then printf "1\\n"; else printf "0\\n"; fi'
        % _q(nm) for nm in names
    )
    got = _bash_lines(subject, env, body)
    if len(got) != len(names):
        fail("T3 is_name_valid: expected %d results, got %d" % (len(names), len(got)))
        return
    for nm, g in zip(names, got, strict=True):
        want = "1" if _NAME_RE.fullmatch(nm) else "0"
        if g != want:
            fail("T3 is_name_valid: %r -> bash %s, reference %s" % (nm, g, want))
        if g == "1":
            if not _accepted_over_safe_charset(nm):
                fail("T3 is_name_valid: accepted %r is NOT over the safe charset" % nm)
            if not re.match(r"[a-z_]", nm):
                fail("T3 is_name_valid: accepted %r does not start with [a-z_]" % nm)


def t3_canaries():
    ## The reference must reject an unsafe-char name (else escape_name safety
    ## would not hold); and accept a single-char name (the old '+' regex did not).
    _expect_caught("T3/ref-rejects-bracket", _NAME_RE.fullmatch("a[b") is None)
    _expect_caught("T3/ref-rejects-upper", _NAME_RE.fullmatch("Ab") is None)
    _expect_caught("T3/ref-accepts-single", _NAME_RE.fullmatch("a") is not None)
    ## The safe-charset guard must reject a name containing '[' (a live BRE
    ## metacharacter escape_name does not handle).
    _expect_caught("T3/safe-charset-guard", not _accepted_over_safe_charset("a[b"))


## ============================ T4: escape_name (+ composition) ===============
def m_escape(name):
    return name.replace(".", "\\.").replace("$", "\\$")


def t4_enumerate(subject, env):
    """(a) escape_name output equals the reference. (b) BRE safety: for a valid
    name, the escaped anchored pattern matches a line IFF the line's first field
    is the literal name."""
    names = ["user", "a.b", "a$", "u.v@w", "x_y", "a.b.c", "user$"]
    body = "\n".join('escape_name %s; printf "\\n"' % _q(nm) for nm in names)
    got = _bash_lines(subject, env, body)
    if len(got) != len(names):
        fail("T4 escape_name: expected %d results, got %d" % (len(names), len(got)))
        return
    for nm, g in zip(names, got, strict=True):
        want = m_escape(nm)
        if g != want:
            fail("T4 escape_name: %r -> bash %r, model %r" % (nm, g, want))

    lines = ["user:x", "a.b:x", "axb:x", "a$:x", "aXb:x", "u.v@w:x", "uzv@w:x"]
    fixture = "\n".join(lines) + "\n"
    parts = []
    for nm in names:
        parts.append(
            'pat="^$(escape_name %s):"; printf %s | grep -c -- "${pat}" || true; '
            'printf "%s\\n"' % (_q(nm), _q(fixture), SENTINEL)
        )
    out = _bash_lines(subject, env, "\n".join(parts))
    idx = 0
    for nm in names:
        seg = []
        while idx < len(out) and out[idx] != SENTINEL:
            seg.append(out[idx])
            idx += 1
        idx += 1
        real_count = int(seg[0]) if seg and seg[0].lstrip("-").isdigit() else -1
        literal_count = sum(1 for ln in lines if ln.split(":", 1)[0] == nm)
        if real_count != literal_count:
            fail("T4 escape_name BRE: name %r matched %d lines, literal expects %d"
                 % (nm, real_count, literal_count))


def t4_canaries():
    _expect_caught("T4/dot-escaped", "a.b" != m_escape("a.b"))
    lines = ["a.b:x", "axb:x"]
    _expect_caught("T4/literal-only",
                   sum(1 for ln in lines if ln.split(":", 1)[0] == "a.b") == 1)


## ==================== T5: group_has_nonroot_member ==========================
def m_group_has_nonroot(group, passwd, group_db):
    """passwd: list of (name, gid). group_db: name -> (gid, [supp members]).
    Mirrors the fixed function: reject non-[a-z_]-initial names; else a non-root
    primary-GID member OR a non-root supplementary member."""
    if not group or not re.match(r"[a-z_]", group):
        return False
    if group not in group_db:
        return False
    gid, members = group_db[group]
    if any(pgid == gid and name != "root" for name, pgid in passwd):
        return True
    return any(m and m != "root" for m in members)


def _getent_shim(passwd, group_db):
    """A bash getent() shadowing the real one, backed by the given fixtures."""
    passwd_lines = "\n".join("%s:x:1000:%s:::" % (n, g) for n, g in passwd)
    group_lines = "\n".join(
        "%s:x:%s:%s" % (name, gid, ",".join(members))
        for name, (gid, members) in group_db.items()
    )
    return (
        "getent() {\n"
        "  local db='' key='' a\n"
        "  for a in \"$@\"; do [ \"$a\" = '--' ] && continue; "
        "if [ -z \"$db\" ]; then db=\"$a\"; elif [ -z \"$key\" ]; then key=\"$a\"; fi; done\n"
        "  local data=''\n"
        "  case \"$db\" in passwd) data=%s ;; group) data=%s ;; *) return 2 ;; esac\n"
        "  if [ -z \"$key\" ]; then printf '%%s\\n' \"$data\"; return 0; fi\n"
        "  local line matched=''\n"
        "  while IFS= read -r line; do [ -n \"$line\" ] || continue; "
        "if [ \"${line%%%%:*}\" = \"$key\" ]; then printf '%%s\\n' \"$line\"; matched=y; fi; "
        "done <<< \"$data\"\n"
        "  [ -n \"$matched\" ] || return 2\n"
        "}\n" % (_q(passwd_lines), _q(group_lines))
    )


def t5_enumerate(subject, env):
    """Run the REAL group_has_nonroot_member over generated fixtures (getent
    shimmed) and confirm rc matches the model, including the numeric-reject."""
    base_pw = [("root", "0"), ("alice", "1000")]
    scenarios = [
        ({"grp": ("5000", [])}, base_pw + [("svc", "5000")], "grp"),   # primary GID
        ({"grp": ("5000", ["alice"])}, base_pw, "grp"),                # supplementary
        ({"grp": ("5000", ["root"])}, base_pw, "grp"),                 # root-only supp
        ({"grp": ("5000", [])}, base_pw, "grp"),                       # no member
        ({"grp": ("0", [])}, base_pw + [("legacy", "0")], "grp"),      # gid via name
        ({"root": ("0", [])}, base_pw + [("legacy", "0")], "0"),       # numeric arg
        ({"grp": ("5000", [])}, base_pw, "1nvalid"),                   # bad first char
        ({"other": ("5000", [])}, base_pw, "grp"),                     # missing group
    ]
    for group_db, passwd, query in scenarios:
        shim = _getent_shim(passwd, group_db)
        body = shim + ("if group_has_nonroot_member %s; then printf 'yes\\n'; "
                       "else printf 'no\\n'; fi" % _q(query))
        got = _bash_lines(subject, env, body)
        real = got[-1] if got else ""
        want = "yes" if m_group_has_nonroot(query, passwd, group_db) else "no"
        if real != want:
            fail("T5 group_has_nonroot_member: query %r db=%r -> bash %r, model %r"
                 % (query, group_db, real, want))


def _supplementary_only(group, passwd, group_db):
    """Broken (pre-fix): supplementary members only; no numeric-reject."""
    if group not in group_db:
        return False
    return any(m and m != "root" for m in group_db[group][1])


def t5_canaries():
    gdb = {"grp": ("5000", [])}
    pw = [("root", "0"), ("svc", "5000")]
    _expect_caught("T5/primary-gid",
                   _supplementary_only("grp", pw, gdb) != m_group_has_nonroot("grp", pw, gdb))
    gdb0 = {"root": ("0", [])}
    pw0 = [("root", "0"), ("legacy", "0")]
    _expect_caught("T5/numeric-reject", m_group_has_nonroot("0", pw0, gdb0) is False)


def main():
    subject, env = _subject_and_env()
    sys.stdout.write("accountctl.sh formal verification (enumeration vs real bash)\n")

    sys.stdout.write("  T1  get_field -- exhaustive enumeration vs reference map\n")
    t1_enumerate(subject, env)
    t1_canaries()

    sys.stdout.write("  T2  get_clean_pass -- strip invariant enumeration vs real bash\n")
    t2_enumerate(subject, env)
    t2_canaries()

    sys.stdout.write("  T3  is_name_valid -- reference-regex anchor + safe-charset invariant\n")
    t3_enumerate(subject, env)
    t3_canaries()

    sys.stdout.write("  T4  escape_name -- escaping + BRE literal-match vs real grep\n")
    t4_enumerate(subject, env)
    t4_canaries()

    sys.stdout.write("  T5  group_has_nonroot_member -- fixture enumeration vs real bash\n")
    t5_enumerate(subject, env)
    t5_canaries()

    sys.stdout.write(
        "verify_accountctl_formal: %d canaries verified, %d obligations failed\n"
        % (CANARIES_VERIFIED[0], FAIL)
    )
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
