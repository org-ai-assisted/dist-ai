#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Formal verification of curl-prgrs' pure decision functions (Z3 + enumeration).

Two complementary methods per theorem, mirroring secure-terminal's verify_formal.py:
  - Z3 (SMT): prove a property over the SYMBOLIC input domain, on a Z3 model of
    the function's branch ladder.
  - ENUMERATION against the REAL bash: run the ACTUAL curl-prgrs functions
    (sourced from the checkout) over a bounded grid and confirm they match the
    Z3/reference model point-for-point -- this anchors the symbolic model to the
    real script, so the proof is about curl-prgrs, not a detached copy.
  - CANARIES: every method is also run against a deliberately BROKEN model and
    must catch it, so a green run has teeth.

Theorems:
  T1  compute_percent               -- result is always a whole number in 0..100;
                                        length 0 maps to 100 (no division by zero).
  T2  classify_download_size        -- the endless-data verdict is always one of
                                        {0, 81, 113, 114}, with the documented
                                        precedence (over-cap 81 beats over-length
                                        114 beats within-bounds 0; a non-whole
                                        size is 113).
  T3  remove_argument_for_header_request -- the output is always a subsequence of
                                        the input and every recognized flag is
                                        dropped together with its following value
                                        (exhaustive over bounded argv).
  T4  content_length_ceiling_for_phase -- the phase-selection feeding
                                        classify_download_size picks the hard cap
                                        for the header phase and the advertised
                                        length for the body phase; COMPOSED with
                                        classify, the header phase never yields 114
                                        (a large-but-legal header is not a false
                                        over-length failure).

SCOPE -- honest. Z3 proves the ARITHMETIC/logic over Bash's signed-64-bit-safe
domain (curl-prgrs bounds an advertised Content-Length to 16 digits, keeping
bytes*100 < 2**63; the proof assumes that bound, which the tool enforces). The
enumeration proves the real bash matches the model on the sampled grid, not the
whole 2**63 space. String-shaped facts (is_whole_number, the arg state machine)
are proved by enumeration, not Z3.

Exit 0 on a fully discharged proof, 1 on any counterexample, unmet assumption,
or model/real-code divergence. A missing z3 or the curl-prgrs subject is a hard
FAILURE (exit 1), never a silent skip -- a verification suite must not disable
itself.
"""

import itertools
import os
import re
import shlex
import subprocess
import sys

try:
    import z3
except Exception as exc:  # pylint: disable=broad-except  # noqa: BLE001 -- any z3 load failure (import or native lib) must FAIL clean
    sys.stderr.write(
        "helper-scripts-lib-tests(verify_curl_prgrs_formal): FAIL missing "
        "dependency (z3 / python3-z3): %s\n" % exc
    )
    sys.exit(1)


def _subject_and_env():
    repo = os.environ.get("HELPER_SCRIPTS_REPO", "").rstrip("/")
    base = repo if repo else ""
    subject = os.path.join(base or "/", "usr/libexec/helper-scripts/curl-prgrs")
    env = dict(os.environ)
    if base:
        env["HELPER_SCRIPTS_PATH"] = base
        env["PATH"] = os.path.join(base, "usr/bin") + os.pathsep + env.get("PATH", "")
    if not os.path.isfile(subject):
        sys.stderr.write(
            "helper-scripts-lib-tests(verify_curl_prgrs_formal): FAIL curl-prgrs "
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


def z3_prove(name, claim, assumptions=(), report=True):
    solver = z3.Solver()
    for assumption in assumptions:
        solver.add(assumption)
    solver.add(z3.Not(claim))
    result = solver.check()
    if result == z3.unsat:
        return True
    if not report:
        return False
    if result == z3.sat:
        fail("Z3 %s: COUNTEREXAMPLE %s" % (name, solver.model()))
    else:
        fail("Z3 %s: proof INCOMPLETE (solver returned %s)" % (name, result))
    return False


## --- reference models (the spec the Z3 proof and the real bash must both meet) ---

_WHOLE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_MAX16 = 10 ** 16 - 1
_STRIP_FLAGS = ("--continue-at", "-C", "--output", "-o")


def _is_whole(value):
    return _WHOLE.match(value) is not None


def m_compute_percent(bytes_v, length_v):
    if length_v <= 0:
        return 100
    p = bytes_v * 100 // length_v
    return 100 if p >= 100 else p


def m_classify(downloaded, max_v, cl_v):
    if not _is_whole(downloaded):
        return 113
    d = int(downloaded)
    if d > int(max_v):
        return 81
    if d > int(cl_v):
        return 114
    return 0


def m_ceiling(header_download, advertised, max_bytes):
    ## Header phase (exact "true") enforces the hard cap; every other value is the
    ## body phase and enforces the advertised length.
    if header_download == "true":
        return int(max_bytes)
    return int(advertised)


def m_strip(args):
    out = []
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a in _STRIP_FLAGS:
            skip = True
            continue
        out.append(a)
    return out


## --- output guards: the properties the enumeration asserts on the REAL bash.
## Named so the canaries below exercise the SAME predicate (no drift between the
## guard that gates a real run and the guard a canary claims to cover). ---

def _percent_in_range(text):
    ## _is_whole (ASCII decimal only), not str.isdigit(): isdigit() is True for
    ## non-decimal Unicode digits that int() then rejects, so the guard would
    ## crash on such output instead of rejecting it.
    return _is_whole(text) and 0 <= int(text) <= 100


def _verdict_ok(text):
    return text in ("0", "81", "113", "114")


## --- run the REAL bash functions over a batch (source curl-prgrs once) ---

def _bash_lines(subject, env, body):
    ## Feed the (large) batch through stdin, not argv -- an exhaustive enumeration
    ## exceeds ARG_MAX as a 'bash -c' argument. shlex.quote the subject so a
    ## checkout path with a space / quote / '$' cannot break or inject into the
    ## source command.
    full = "source %s\n%s\n" % (shlex.quote(subject), body)
    proc = subprocess.run(
        ["bash", "-s"], input=full, env=env, capture_output=True, text=True, timeout=120
    )
    if proc.returncode != 0 and not proc.stdout:
        fail("bash batch failed rc=%d: %s" % (proc.returncode, proc.stderr[-300:]))
    return proc.stdout.splitlines()


def _q(value):
    return "'" + str(value).replace("'", "'\\''") + "'"


## ============================ T1: compute_percent ============================

def t1_z3(broken=False):
    """0 <= compute_percent(bytes, length) <= 100 over the int64-safe domain, and
    length 0 -> 100. 'broken' proves a wrong model to give the canary teeth."""
    b = z3.Int("bytes")
    length = z3.Int("length")
    dom = [b >= 0, b <= _MAX16, length >= 0, length <= _MAX16]

    ratio = b * 100 / length            # Z3 Int division; guarded by length > 0
    clamped = z3.If(ratio >= 100, z3.IntVal(100), ratio)
    model = z3.If(length <= 0, z3.IntVal(100), clamped)
    if broken:
        model = z3.If(length <= 0, z3.IntVal(100), ratio)  # forgets the clamp

    in_range = z3.And(model >= 0, model <= 100)
    zero_len = z3.Implies(length == 0, model == 100)
    ok_range = z3_prove("T1-compute_percent-range", in_range, dom, report=not broken)
    ok_zero = z3_prove("T1-compute_percent-zero-length", zero_len, dom, report=not broken)
    return ok_range and ok_zero


def t1_enumerate(subject, env):
    """Run the REAL compute_percent over a grid and confirm it equals the model
    and stays in 0..100."""
    sizes = [0, 1, 2, 3, 7, 49, 50, 99, 100, 101, 500, 999, 1000, 10 ** 6, _MAX16 // 100]
    lengths = [1, 2, 3, 7, 49, 50, 99, 100, 101, 500, 1000, 10 ** 6, _MAX16]
    grid = [(b, length) for b in sizes for length in lengths]
    grid += [(b, 0) for b in sizes]     # the length-0 arm
    body = "\n".join('compute_percent %s %s; printf "\\n"' % (b, length) for b, length in grid)
    got = _bash_lines(subject, env, body)
    if len(got) != len(grid):
        fail("T1 enumerate: expected %d results, got %d" % (len(grid), len(got)))
        return
    for (b, length), g in zip(grid, got, strict=True):
        want = m_compute_percent(b, length)
        if g != str(want):
            fail("T1 enumerate: compute_percent %d %d -> bash %s, model %d" % (b, length, g, want))
        if not _percent_in_range(g):
            fail("T1 enumerate: compute_percent %d %d -> out-of-range %s" % (b, length, g))


def _unclamped_percent(bytes_v, length_v):
    """Broken: forgets the ceiling clamp, so bytes > length exceeds 100."""
    if length_v <= 0:
        return 100
    return bytes_v * 100 // length_v


def t1_canaries():
    _expect_caught("T1/z3-clamp", not t1_z3(broken=True))
    ## An unclamped compute_percent(200, 100) -> 200 must FAIL the range guard;
    ## if it were (wrongly) clamped, _percent_in_range accepts it and this fails.
    _expect_caught("T1/model-range", not _percent_in_range(str(_unclamped_percent(200, 100))))


## ========================= T2: classify_download_size =======================

def t2_z3(broken=False):
    """The numeric verdict (whole 'downloaded') is one of {0,81,114} with the
    documented precedence; 81 dominates 114 dominates 0."""
    d = z3.Int("d")
    mx = z3.Int("mx")
    cl = z3.Int("cl")
    dom = [d >= 0, d <= _MAX16, mx >= 0, mx <= _MAX16, cl >= 0, cl <= _MAX16]

    verdict = z3.If(d > mx, z3.IntVal(81), z3.If(d > cl, z3.IntVal(114), z3.IntVal(0)))
    if broken:
        verdict = z3.If(d > cl, z3.IntVal(114), z3.If(d > mx, z3.IntVal(81), z3.IntVal(0)))

    in_set = z3.Or(verdict == 0, verdict == 81, verdict == 114)
    over_cap = z3.Implies(d > mx, verdict == 81)          # cap beats everything
    within = z3.Implies(z3.And(d <= mx, d <= cl), verdict == 0)
    ok1 = z3_prove("T2-classify-verdict-set", in_set, dom, report=not broken)
    ok2 = z3_prove("T2-classify-cap-precedence", over_cap, dom, report=not broken)
    ok3 = z3_prove("T2-classify-within-bounds", within, dom, report=not broken)
    return ok1 and ok2 and ok3


def t2_enumerate(subject, env):
    """Run the REAL classify_download_size over a grid, including NON-whole sizes
    (the 113 path Z3 does not model), and confirm it matches the model and the
    {0,81,113,114} verdict set."""
    numeric = [0, 1, 2, 50, 99, 100, 101, 500, 1000]
    garbage = ["x", "-1", "07", "1a", "", " 5", "3.0"]
    sizes = [str(n) for n in numeric] + garbage
    caps = [0, 1, 100, 500, 1000]
    cls = [0, 1, 100, 500, 1000]
    grid = [(s, mx, cl) for s in sizes for mx in caps for cl in cls]
    body = "\n".join(
        'classify_download_size %s %s %s; printf "\\n"' % (_q(s), mx, cl)
        for s, mx, cl in grid
    )
    got = _bash_lines(subject, env, body)
    if len(got) != len(grid):
        fail("T2 enumerate: expected %d results, got %d" % (len(grid), len(got)))
        return
    for (s, mx, cl), g in zip(grid, got, strict=True):
        want = m_classify(s, mx, cl)
        if g != str(want):
            fail("T2 enumerate: classify %r %d %d -> bash %s, model %d" % (s, mx, cl, g, want))
        if not _verdict_ok(g):
            fail("T2 enumerate: classify %r %d %d -> bad verdict %s" % (s, mx, cl, g))


def _bogus_verdict_classify(downloaded, max_v, cl_v):
    """Broken: emits an undocumented verdict for the non-whole (113) path."""
    if not _is_whole(downloaded):
        return 999
    return m_classify(downloaded, max_v, cl_v)


def t2_canaries():
    _expect_caught("T2/z3-precedence", not t2_z3(broken=True))
    ## A classify that emits an undocumented verdict for garbage input must FAIL
    ## the verdict-set guard; a model returning a real {0,81,113,114} would pass
    ## it and this canary would fail.
    _expect_caught("T2/verdict-set", not _verdict_ok(str(_bogus_verdict_classify("x", 100, 100))))


## ================== T3: remove_argument_for_header_request ==================

def _is_subsequence(sub, whole):
    it = iter(whole)
    return all(item in it for item in sub)


def t3_enumerate(subject, env):
    """Exhaustive over argv up to length 4 from a flag alphabet: the REAL output
    equals the model, is a subsequence of the input, and drops every recognized
    flag with the value after it."""
    alphabet = ["-o", "--output", "-C", "--continue-at", "url", "-sSL"]
    combos = []
    for n in range(0, 5):
        combos.extend(itertools.product(alphabet, repeat=n))
    sentinel = "==CPSPLIT=="
    parts = []
    for args in combos:
        argv = " ".join(_q(a) for a in args)
        parts.append(
            'remove_argument_for_header_request %s; printf "%%s\\n" "${header_arguments[@]}"; '
            'printf "%%s\\n" %s' % (argv, _q(sentinel))
        )
    ## One bash run for the whole enumeration; per-combo outputs are delimited by
    ## the sentinel line.
    flat = _bash_lines(subject, env, "\n".join(parts))
    idx = 0
    for args in combos:
        out = []
        while idx < len(flat) and flat[idx] != sentinel:
            out.append(flat[idx])
            idx += 1
        idx += 1  # skip sentinel
        want = list(m_strip(args))
        # bash prints an empty array as a single blank line; normalize.
        if want == [] and out == [""]:
            out = []
        if out != want:
            fail("T3 enumerate: strip %r -> bash %r, model %r" % (list(args), out, want))
        if not _is_subsequence(out, list(args)):
            fail("T3 enumerate: strip %r -> %r is not a subsequence" % (list(args), out))


def _leaky_strip(args):
    """Broken: drops the recognized flag but KEEPS the value that follows it."""
    return [a for a in args if a not in _STRIP_FLAGS]


def _injecting_strip(args):
    """Broken: appends an argument absent from the input (not a subsequence)."""
    return [*m_strip(args), "--injected"]


def t3_canaries():
    ## A strip that keeps a flag's value (["-o","/f","url"] -> ["/f","url"]) must
    ## DIFFER from the correct model ["url"] -- the enumeration's equality guard
    ## catches it; if _leaky_strip also dropped the value this canary would fail.
    _expect_caught("T3/model-strip",
                   _leaky_strip(["-o", "/f", "url"]) != m_strip(["-o", "/f", "url"]))
    ## A strip that injects an argument must FAIL the subsequence guard.
    _expect_caught("T3/model-subseq",
                   not _is_subsequence(_injecting_strip(["-o", "/f", "url"]), ["-o", "/f", "url"]))


## ============= T4: content_length_ceiling_for_phase (+ composition) ==========

def t4_z3(broken=False):
    """The phase-selection feeding classify_download_size is correct:
      - header phase selects the hard cap (max_bytes), body phase the advertised
        length;
      - COMPOSED with classify_download_size, the header phase can NEVER yield 114
        (an over-advertised verdict) -- only 0 (<= cap) or 81 (> cap) -- so a
        large-but-legal header is never a false over-length failure. This is the
        property the estimate-as-ceiling bug violated.
    'broken' makes the header phase enforce the estimate, which the canary catches."""
    d = z3.Int("d")
    adv = z3.Int("adv")
    mx = z3.Int("mx")
    dom = [d >= 0, d <= _MAX16, adv >= 0, adv <= _MAX16, mx >= 0, mx <= _MAX16]

    header_ceiling = adv if broken else mx     # BUG: header enforces the estimate
    body_ceiling = adv

    def classify(cl):
        ## classify_download_size for a WHOLE d: over-cap 81 beats over-length 114.
        return z3.If(d > mx, z3.IntVal(81), z3.If(d > cl, z3.IntVal(114), z3.IntVal(0)))

    sel_header = header_ceiling == mx
    sel_body = body_ceiling == adv
    header_never_114 = z3.Not(classify(header_ceiling) == 114)

    ok_h = z3_prove("T4-ceiling-header-is-cap", sel_header, dom, report=not broken)
    ok_b = z3_prove("T4-ceiling-body-is-advertised", sel_body, dom, report=not broken)
    ok_no114 = z3_prove("T4-header-never-114", header_never_114, dom, report=not broken)
    return ok_h and ok_b and ok_no114


def t4_enumerate(subject, env):
    """Run the REAL content_length_ceiling_for_phase over a grid (confirm it equals
    the model, using EXACT 'true' for the header phase), then drive the REAL
    composed pipeline (ceiling -> classify) and confirm the header phase never
    yields 114 for a size within the cap."""
    ## (a) the selection function itself.
    phases = ["true", "false", "", "TRUE", "yes"]     # only exact "true" is header
    advs = [0, 1, 100, 8000, 32000]
    caps = [0, 1, 100, 8000, 32000]
    grid = [(h, a, m) for h in phases for a in advs for m in caps]
    body = "\n".join(
        'content_length_ceiling_for_phase %s %s %s; printf "\\n"' % (_q(h), a, m)
        for h, a, m in grid
    )
    got = _bash_lines(subject, env, body)
    if len(got) != len(grid):
        fail("T4 enumerate: expected %d ceiling results, got %d" % (len(grid), len(got)))
        return
    for (h, a, m), g in zip(grid, got, strict=True):
        want = m_ceiling(h, a, m)
        if g != str(want):
            fail("T4 enumerate: ceiling %r %d %d -> bash %s, model %d" % (h, a, m, g, want))

    ## (b) composition on the REAL pipeline: header phase, size between the
    ## advertised estimate and the cap must classify 0 (never 114); size over the
    ## cap must be 81. This is the estimate-as-ceiling bug scenario, on real bash.
    cap = 32000
    est = 8000
    sizes = [0, est, est + 1, 9000, cap, cap + 1, cap + 5000]
    comp = "\n".join(
        'cl="$(content_length_ceiling_for_phase true %s %s)"; '
        'classify_download_size %s %s "${cl}"; printf "\\n"' % (est, cap, s, cap)
        for s in sizes
    )
    comp_got = _bash_lines(subject, env, comp)
    if len(comp_got) != len(sizes):
        fail("T4 compose: expected %d results, got %d" % (len(sizes), len(comp_got)))
        return
    for s, g in zip(sizes, comp_got, strict=True):
        want = 81 if s > cap else 0            # header phase: 0 within cap, 81 over
        if g != str(want):
            fail("T4 compose: header size %d (est %d cap %d) -> bash %s, want %d"
                 % (s, est, cap, g, want))
        if g == "114":
            fail("T4 compose: header size %d wrongly classified over-length (114)" % s)


def _estimate_ceiling(header_download, advertised, max_bytes):
    """Broken: header phase enforces the estimate (advertised), reintroducing 114."""
    return int(advertised)


def t4_canaries():
    _expect_caught("T4/z3-header-cap", not t4_z3(broken=True))
    ## With the broken estimate ceiling, a header size between the estimate and the
    ## cap classifies 114; the correct cap ceiling gives 0. The composition guard
    ## must catch that 114.
    broken_cl = _estimate_ceiling("true", 8000, 32000)
    _expect_caught("T4/compose-no-114", m_classify("9000", 32000, broken_cl) == 114)


def main():
    subject, env = _subject_and_env()
    sys.stdout.write("curl-prgrs formal verification (Z3 %s)\n" % z3.get_version_string())

    sys.stdout.write("  T1  compute_percent -- Z3 range + zero-length\n")
    t1_z3()
    sys.stdout.write("  T1  compute_percent -- enumeration vs real bash\n")
    t1_enumerate(subject, env)
    t1_canaries()

    sys.stdout.write("  T2  classify_download_size -- Z3 verdict set + precedence\n")
    t2_z3()
    sys.stdout.write("  T2  classify_download_size -- enumeration vs real bash\n")
    t2_enumerate(subject, env)
    t2_canaries()

    sys.stdout.write("  T3  remove_argument_for_header_request -- exhaustive enumeration\n")
    t3_enumerate(subject, env)
    t3_canaries()

    sys.stdout.write("  T4  content_length_ceiling_for_phase -- Z3 selection + no-114 composition\n")
    t4_z3()
    sys.stdout.write("  T4  content_length_ceiling_for_phase -- enumeration + real pipeline\n")
    t4_enumerate(subject, env)
    t4_canaries()

    sys.stdout.write(
        "verify_curl_prgrs_formal: %d canaries verified, %d obligations failed\n"
        % (CANARIES_VERIFIED[0], FAIL)
    )
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
