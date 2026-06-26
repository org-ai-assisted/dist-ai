#!/usr/bin/env python3
"""
Faithful in-process test harness for the Whonix onion-grater Tor control
port filter profiles.

It imports the REAL onion-grater filtering code from the derivative-maker
checkout (profile normalization, the get_rule regex matcher, and the
command/response rewriters) and replays each application's Tor control
command sequence through it, asserting that:

  * the legitimate commands each app sends are ALLOWED (proxied to Tor), and
  * crafted argument-injection variants are BLOCKED (510 Command filtered).

It also reproduces the two fixed security bugs by running the historical
(vulnerable) patterns through the same real matcher and showing the new
patterns block what the old ones allowed, with no regression for the
legitimate form.

No root, no network, no real Tor is needed. The only stubbed component is
Tor itself, which is exactly the component a test must not mutate. The
security boundary in onion-grater is get_rule() returning None (-> filter_line
-> "510 Command filtered") versus returning a rule (-> proxy_line -> the line
is sent to Tor verbatim or after the rule's replacement rewrite). That real
code path is what this harness exercises.

Override the checkout location with ONION_GRATER_REPO if it is not at the
default path.
"""

import importlib.machinery
import importlib.util
import os
import sys

def _resolve_onion_grater():
    """Locate the onion-grater script + example profiles: ONION_GRATER_REPO
    override, else the installed package, else a derivative-maker checkout."""
    repo = os.environ.get("ONION_GRATER_REPO")
    if repo:
        return (os.path.join(repo, "usr/lib/onion-grater"),
                os.path.join(repo, "usr/share/doc/onion-grater-merger/examples"))
    if os.path.exists("/usr/lib/onion-grater"):
        return ("/usr/lib/onion-grater",
                "/usr/share/doc/onion-grater-merger/examples")
    repo = "/home/user/derivative-maker/packages/whonix/onion-grater"
    return (os.path.join(repo, "usr/lib/onion-grater"),
            os.path.join(repo, "usr/share/doc/onion-grater-merger/examples"))


MODULE_PATH, PROFILE_DIR = _resolve_onion_grater()

# Service ids used as legitimate v3 onion addresses in the test vectors.
ADDR = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd"
AUTH_ADDR = "m5bmcnsk64naezc26scz2xb3l3n2nd5xobsljljrpvf77tclmykn7wid"
AUTH_KEY = "x25519:uBKh6DGrkcFxB1adYuyKQltUDDUT9IZrOsne3nfHbHI="
# A relay fingerprint shape for HSFETCH SERVER= options.
FPR = "$FEDCBA9876543210FEDCBA9876543210FEDCBA98"


def fail(msg):
    print("FATAL: " + msg, file=sys.stderr)
    raise SystemExit(2)


def load_onion_grater():
    if not os.path.isfile(MODULE_PATH):
        # Exit 77 -> "skipped" in the automake/TAP convention the runner uses.
        print("SKIP: onion-grater module not found at " + MODULE_PATH)
        print("      set ONION_GRATER_REPO to the derivative-maker checkout.")
        raise SystemExit(77)
    loader = importlib.machinery.SourceFileLoader("onion_grater", MODULE_PATH)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


og = load_onion_grater()
yaml = og.yaml
Handler = og.FilteredControlPortProxyHandler
Session = og.FilteredControlPortProxySession


def build_commands(commands, confs=None):
    """Run profile command/conf dicts through the real normalizer."""
    handler = Handler.__new__(Handler)
    handler.allowed_commands = {}
    handler.add_allowed_commands(dict(commands) if commands else {})
    handler.add_allowed_confs_commands(dict(confs) if confs else {})
    return handler.allowed_commands


def build_events(events):
    handler = Handler.__new__(Handler)
    handler.allowed_events = {}
    handler.add_allowed_events(dict(events) if events else {})
    return handler.allowed_events


def decide(allowed_commands, cmd, arg_str):
    """Mirror onion-grater's generic-command dispatch: rule found -> proxied
    to Tor (ALLOW), rule None -> filter_line (BLOCK)."""
    session = Session.__new__(Session)
    session.allowed_commands = allowed_commands
    rule = Session.get_rule(session, cmd.upper(), arg_str)
    return "ALLOW" if rule is not None else "BLOCK"


def decide_setevents(allowed_events, arg_str):
    """Mirror the dedicated SETEVENTS branch (handle(), line ~514)."""
    events = [event.upper() for event in arg_str.split()]
    ok = all(event in allowed_events for event in events)
    return "ALLOW" if ok else "BLOCK"


def rewrite_response(replacers, lines):
    """Drive the real response rewriter (rewrite_matched_lines)."""
    session = Session.__new__(Session)
    session.client_address = ("127.0.0.1", 0)
    session.server_address = ("127.0.0.1", 0)
    return Session.rewrite_matched_lines(session, replacers, lines)


def load_profile(name):
    with open(os.path.join(PROFILE_DIR, name), "rb") as handle:
        docs = [doc for doc in yaml.safe_load_all(handle) if doc]
    entry = docs[-1][0]
    return (
        entry.get("commands") or {},
        entry.get("confs") or {},
        entry.get("events") or {},
    )


# --------------------------------------------------------------------------
# Per-profile test vectors. Each entry: (cmd, arg_str, expected).
# Legitimate forms (ALLOW) are taken from the profile patterns / app behaviour;
# injection forms (BLOCK) append extra space-separated tokens, the class of
# bug fixed in the Bisq SETCONF rule.
# --------------------------------------------------------------------------

PROFILE_CASES = {
    "40_bisq.yml": [
        ("GETINFO", "status/bootstrap-phase", "ALLOW"),
        ("GETINFO", "status/bootstrap-phase ns/all", "BLOCK"),
        ("ADD_ONION", "NEW:ED25519-V3 Port=9999,9999", "ALLOW"),
        ("ADD_ONION", "NEW:ED25519-V3 Port=9999,9999 Flags=Detach", "BLOCK"),
        ("DEL_ONION", ADDR, "ALLOW"),
        ("DEL_ONION", ADDR + " SETCONF DisableNetwork=0", "BLOCK"),
        ("HSFETCH", ADDR, "ALLOW"),
        ("HSFETCH", ADDR + " SERVER=" + FPR, "ALLOW"),
        ("HSFETCH", ADDR + " DisableNetwork=0", "BLOCK"),
        ("SETCONF", "DisableNetwork=0", "ALLOW"),
        ("SETCONF", "DisableNetwork=1", "ALLOW"),
        ("SETCONF", "DisableNetwork=2", "BLOCK"),
        ("SETCONF", "DisableNetwork=0 Socks5Proxy=10.0.0.1:9050", "BLOCK"),
    ],
    "40_cwtch.yml": [
        ("GETINFO", "network-liveness", "ALLOW"),
        ("GETINFO", "status/bootstrap-phase", "ALLOW"),
        ("GETCONF", "DisableNetwork", "ALLOW"),
        ("GETCONF", "DisableNetwork SocksPort", "BLOCK"),
        ("ADD_ONION",
         "ED25519-V3:AAAA Flags=DiscardPK,Detach Port=9878,[::]:15000", "ALLOW"),
        ("ADD_ONION",
         "ED25519-V3:AAAA Flags=DiscardPK,Detach Port=9878,[::]:15378", "ALLOW"),
        ("ADD_ONION",
         "ED25519-V3:AAAA Flags=DiscardPK,Detach Port=9878,[::]:15999", "BLOCK"),
        ("DEL_ONION", ADDR, "ALLOW"),
        ("DEL_ONION", ADDR + " evil", "BLOCK"),
        ("HSFETCH", ADDR, "ALLOW"),
        ("HSFETCH", ADDR + " SERVER=" + FPR, "ALLOW"),
        ("HSFETCH", ADDR + " Bridge=1.2.3.4", "BLOCK"),
    ],
    "40_haveno.yml": [
        ("AUTHCHALLENGE", "SAFECOOKIE deadbeefcafe1234", "ALLOW"),
        ("AUTHCHALLENGE", "SAFECOOKIE deadbeef SETCONF Socks5Proxy=x", "BLOCK"),
        ("GETINFO", "status/bootstrap-phase", "ALLOW"),
        ("GETINFO", "net/listeners/socks", "ALLOW"),
        ("ADD_ONION", "NEW:ED25519-V3 Port=9999,9999", "ALLOW"),
        ("DEL_ONION", ADDR, "ALLOW"),
        ("DEL_ONION", ADDR + " SETCONF DisableNetwork=0", "BLOCK"),
        ("HSFETCH", ADDR, "ALLOW"),
        ("HSFETCH", ADDR + " SERVER=" + FPR + " SERVER=" + FPR, "ALLOW"),
        ("HSFETCH", ADDR + " Socks5Proxy=x", "BLOCK"),
    ],
    "40_lnd.yml": [
        # lnd's patterns intentionally end with a trailing space.
        ("ADD_ONION", "NEW:ED25519-V3 Port=9735,9735 ", "ALLOW"),
        ("ADD_ONION", "NEW:ED25519-V3 Port=9911,9911 ", "ALLOW"),
        ("ADD_ONION", "NEW:ED25519-V3 Port=9735,9735 Flags=Detach", "BLOCK"),
        ("DEL_ONION", ADDR, "ALLOW"),
        ("DEL_ONION", ADDR + " evil", "BLOCK"),
    ],
    "40_onion_authentication.yml": [
        # Legitimate forms: x25519 key, optionally ClientName= and/or Flags=,
        # in the order the profile pattern requires.
        ("onion_client_auth_add", AUTH_ADDR + " " + AUTH_KEY, "ALLOW"),
        ("onion_client_auth_add",
         AUTH_ADDR + " " + AUTH_KEY + " ClientName=alice", "ALLOW"),
        ("onion_client_auth_add",
         AUTH_ADDR + " " + AUTH_KEY + " Flags=Permanent", "ALLOW"),
        ("onion_client_auth_add",
         AUTH_ADDR + " " + AUTH_KEY + " ClientName=alice Flags=Permanent",
         "ALLOW"),
        # Optional parameters in the WRONG order: ClientName= must precede
        # Flags=, so the leftover token defeats the full match.
        ("onion_client_auth_add",
         AUTH_ADDR + " " + AUTH_KEY + " Flags=Permanent ClientName=alice",
         "BLOCK"),
        # The mandatory credential must be an x25519 key, not another
        # algorithm or arbitrary junk, and it cannot be omitted.
        ("onion_client_auth_add", AUTH_ADDR + " ed25519:AAAA", "BLOCK"),
        ("onion_client_auth_add", AUTH_ADDR + " evil:blob", "BLOCK"),
        ("onion_client_auth_add", AUTH_ADDR, "BLOCK"),
        # Argument injection: an extra control command appended directly, or
        # appended after an accepted optional parameter, must be filtered.
        ("onion_client_auth_add",
         AUTH_ADDR + " " + AUTH_KEY + " SETCONF Bridge=1.2.3.4", "BLOCK"),
        ("onion_client_auth_add",
         AUTH_ADDR + " " + AUTH_KEY + " ClientName=alice SETCONF "
         "DisableNetwork=0", "BLOCK"),
        ("onion_client_auth_add",
         AUTH_ADDR + " " + AUTH_KEY + " Flags=Permanent SETCONF "
         "DisableNetwork=0", "BLOCK"),
    ],
    "40_onionshare.yml": [
        ("GETINFO", "onions/current", "ALLOW"),
        ("GETINFO", "status/bootstrap-phase", "ALLOW"),
        ("GETCONF", "hiddenservicesinglehopmode", "ALLOW"),
        ("ADD_ONION", "NEW:ED25519-V3 Port=80,17600", "ALLOW"),
        ("ADD_ONION", "NEW:ED25519-V3 Port=80,17600 Flags=Detach", "BLOCK"),
        ("DEL_ONION", ADDR, "ALLOW"),
        ("DEL_ONION", ADDR + " SETCONF DisableNetwork=0", "BLOCK"),
    ],
    "40_ricochet.yml": [
        ("GETINFO",
         "status/circuit-established status/bootstrap-phase net/listeners/socks",
         "ALLOW"),
        ("GETCONF", "DisableNetwork", "ALLOW"),
        ("GETCONF", "DisableNetwork SocksPort", "BLOCK"),
        ("ADD_ONION", "NEW:ED25519-V3 Port=9878,127.0.0.1:11009", "ALLOW"),
        ("DEL_ONION", ADDR, "ALLOW"),
        ("DEL_ONION", ADDR + " evil", "BLOCK"),
    ],
    "40_wahay.yml": [
        ("ADD_ONION",
         "NEW:ED25519-V3 Port=8181,127.0.0.1:8181 Port=64738,127.0.0.1:64738",
         "ALLOW"),
        ("DEL_ONION", ADDR, "ALLOW"),
        ("DEL_ONION", ADDR + " evil", "BLOCK"),
        ("GETINFO", "version", "ALLOW"),
    ],
    "40_zeronet.yml": [
        ("ADD_ONION", "NEW:ED25519-V3 Port=15441,15441", "ALLOW"),
        ("ADD_ONION", "NEW:ED25519-V3 port=15441", "ALLOW"),
        ("GETCONF", "hiddenservicesinglehopmode", "ALLOW"),
        ("DEL_ONION", ADDR, "ALLOW"),
        ("DEL_ONION", ADDR + " evil", "BLOCK"),
    ],
}

SETEVENTS_CASES = {
    "40_cwtch.yml": [
        ("CIRC WARN ERR", "ALLOW"),
        ("CIRC ORCONN INFO NOTICE WARN ERR HS_DESC HS_DESC_CONTENT", "ALLOW"),
        ("CIRC WARN ERR DEBUG", "BLOCK"),
    ],
    "40_haveno.yml": [
        ("CIRC ORCONN INFO NOTICE WARN ERR HS_DESC HS_DESC_CONTENT", "ALLOW"),
        ("DEBUG", "BLOCK"),
    ],
}


# --------------------------------------------------------------------------
# Test runner.
# --------------------------------------------------------------------------

class Results:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def check(self, label, got, expected):
        if got == expected:
            self.passed += 1
        else:
            self.failed += 1
            print("  FAIL: {0}: expected {1}, got {2}".format(
                label, expected, got))


def run_profile_cases(results):
    print("== shipped profiles: legitimate commands allowed, injection blocked ==")
    for name, cases in PROFILE_CASES.items():
        commands, confs, _events = load_profile(name)
        allowed = build_commands(commands, confs)
        for cmd, arg, expected in cases:
            got = decide(allowed, cmd, arg)
            results.check("{0} {1} {2!r}".format(name, cmd, arg), got, expected)
    for name, cases in SETEVENTS_CASES.items():
        _commands, _confs, events = load_profile(name)
        allowed_events = build_events(events)
        for arg, expected in cases:
            got = decide_setevents(allowed_events, arg)
            results.check("{0} SETEVENTS {1!r}".format(name, arg),
                          got, expected)


def run_reproductions(results):
    print("== reproduction: each fixed pattern, old (vulnerable) vs new ==")
    # (label, cmd, old_pattern, new_pattern, attack_arg, legit_arg)
    repros = [
        ("Bisq SETCONF deanon (a0bc80d)", "SETCONF",
         "DisableNetwork.*", "DisableNetwork=[01]",
         "DisableNetwork=0 Socks5Proxy=10.0.0.1:9050", "DisableNetwork=0"),
        ("DEL_ONION", "DEL_ONION",
         ".+", r"\S+",
         ADDR + " SETCONF DisableNetwork=0", ADDR),
        ("HSFETCH", "HSFETCH",
         ".+", r"\S+( SERVER=\S+)*",
         ADDR + " DisableNetwork=0", ADDR + " SERVER=" + FPR),
        ("onion_client_auth_add", "onion_client_auth_add",
         ".+", r"\S+ x25519:\S+( ClientName=\S+)?( Flags=\S+)?",
         AUTH_ADDR + " " + AUTH_KEY + " SETCONF Bridge=1.2.3.4",
         AUTH_ADDR + " " + AUTH_KEY),
        ("AUTHCHALLENGE", "AUTHCHALLENGE",
         "SAFECOOKIE .*", r"SAFECOOKIE \S+",
         "SAFECOOKIE deadbeef SETCONF Socks5Proxy=x", "SAFECOOKIE deadbeef"),
    ]
    for label, cmd, old_pat, new_pat, attack, legit in repros:
        old = build_commands({cmd: [{"pattern": old_pat}]})
        new = build_commands({cmd: [{"pattern": new_pat}]})
        # The bug: the old pattern lets the injection through to Tor.
        results.check(label + ": OLD allows injection (bug reproduced)",
                      decide(old, cmd, attack), "ALLOW")
        # The fix: the new pattern blocks the injection.
        results.check(label + ": NEW blocks injection (fixed)",
                      decide(new, cmd, attack), "BLOCK")
        # No regression: the legitimate form is still allowed.
        results.check(label + ": NEW allows legitimate form",
                      decide(new, cmd, legit), "ALLOW")


def run_bootstrap_rewrite(results):
    print("== reproduction: bootstrap-phase response rewrite typo (=* -> =.*) ==")
    reply = ('250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=30 '
             'TAG=conn SUMMARY="x"\r\n')
    done = "PROGRESS=100 TAG=done"
    old_rule = [{"pattern": "250-status/bootstrap-phase=*",
                 "replacement": ('250-status/bootstrap-phase=NOTICE BOOTSTRAP '
                                 'PROGRESS=100 TAG=done SUMMARY="Done"')}]
    new_rule = [{"pattern": "250-status/bootstrap-phase=.*",
                 "replacement": ('250-status/bootstrap-phase=NOTICE BOOTSTRAP '
                                 'PROGRESS=100 TAG=done SUMMARY="Done"')}]
    # Old typo pattern never matches the real reply, so it is left unchanged.
    results.check("OLD '=*' leaves real reply unrewritten (dead code)",
                  done in rewrite_response(old_rule, reply), False)
    # New pattern matches and forces the bootstrapped reply.
    results.check("NEW '=.*' rewrites reply to bootstrapped",
                  done in rewrite_response(new_rule, reply), True)
    # And the shipped profile now carries the working pattern.
    commands, _confs, _events = load_profile("40_bisq.yml")
    rule = commands["GETINFO"][0]["response"]
    results.check("shipped bisq bootstrap rewrite works on real reply",
                  done in rewrite_response(rule, reply), True)


def main():
    print("onion-grater profile test harness")
    print("onion-grater: " + MODULE_PATH)
    print("profiles:     " + PROFILE_DIR)
    print()
    results = Results()
    run_profile_cases(results)
    run_reproductions(results)
    run_bootstrap_rewrite(results)
    print()
    total = results.passed + results.failed
    print("{0}/{1} checks passed".format(results.passed, total))
    if results.failed:
        print("RESULT: FAIL ({0} failed)".format(results.failed))
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
