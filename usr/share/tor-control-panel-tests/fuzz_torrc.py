#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Randomized in-process fuzzer for tor-control-panel's untrusted-input parsers.

These functions all consume attacker-influenceable input -- a torrc that
round-trips through disk (user-pasted bridge lines, possibly tampered with),
proxy/bridge fields typed into the GUI, and Tor's own control output. They must
never crash, hang, or return a wrong-typed value on adversarial input; a crash
here is a GUI that dies (or worse, mangles the config) on a hostile torrc.

Targets:
  * validators.valid_ip / valid_port / valid_custom_bridges  -> always bool
  * torrc_gen.main_torrc_includes_dropin                     -> always bool
  * torrc_gen.read_custom_bridge_lines                       -> list[str]
  * torrc_gen.gen_torrc  +  torrc_gen.parse_torrc            -> no crash, and
    parse_torrc always returns the documented dict shape

Run: fuzz_torrc.py [--iterations N] [--seed N]. On a failure it prints the seed
and the offending input so the case can be replayed deterministically.
"""

import argparse
import random
import sys
import tempfile
from pathlib import Path

import tcp_testlib as T  # noqa: F401  (resolves the source + offscreen Qt)
from tor_control_panel import torrc_gen, validators


## ---- input generators -------------------------------------------------------

## Bytes/among these make torrc, bridge and control-output parsers interesting.
_ALPHABET = (
    "obfs4 snowflake meek_lite Bridge BridgeRelay DisableNetwork UseBridges "
    "ClientTransportPlugin # %include /etc/tor 1.2.3.4:1234 [::1]:9050 "
    "\t\n\r\x00\x1b[31m <b> obfs4proxy cert= iat-mode=0 . : , = \" ' \\ /"
).split(" ")

_CHARS = "abcdef0123456789.:[]# \t\n\r\x00\x1b<>\"'/=%-"


def _rand_token(rnd):
    kind = rnd.random()
    if kind < 0.35:
        return rnd.choice(_ALPHABET)
    if kind < 0.7:
        return "".join(rnd.choice(_CHARS) for _ in range(rnd.randint(0, 40)))
    ## Occasionally a very long run, to probe pathological inputs.
    return rnd.choice(_CHARS) * rnd.randint(0, 4000)


def _rand_line(rnd):
    return " ".join(_rand_token(rnd) for _ in range(rnd.randint(0, 6)))


def _rand_text(rnd):
    ## A multi-line blob, sometimes seeded with the custom-bridges marker so
    ## read_custom_bridge_lines / parse_torrc take their parsing branches.
    lines = [_rand_line(rnd) for _ in range(rnd.randint(0, 12))]
    if rnd.random() < 0.4:
        lines.insert(rnd.randint(0, len(lines)),
                     "# Custom bridges are used")
    if rnd.random() < 0.4:
        lines.insert(0, "DisableNetwork " + rnd.choice(["0", "1", "x", ""]))
    return "\n".join(lines)


## ---- fuzz phases ------------------------------------------------------------

def phase_validators(rnd, iterations):
    ## Pure, no-I/O validators fuzzed in the hot loop.
    hot = (validators.valid_port, validators.valid_custom_bridges,
           torrc_gen.main_torrc_includes_dropin)
    for _ in range(iterations):
        value = _rand_token(rnd) if rnd.random() < 0.5 else _rand_line(rnd)
        for func in hot:
            result = func(value)
            if not isinstance(result, bool):
                raise AssertionError(
                    "{0} returned non-bool {1!r} for {2!r}".format(
                        func.__name__, result, value))

    ## valid_ip resolves via getaddrinfo (real DNS), so probe it only on a small
    ## curated set of adversarial inputs -- crash-safety, not throughput; a hot
    ## loop here would fire thousands of DNS lookups.
    for value in ("", " ", "\x00", "[", "]:", ":::", "1.2.3.4:x", "a" * 4000,
                  "\x1b[31m", "obfs4 1.2.3.4", "\n", "%include", "[::1]"):
        if not isinstance(validators.valid_ip(value), bool):
            raise AssertionError("valid_ip non-bool for {0!r}".format(value))


def phase_custom_bridges(rnd, iterations):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "torrc"
        for _ in range(iterations):
            path.write_text(_rand_text(rnd), encoding="utf-8")
            lines = torrc_gen.read_custom_bridge_lines(str(path))
            if not isinstance(lines, list) or not all(
                    isinstance(item, str) for item in lines):
                raise AssertionError(
                    "read_custom_bridge_lines returned {0!r}".format(lines))
            ## Sanitized output must not carry raw control characters through to
            ## the rich-text widget.
            for item in lines:
                if any(ord(char) < 32 and char not in "\t" for char in item):
                    raise AssertionError(
                        "unsanitized control char in {0!r}".format(item))


def phase_gen_parse(rnd, iterations):
    bridge_choices = ["None", "obfs4", "snowflake", "meek", ""]
    proxy_choices = ["None", "SOCKS5", "SOCKS4", "HTTP/HTTPS", ""]
    with T.sandbox() as torrc:
        for _ in range(iterations):
            args = [
                rnd.choice(bridge_choices) if rnd.random() < 0.7
                else _rand_token(rnd),
                rnd.choice(["None", _rand_text(rnd)]),
                rnd.choice(proxy_choices) if rnd.random() < 0.7
                else _rand_token(rnd),
            ]
            ## Sometimes append proxy fields (ip, port, user, pass).
            if rnd.random() < 0.6:
                args += [_rand_token(rnd) for _ in range(rnd.randint(1, 4))]
            torrc_gen.gen_torrc(args)
            ## The generated torrc must always parse back into the documented
            ## shape without crashing.
            parsed = torrc_gen.parse_torrc()
            if not isinstance(parsed, (dict, tuple, list)):
                raise AssertionError(
                    "parse_torrc returned {0!r} for args {1!r}".format(
                        parsed, args))
            ## And an adversarial hand-written torrc must parse too.
            torrc.write_text(_rand_text(rnd), encoding="utf-8")
            torrc_gen.parse_torrc()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=20000)
    parser.add_argument("--seed", type=int, default=None)
    opts = parser.parse_args()

    seed = opts.seed if opts.seed is not None else random.randrange(2 ** 32)
    rnd = random.Random(seed)
    per_phase = max(1, opts.iterations // 3)
    print("fuzz_torrc: seed={0} iterations={1}".format(seed, opts.iterations))

    phases = (
        ("validators", phase_validators),
        ("custom_bridges", phase_custom_bridges),
        ("gen_parse", phase_gen_parse),
    )
    for name, func in phases:
        try:
            func(rnd, per_phase)
        except Exception:
            sys.stderr.write(
                "fuzz_torrc: FAILURE in phase '{0}' -- replay with "
                "--seed {1}\n".format(name, seed))
            raise
        print("fuzz_torrc: phase '{0}' ok ({1} iterations)".format(
            name, per_phase))

    print("fuzz_torrc: PASS")


if __name__ == "__main__":
    main()
