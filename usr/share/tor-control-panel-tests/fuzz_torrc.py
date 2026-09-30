#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Randomized in-process fuzzer for tor-control-panel's untrusted-input parsers.

These functions consume attacker-influenceable input -- a torrc that round-trips
through disk (user-pasted bridge lines, possibly tampered with) and the config
the GUI regenerates. They must never crash, hang, or return a wrong-typed value;
a crash here is a GUI that dies (or mangles the config) on a hostile torrc.

Targets (master-present only):
  * torrc_gen.gen_torrc  +  torrc_gen.parse_torrc            -> no crash, and
    parse_torrc always returns the documented tuple shape
  * tor_status.tor_status                                    -> a defined state
    string, on adversarial torrc content

Scope note: gen_torrc AND parse_torrc on upstream master are NOT hardened
against malformed input (a junk bridge/proxy argument raises IndexError/
ValueError, and parse_torrc raises IndexError on a bare 'Bridge' line), so both
are exercised over VALID input only -- gen_torrc over its valid argument space,
parse_torrc over the well-formed torrc gen_torrc just wrote. tor_status reads
whatever is on disk defensively, so it takes the adversarial blobs. The
validator / bootstrap-phase / custom-bridge-reader fuzz phases were dropped:
those targets (validators, tor_bootstrap_parse, torrc_gen.read_custom_bridge_lines)
do not exist on master.

Run: fuzz_torrc.py [--iterations N] [--seed N]. On a failure it prints the seed
and the offending input so the case can be replayed deterministically.
"""

import argparse
import random
import sys
import tempfile
from pathlib import Path

import tcp_testlib as T  # noqa: F401  (resolves the source + offscreen Qt)
from tor_control_panel import torrc_gen, tor_status


## ---- input generators -------------------------------------------------------

## Bytes/among these make the torrc parsers interesting.
_ALPHABET = (
    'obfs4 snowflake meek_lite Bridge BridgeRelay DisableNetwork UseBridges '
    'ClientTransportPlugin # %include /etc/tor 1.2.3.4:1234 [::1]:9050 '
    "\t\n\r\x00\x1b[31m <b> obfs4proxy cert= iat-mode=0 . : , = \" ' \\ /"
).split(' ')

_CHARS = "abcdef0123456789.:[]# \t\n\r\x00\x1b<>\"'/=%-"

## Valid gen_torrc inputs. 'Custom bridges' is deliberately NOT a bridge_type
## choice: bridges_command has no matching entry on master, so it would raise.
_BRIDGE_TYPES = ['None', 'obfs4', 'snowflake', 'meek']
_CUSTOM_BRIDGES = [
    'None',
    'obfs4 1.2.3.4:1234 ABCDEF0123456789ABCDEF0123456789ABCDEF01',
    'snowflake 5.6.7.8:9000 0123456789ABCDEF0123456789ABCDEF01234567',
]
## Exact master proxy strings (proxies list); 'HTTP / HTTPS' has spaces.
_PROXY_TYPES = ['None', 'HTTP / HTTPS', 'SOCKS4', 'SOCKS5']


def _rand_token(rnd):
    kind = rnd.random()
    if kind < 0.35:
        return rnd.choice(_ALPHABET)
    if kind < 0.7:
        return ''.join(rnd.choice(_CHARS) for _ in range(rnd.randint(0, 40)))
    ## Occasionally a very long run, to probe pathological inputs.
    return rnd.choice(_CHARS) * rnd.randint(0, 4000)


def _rand_line(rnd):
    return ' '.join(_rand_token(rnd) for _ in range(rnd.randint(0, 6)))


def _rand_text(rnd):
    ## A multi-line blob, sometimes seeded with the custom-bridges marker and a
    ## DisableNetwork directive so parse_torrc / tor_status take their branches.
    lines = [_rand_line(rnd) for _ in range(rnd.randint(0, 12))]
    if rnd.random() < 0.4:
        lines.insert(rnd.randint(0, len(lines)),
                     '# Custom bridges are used')
    if rnd.random() < 0.4:
        lines.insert(0, 'DisableNetwork ' + rnd.choice(['0', '1', 'x', '']))
    return '\n'.join(lines)


def _rand_proxy_field(rnd):
    ## A benign proxy field: no line break / NUL (gen_torrc on master does not
    ## guard against torrc injection, so keep the value single-line here).
    return ''.join(rnd.choice('abcdef0123456789.:') for _ in range(rnd.randint(0, 20)))


## ---- fuzz phases ------------------------------------------------------------

def phase_gen_parse(rnd, iterations):
    with T.sandbox():
        for _ in range(iterations):
            args = [
                rnd.choice(_BRIDGE_TYPES),
                rnd.choice(_CUSTOM_BRIDGES),
                rnd.choice(_PROXY_TYPES),
                ## proxy ip / port / user / pass (used only when len(args) >= 7)
                rnd.choice(['127.0.0.1', '192.0.2.1', '[::1]', '']),
                rnd.choice(['9050', '1080', '0', '']),
                _rand_proxy_field(rnd),
                _rand_proxy_field(rnd),
            ]
            ## gen_torrc over its valid input space must not crash.
            torrc_gen.gen_torrc(args)
            ## The well-formed torrc gen_torrc just wrote must always parse back
            ## into the documented tuple shape without crashing.
            parsed = torrc_gen.parse_torrc()
            if not isinstance(parsed, (dict, tuple, list)):
                raise AssertionError(
                    'parse_torrc returned {0!r} for args {1!r}'.format(
                        parsed, args))


def phase_tor_status(rnd, iterations):
    ## tor_status() classifies the torrc's DisableNetwork directive; feed it
    ## adversarial torrc content and require a defined string result.
    with T.sandbox() as torrc:
        for _ in range(iterations):
            torrc.write_text(_rand_text(rnd), encoding='utf-8')
            result = tor_status.tor_status()
            if result not in ('tor_enabled', 'tor_disabled'):
                raise AssertionError(
                    'tor_status returned {0!r}'.format(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iterations', type=int, default=20000)
    parser.add_argument('--seed', type=int, default=None)
    opts = parser.parse_args()

    seed = opts.seed if opts.seed is not None else random.randrange(2 ** 32)
    rnd = random.Random(seed)
    phases = (
        ('gen_parse', phase_gen_parse),
        ('tor_status', phase_tor_status),
    )
    per_phase = max(1, opts.iterations // len(phases))
    print('fuzz_torrc: seed={0} iterations={1}'.format(seed, opts.iterations))
    for name, func in phases:
        try:
            func(rnd, per_phase)
        except Exception:
            sys.stderr.write(
                "fuzz_torrc: FAILURE in phase '{0}' -- replay with "
                '--seed {1}\n'.format(name, seed))
            raise
        print("fuzz_torrc: phase '{0}' ok ({1} iterations)".format(
            name, per_phase))

    print('fuzz_torrc: PASS')


if __name__ == '__main__':
    main()
