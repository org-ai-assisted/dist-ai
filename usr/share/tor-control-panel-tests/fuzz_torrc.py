#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Randomized, in-process fuzzer for tor_control_panel's untrusted-input logic in
tor_control_panel_lib (the Qt-free layer).

Properties checked (per phase, each over --iterations rounds):

  parse        tcpl_parse_torrc() on arbitrary torrc text must return a
               TcplTorConfInfo or a str -- never raise.
  make_sane    tcpl_make_tor_conf_info_sane() on an arbitrary TcplTorConfInfo
               must return a TcplTorConfInfo or a str -- never raise (its
               documented contract is to describe problems via a returned str).
  bridge_pfx   tcpl_bridge_lines_add_prefix()/remove_prefix() may raise ONLY
               ValueError (documented) and otherwise return list[str].
  port         tcpl_default_port_for_protocol() returns an int or raises ONLY
               ValueError.

A phase records the first offending input with the seed to reproduce it, and
keeps running the remaining phases so one defect does not mask the others.
Reproduce a specific run with --seed N. Exits non-zero if any phase found a
property violation.
"""

import argparse
import copy
import random
import string
import sys

import tcp_testlib
from tor_control_panel import tor_control_panel_lib as tcpl

tcp_testlib.require_app()


TORRC_TOKENS = [
    'DisableNetwork', 'UseBridges', 'ClientTransportPlugin', 'Bridge',
    'HTTPSProxy', 'Socks4Proxy', 'Socks5Proxy', 'HTTPSProxyAuthenticator',
    'Socks5ProxyUsername', 'Socks5ProxyPassword', '0', '1', '2', 'obfs4',
    'snowflake', 'meek_lite', '10.0.0.1:443', 'user:pass', '#', '',
    ':', '::1', 'x' * 40,
]
PROXY_TYPES = tcpl.tcpl_proxy_type_list + ['SOCKS4', 'bogus', '', None]
BRIDGE_TYPES = tcpl.tcpl_bridge_type_list + ['telepathy', '']


def _rand_text(rng):
    line_count = rng.randint(0, 6)
    lines = []
    for _ in range(line_count):
        token_count = rng.randint(0, 4)
        tokens = [rng.choice(TORRC_TOKENS) for _ in range(token_count)]
        lines.append(' '.join(tokens))
    return '\n'.join(lines)


def _rand_bridge_lines(rng):
    out = []
    for _ in range(rng.randint(0, 3)):
        parts = [rng.choice(['Bridge', '']), rng.choice(BRIDGE_TYPES)]
        parts += [
            ''.join(rng.choice(string.printable) for _ in range(rng.randint(0, 6)))
        ]
        out.append(' '.join(p for p in parts if p != '').strip())
    return out


def _rand_conf_info(rng):
    info = copy.deepcopy(tcpl.tcpl_blank_tor_conf_info)
    info.network_enabled = rng.choice([True, False, None])
    info.bridges_enabled = rng.choice([True, False, None])
    info.bridge_type_set = set(
        rng.choice(BRIDGE_TYPES) for _ in range(rng.randint(0, 2))
    )
    info.bridge_line_list = _rand_bridge_lines(rng)
    info.proxy_type = rng.choice(PROXY_TYPES)
    info.proxy_host = rng.choice([None, '10.0.0.1', '', ':'])
    info.proxy_port = rng.choice([None, 0, 1080, -1, 99999])
    info.proxy_username = rng.choice([None, '', 'u', 'x' * 300])
    info.proxy_password = rng.choice([None, '', 'p', 'x' * 300])
    return info


class Failure(Exception):
    pass


def _phase_parse(rng, iterations, torrc_file):
    for _ in range(iterations):
        text = _rand_text(rng)
        torrc_file.write_text(text, encoding='utf-8')
        try:
            result = tcpl.tcpl_parse_torrc()
        except Exception as exc:  # noqa: BLE001
            raise Failure(f"tcpl_parse_torrc raised {type(exc).__name__}: "
                          f"{exc}\n--- torrc ---\n{text}") from exc
        if not isinstance(result, (tcpl.TcplTorConfInfo, str)):
            raise Failure(f"tcpl_parse_torrc returned {type(result)} for:\n{text}")


def _phase_make_sane(rng, iterations, _torrc_file):
    for _ in range(iterations):
        info = _rand_conf_info(rng)
        snapshot = repr(info)
        try:
            result = tcpl.tcpl_make_tor_conf_info_sane(info)
        except Exception as exc:  # noqa: BLE001
            raise Failure(f"tcpl_make_tor_conf_info_sane raised "
                          f"{type(exc).__name__}: {exc}\n{snapshot}") from exc
        if not isinstance(result, (tcpl.TcplTorConfInfo, str)):
            raise Failure(f"tcpl_make_tor_conf_info_sane returned "
                          f"{type(result)} for:\n{snapshot}")


def _phase_bridge_pfx(rng, iterations, _torrc_file):
    for _ in range(iterations):
        lines = _rand_bridge_lines(rng)
        for func in (tcpl.tcpl_bridge_lines_add_prefix,
                     tcpl.tcpl_bridge_lines_remove_prefix):
            try:
                result = func(list(lines))
            except ValueError:
                continue
            except Exception as exc:  # noqa: BLE001
                raise Failure(f"{func.__name__} raised {type(exc).__name__}: "
                              f"{exc}\nlines={lines!r}") from exc
            if not isinstance(result, list) or not all(
                isinstance(item, str) for item in result
            ):
                raise Failure(f"{func.__name__} returned {result!r} for "
                              f"{lines!r}")


def _phase_port(rng, iterations, _torrc_file):
    candidates = list(PROXY_TYPES) + [
        ''.join(rng.choice(string.printable) for _ in range(rng.randint(0, 8)))
        for _ in range(8)
    ]
    for _ in range(iterations):
        protocol = rng.choice(candidates)
        if protocol is None:
            continue
        try:
            result = tcpl.tcpl_default_port_for_protocol(protocol)
        except ValueError:
            continue
        except Exception as exc:  # noqa: BLE001
            raise Failure(f"tcpl_default_port_for_protocol raised "
                          f"{type(exc).__name__}: {exc}\nprotocol={protocol!r}"
                          ) from exc
        if not isinstance(result, int):
            raise Failure(f"tcpl_default_port_for_protocol returned {result!r} "
                          f"for {protocol!r}")


PHASES = {
    'parse': _phase_parse,
    'make_sane': _phase_make_sane,
    'bridge_pfx': _phase_bridge_pfx,
    'port': _phase_port,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iterations', type=int, default=30000)
    parser.add_argument('--seed', type=int, default=None)
    args = parser.parse_args()

    base_seed = args.seed if args.seed is not None else random.randrange(2 ** 32)
    print(f"fuzz_torrc: seed={base_seed} iterations={args.iterations}")

    failures = []
    with tcp_testlib.sandbox() as torrc_file:
        for name, phase_func in PHASES.items():
            ## A per-phase seed derived from the base keeps each phase
            ## independently reproducible from the single reported seed.
            rng = random.Random(f"{base_seed}:{name}")
            try:
                phase_func(rng, args.iterations, torrc_file)
                print(f"  {name}: ok")
            except Failure as exc:
                print(f"  {name}: FAIL\n{exc}")
                failures.append(name)

    if failures:
        print(f"fuzz_torrc: FAILED phases: {', '.join(failures)} "
              f"(reproduce with --seed {base_seed})")
        return 1
    print("fuzz_torrc: all phases ok")
    return 0


if __name__ == '__main__':
    sys.exit(main())
