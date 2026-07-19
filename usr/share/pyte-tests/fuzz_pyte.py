#!/usr/bin/env python3
"""In-process fuzz harness for pyte's Stream / ByteStream / Screen.

Feeds randomised, adversarial escape/control/text sequences to a Screen through
a Stream (and a ByteStream) and checks that:

  * feed() does not raise, and
  * a small set of state invariants holds afterwards.

Known, already-reported defects (see ``BUGS/``) are listed in
``known_crashes.json`` next to this file; the harness treats a crash whose
signature is in that allowlist as expected and keeps going. Any crash with a
NEW signature -- or any invariant violation -- fails the run (exit 1) and prints
the seed and the exact reproducing sequence, so it can be turned into a
regression test.

Usage:
    fuzz_pyte.py [--iterations N] [--seed BASE] [--report]

``--report`` prints every crash signature seen (with an example seed) and exits
0; use it to refresh the allowlist. Without it, the run gates on new crashes.

Deterministic: iteration ``i`` uses ``random.Random(base_seed + i)``, so any
finding reproduces exactly from its printed seed.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import traceback

import pyte

HERE = os.path.dirname(os.path.abspath(__file__))
ALLOWLIST_PATH = os.path.join(HERE, "known_crashes.json")

FINALS = "@ABCDEFGHIJKLMPSTXZ`abcdefghilmnpqrstuvwxyz{|}~"
PARAMS = ["", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "99", "9999",
          "100000", "0;0", "1;1", "1;2;3", "38;5;1", "38;2;1;2;3", "48;5;255",
          ";", ";;", "?6", "?25", "?5", "?7", "?3", "?1", "?", ">"]
INTERMEDIATE = ["", " ", "!", "#", "$", "%", "(", ")", "*"]
ESCAPES = ["c", "D", "E", "M", "H", "7", "8", "#8", "%@", "%G", "(B", "(0",
           ")0", ")B", "(U", "(V", "=", ">"]
CTRL = ["\x00", "\x07", "\x08", "\x09", "\n", "\x0b", "\x0c", "\r", "\x0e",
        "\x0f", "\x18", "\x1a", "\x7f", "\x9b", "\x9c", "\x9d"]
TEXT = ["a", "ab", " ", "\t", "\u4e00", "\U0001f600", "\u0301", "\u200d",
        "\U0001f3fb", "\u00e9", "\U0001f469\u200d\U0001f469", "\ufe0f", "z" * 5]
OSC = ["\x1b]0;title\x07", "\x1b]2;hi\x1b\\", "\x1b]1;icon\x07",
       "\x1b]R\x07", "\x1b]P00ffff", "\x1b]52;c;x\x07", "\x1b]"]


def _tokens() -> list[str]:
    toks: list[str] = []
    toks += ["\x1b[" + p + f for p in PARAMS for f in FINALS]
    toks += ["\x1b[" + i + p + f
             for i in INTERMEDIATE for p in ("", "0", "1") for f in FINALS]
    toks += ["\x1b" + e for e in ESCAPES]
    toks += CTRL + TEXT + OSC
    return toks


TOKENS = _tokens()


def _signature(exc: BaseException) -> str:
    """A coarse, message-stable signature grouping equivalent crashes."""
    tb = exc.__traceback__
    site = "?"
    for frame, _lineno in traceback.walk_tb(tb):
        filename = frame.f_code.co_filename
        if (os.sep + "pyte" + os.sep) in filename \
                and "tests" not in filename:
            site = f"{os.path.basename(filename)}:{frame.f_code.co_name}"
    msg = str(exc)
    msg = re.sub(r"'[^']*'", "'X'", msg)          # drop quoted identifiers
    msg = re.sub(r"\b\w+\(\)", "F()", msg)         # drop method names
    msg = re.sub(r"\d+", "N", msg)                  # drop numbers
    return f"{type(exc).__name__}|{site}|{msg.strip()[:60]}"


def _check_invariants(screen: pyte.Screen) -> None:
    display = screen.display
    assert len(display) == screen.lines, \
        f"display has {len(display)} rows, expected {screen.lines}"
    assert 0 <= screen.cursor.x <= screen.columns, \
        f"cursor.x={screen.cursor.x} out of [0,{screen.columns}]"
    assert 0 <= screen.cursor.y < screen.lines, \
        f"cursor.y={screen.cursor.y} out of [0,{screen.lines})"


def _one_round(rng: random.Random, use_bytes: bool) -> list[str]:
    screen = pyte.Screen(rng.choice([1, 3, 8, 20, 80]),
                         rng.choice([1, 3, 8, 24]))
    stream = pyte.ByteStream(screen) if use_bytes else pyte.Stream(screen)
    seq = [rng.choice(TOKENS) for _ in range(rng.randint(1, 10))]
    for tok in seq:
        data = tok.encode("utf-8", "surrogatepass") if use_bytes else tok
        stream.feed(data)
    _check_invariants(screen)
    return seq


def _load_allowlist() -> set[str]:
    try:
        with open(ALLOWLIST_PATH, encoding="utf-8") as handle:
            return set(json.load(handle)["signatures"])
    except (OSError, ValueError, KeyError):
        return set()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=20000)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--report", action="store_true",
                        help="list every signature seen and exit 0")
    args = parser.parse_args(argv)

    allow = _load_allowlist()
    seen: dict[str, tuple[int, bool, list[str]]] = {}
    new_findings: dict[str, tuple[int, bool, list[str]]] = {}

    for i in range(args.iterations):
        seed = args.seed + i
        use_bytes = bool(i & 1)
        rng = random.Random(seed)
        try:
            _one_round(rng, use_bytes)
        except (Exception, SystemExit) as exc:  # fuzz harness: record any target
            # crash (incl. a target calling sys.exit) but let KeyboardInterrupt
            # through so the operator can still stop the run
            sig = _signature(exc)
            rng2 = random.Random(seed)
            seq = [rng2.choice(TOKENS) for _ in range(rng2.randint(1, 10))]
            seen.setdefault(sig, (seed, use_bytes, seq))
            if sig not in allow:
                new_findings.setdefault(sig, (seed, use_bytes, seq))

    if args.report:
        print(f"pyte {getattr(pyte, '__version__', 'n/a')} -- "
              f"{args.iterations} iters from seed {args.seed}")
        for sig, (seed, ub, seq) in sorted(seen.items()):
            known = "KNOWN" if sig in allow else "NEW  "
            kind = "ByteStream" if ub else "Stream"
            print(f"[{known}] {sig}\n         seed={seed} {kind} seq={seq!r}")
        print(f"total distinct signatures: {len(seen)} "
              f"({len(new_findings)} new)")
        return 0

    if new_findings:
        print(f"FUZZ FAIL: {len(new_findings)} new crash signature(s) on "
              f"pyte {getattr(pyte, '__version__', 'n/a')}:", file=sys.stderr)
        for sig, (seed, ub, seq) in sorted(new_findings.items()):
            kind = "ByteStream" if ub else "Stream"
            print(f"  {sig}\n    reproduce: seed={seed} {kind} seq={seq!r}",
                  file=sys.stderr)
        return 1

    print(f"OK: {args.iterations} iterations, no new crashes "
          f"({len(seen)} known signature(s) hit).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
