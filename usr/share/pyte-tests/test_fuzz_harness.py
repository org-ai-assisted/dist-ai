#!/usr/bin/python3 -Bsu

"""Regression tests for the fuzz harness's own reproduction fidelity.

The harness must report the EXACT sequence that crashed. It draws two screen
dimensions from the RNG before the token sequence, so regenerating the sequence
from a fresh ``Random(seed)`` (as an earlier version did) omits those two draws
and reports a different sequence than the one that actually failed.
"""
import random

import fuzz_pyte


def _true_seq(seed: int) -> list[str]:
    """The sequence _one_round really feeds: the two dimension draws first."""
    rng = random.Random(seed)
    rng.choice([1, 3, 8, 20, 80])  # screen columns
    rng.choice([1, 3, 8, 24])      # screen lines
    return [rng.choice(fuzz_pyte.TOKENS) for _ in range(rng.randint(1, 10))]


def test_one_round_records_the_exact_fed_sequence() -> None:
    for seed in range(50):
        captured: list[str] = []
        try:
            fuzz_pyte._one_round(random.Random(seed), bool(seed & 1), captured)
        except Exception:  # noqa: BLE001 - a target crash must still leave seq
            pass
        assert captured == _true_seq(seed), f"seed {seed}"


def test_captured_seq_is_not_the_naive_regeneration() -> None:
    """Prove the captured sequence is not the fresh-RNG regeneration that the
    fidelity bug reported (which omitted the two dimension draws)."""
    seed = 12345
    captured: list[str] = []
    try:
        fuzz_pyte._one_round(random.Random(seed), False, captured)
    except Exception:  # noqa: BLE001
        pass
    rng = random.Random(seed)
    naive = [rng.choice(fuzz_pyte.TOKENS) for _ in range(rng.randint(1, 10))]
    assert captured != naive
