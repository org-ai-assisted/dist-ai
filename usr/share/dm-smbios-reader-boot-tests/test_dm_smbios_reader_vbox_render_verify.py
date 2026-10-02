#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression tests for dm-smbios-reader-vbox's render-verification against committed baselines.

Exercises the pure image-comparison logic + the `verify` subcommand handler using
the real per-image baselines under render-baselines/, with no VM and no tesseract:
a baseline matches itself, a different Calamares page does not, and _cmd_verify maps
those to PASS/FAIL exit codes. This is what makes the committed baselines a GATE
rather than dead files.
"""

import importlib.machinery
import importlib.util
import types
from pathlib import Path

import pytest

pytest.importorskip('PIL.Image')

BACKEND = Path(__file__).resolve().parent / 'dm-smbios-reader-vbox'
BASELINES = Path(__file__).resolve().parent / 'render-baselines' \
    / 'kicksecure-calamares-1280x800'


def _load():
    loader = importlib.machinery.SourceFileLoader(
        'dm_vbox_render_under_test', str(BACKEND))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


M = _load()

WELCOME = BASELINES / 'welcome.png'
LOCATION = BASELINES / 'location.png'
PARTITIONS = BASELINES / 'partitions.png'
PARTITIONS_LUKS = BASELINES / 'partitions-luks.png'


def test_baselines_present():
    ## the committed baselines the gate compares against must actually ship.
    for path in (WELCOME, LOCATION, PARTITIONS, PARTITIONS_LUKS):
        assert path.is_file(), 'missing render baseline: %s' % path


def test_identical_image_is_zero_diff():
    assert M.image_diff_ratio(str(WELCOME), str(WELCOME)) == 0.0


def test_screen_matches_self():
    assert M.screen_matches(str(WELCOME), str(WELCOME), tol=0.01)


def test_screen_mismatch_between_distinct_pages():
    ## Welcome vs Partitions are visibly different pages -> beyond the 5% default.
    assert not M.screen_matches(str(WELCOME), str(PARTITIONS), tol=0.05)
    assert M.image_diff_ratio(str(WELCOME), str(PARTITIONS)) > 0.05


def _verify_args(shot, baseline, tol=0.05, expect=None):
    return types.SimpleNamespace(
        shot=str(shot), baseline=str(baseline), tol=tol, expect=expect or [])


def test_cmd_verify_pass_on_match():
    assert M._cmd_verify(_verify_args(WELCOME, WELCOME)) == M.PASS_RC


def test_cmd_verify_fail_on_mismatch():
    assert M._cmd_verify(_verify_args(PARTITIONS, WELCOME)) == M.FAIL_RC


def test_cmd_verify_setup_error_on_missing_file(tmp_path):
    missing = tmp_path / 'nope.png'
    assert M._cmd_verify(_verify_args(missing, WELCOME)) == M.SETUP_RC


def test_ocr_text_contains_decision_is_fuzzy():
    ## the OCR decision is unit-testable without tesseract (pure string logic).
    assert M.ocr_text_contains('Welcome to the Calamares installer', 'welcome to the')
    assert not M.ocr_text_contains('Welcome page', ['region', 'zone'])
