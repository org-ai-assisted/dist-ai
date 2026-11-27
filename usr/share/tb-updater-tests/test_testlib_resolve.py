#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression tests for tb_updater_testlib._resolve subject resolution.

A REQUIRED subject missing from a PRESENT checkout is a regression, not an
unavailable target: _resolve must FAIL (exit 1), never skip (77). A skip there
silently drops that subject's regression coverage (a removed hook reading as
green). Only a genuinely unavailable target (no checkout, nothing installed)
exits 77, which target_available_probe.py turns into the one authorized
whole-suite skip.
"""

import pytest

import tb_updater_testlib as T


def test_resolve_fatal_when_checkout_present_but_subject_missing(tmp_path,
                                                                 monkeypatch):
    repo = tmp_path / "checkout"
    repo.mkdir()
    monkeypatch.setenv("TB_UPDATER_REPO", str(repo))
    with pytest.raises(SystemExit) as caught:
        T._resolve("usr/bin/does-not-exist",
                   "/usr/bin/does-not-exist", "subject")
    assert caught.value.code == 1


def test_resolve_skip_when_target_genuinely_unavailable(tmp_path, monkeypatch):
    monkeypatch.delenv("TB_UPDATER_REPO", raising=False)
    with pytest.raises(SystemExit) as caught:
        T._resolve("usr/bin/x", str(tmp_path / "not-installed"), "subject")
    assert caught.value.code == 77


def test_resolve_returns_checkout_path_when_present(tmp_path, monkeypatch):
    target = tmp_path / "checkout" / "usr" / "bin" / "tool"
    target.parent.mkdir(parents=True)
    target.write_text("#!/bin/sh\n")
    monkeypatch.setenv("TB_UPDATER_REPO", str(tmp_path / "checkout"))
    assert T._resolve("usr/bin/tool", "/usr/bin/tool", "tool") == str(target)
