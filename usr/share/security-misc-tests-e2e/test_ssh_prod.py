#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Hard-gating scan of the live production SSH servers against security-misc's
shipped ssh-audit server policy, using the real shipped ssh-audit-test tool.

kicksecure.com and whonix.org must present EXACTLY the security-misc hardened
algorithm set (server.policy, exact match). This FAILS if a production server
runs an unhardened / weaker sshd, or if it drops security-misc's SSH hardening
in a future change.

--e2e category: requires clearnet egress to port 22. A connection failure fails
the gate (never a silent pass); reachability plus hardening is the contract.
"""

import glob
import os
import shutil
import subprocess

import pytest

REPO = os.environ.get("SECURITY_MISC_REPO", "")

PROD_HOSTS = ("kicksecure.com", "whonix.org")


def _resolve(installed, repo_glob):
    if os.path.exists(installed):
        return installed
    if REPO:
        matches = sorted(glob.glob(os.path.join(REPO, repo_glob)))
        if matches:
            return matches[0]
    pytest.fail(f"could not resolve {installed} (nor {repo_glob} under SECURITY_MISC_REPO)")
    return None  ## unreachable; pytest.fail raises


def test_production_ssh_matches_hardened_policy():
    """kicksecure.com and whonix.org sshd must match security-misc server.policy."""
    if shutil.which("ssh-audit") is None:
        pytest.fail("required dependency not found on PATH: ssh-audit")
    tool = _resolve("/usr/bin/ssh-audit-test", "usr/bin/ssh-audit-test*")
    policy = _resolve(
        "/usr/share/security-misc/ssh-audit/server.policy",
        "usr/share/security-misc/ssh-audit/server.policy*",
    )
    result = subprocess.run(
        ["bash", tool, "--policy", policy, "--", *PROD_HOSTS],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "production SSH server(s) do not match the security-misc hardened "
        f"policy:\n{result.stdout}\n{result.stderr}"
    )
