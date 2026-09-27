#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Hard-gating scan of the live production SSH servers against security-misc's
hardened ssh-audit server policy (bundled in the sibling security-misc-tests
suite; the config drift-guard there keeps it in sync with security-misc).

kicksecure.com and whonix.org must present EXACTLY the security-misc hardened
algorithm set (server.policy, exact match). This FAILS if a production server
runs an unhardened / weaker sshd, or drops security-misc's SSH hardening in a
future change.

--e2e category: requires clearnet egress to port 22. A connection failure fails
the gate (never a silent pass); reachability plus hardening is the contract.
"""

import os
import shutil
import subprocess

import pytest

PROD_HOSTS = ("kicksecure.com", "whonix.org")

## The server policy lives in the sibling core suite (single copy, drift-guarded
## there against security-misc's config); both suites install under /usr/share.
SERVER_POLICY = os.path.normpath(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        "security-misc-tests",
        "server.policy",
    )
)


def test_production_ssh_matches_hardened_policy():
    """kicksecure.com and whonix.org sshd must match security-misc server.policy."""
    ssh_audit = shutil.which("ssh-audit")
    if ssh_audit is None:
        pytest.fail("required dependency not found on PATH: ssh-audit")
    if not os.path.exists(SERVER_POLICY):
        pytest.fail(f"bundled server policy missing: {SERVER_POLICY}")
    failures = []
    for host in PROD_HOSTS:
        result = subprocess.run(
            [ssh_audit, "--policy", SERVER_POLICY, "--", host],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            failures.append(f"{host}:\n{result.stdout}\n{result.stderr}")
    assert not failures, (
        "production SSH server(s) do not match the security-misc hardened "
        "policy (unhardened sshd, or unreachable on port 22):\n\n"
        + "\n".join(failures)
    )
