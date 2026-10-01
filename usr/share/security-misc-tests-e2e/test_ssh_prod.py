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
import time

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

## Bound each per-host scan: a host that accepts TCP but then stalls (a mid-protocol
## hang, a filtered port that never RSTs) would otherwise hang ssh-audit -- and this gate --
## INDEFINITELY. A stalled host must FAIL the gate (reachability is part of the contract),
## never hang it.
SSH_AUDIT_TIMEOUT = 60


def _scan_host(ssh_audit, host, timeout=SSH_AUDIT_TIMEOUT):
    """Scan one host against the hardened policy. Return a failure description, or
    None on an exact policy match. A timeout (stalled host) is a FAILURE, not a hang."""
    try:
        result = subprocess.run(
            [ssh_audit, "--policy", SERVER_POLICY, "--", host],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return (
            f"{host}: ssh-audit did not finish within {timeout}s (host stalled):\n"
            f"{exc.stdout or ''}\n{exc.stderr or ''}"
        )
    if result.returncode != 0:
        return f"{host}:\n{result.stdout}\n{result.stderr}"
    return None


def test_production_ssh_matches_hardened_policy():
    """kicksecure.com and whonix.org sshd must match security-misc server.policy."""
    ssh_audit = shutil.which("ssh-audit")
    if ssh_audit is None:
        pytest.fail("required dependency not found on PATH: ssh-audit")
    if not os.path.exists(SERVER_POLICY):
        pytest.fail(f"bundled server policy missing: {SERVER_POLICY}")
    failures = []
    for host in PROD_HOSTS:
        failure = _scan_host(ssh_audit, host)
        if failure is not None:
            failures.append(failure)
    assert not failures, (
        "production SSH server(s) do not match the security-misc hardened "
        "policy (unhardened sshd, or unreachable on port 22):\n\n"
        + "\n".join(failures)
    )


def test_stalled_host_fails_not_hangs(tmp_path):
    """A host whose ssh-audit never returns must be recorded as a FAILURE within the
    timeout, not hang the gate forever. Drives _scan_host against a stub ssh-audit that
    outlives a short timeout; asserts a timeout-failure AND bounded wall-clock. No egress
    (the stub ignores its arguments)."""
    stub = tmp_path / "ssh-audit-stub"
    stub.write_text("#!/bin/sh\nsleep 5\n")
    stub.chmod(0o755)
    start = time.monotonic()
    failure = _scan_host(str(stub), "stalled.example", timeout=1)
    elapsed = time.monotonic() - start
    assert failure is not None and "did not finish within" in failure, (
        f"a stalled host must yield a timeout failure, got: {failure!r}"
    )
    assert elapsed < 4, (
        f"the scan did not bound the stall (took {elapsed:.1f}s); the timeout is not enforced"
    )
