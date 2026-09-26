#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Validate security-misc's shipped SSH client and server hardening via ssh-audit.

security-misc ships:
  etc/ssh/sshd_config.d/30_security-misc.conf   (server crypto policy)
  etc/ssh/ssh_config.d/30_security-misc.conf    (client crypto policy)
  usr/share/security-misc/ssh-audit/server.policy  (ssh-audit exact-match spec)
  usr/share/security-misc/ssh-audit/client.policy
  usr/bin/ssh-audit-test                        (server-audit driver)

This suite drives the REAL shipped ssh-audit-test tool and ssh-audit against a
throwaway sshd / client built from the ACTUAL shipped config (read at runtime,
no synthetic copy), and asserts:
  - a server carrying security-misc's crypto directives PASSES server.policy;
  - the security-misc ssh_config client PASSES client.policy;
  - both policies still match the shipped config (drift guard);
  - a STOCK server / client FAILS the policy (canary: the check has teeth).

The sshd runs unprivileged on a high loopback port, so no root / PAM / absolute
host key is involved; only the crypto algorithm directives (which are all that
ssh-audit grades) are extracted from the shipped drop-in.
"""

import glob
import os
import shutil
import socket
import subprocess
import time

import pytest

REPO = os.environ.get("SECURITY_MISC_REPO", "")

## Crypto directives ssh-audit grades; extracted from the shipped sshd/ssh config.
CRYPTO_DIRECTIVES = (
    "KexAlgorithms",
    "Ciphers",
    "MACs",
    "HostKeyAlgorithms",
    "PubkeyAcceptedAlgorithms",
)

## ssh-audit lists these transport pseudo-algorithms in the kex set; OpenSSH adds
## them automatically, so they appear in the policy but not in sshd/ssh config.
KEX_PSEUDO = frozenset(
    {
        "ext-info-s",
        "ext-info-c",
        "kex-strict-s-v00@openssh.com",
        "kex-strict-c-v00@openssh.com",
    }
)


def _require(tool):
    path = shutil.which(tool)
    if path is None:
        ## A missing dependency is an environment bug, never a silent skip.
        pytest.fail(f"required dependency not found on PATH: {tool}")
    return path


def _resolve(relglob):
    """Resolve a security-misc artifact from the checkout (SECURITY_MISC_REPO)
    or, failing that, the installed package (unset base -> production paths).

    Skip (never fail) when security-misc is neither checked out nor installed:
    an absent optional subject, matching the dist-ai registry's
    unresolved-target contract. The runner also gates this with exit 77."""
    if REPO:
        matches = sorted(glob.glob(os.path.join(REPO, relglob)))
        if len(matches) > 1:
            pytest.fail(f"ambiguous match for {relglob} under {REPO}: {matches}")
        if matches:
            return matches[0]
        ## REPO is set: this artifact SHOULD exist. Its absence is a broken
        ## checkout, not security-misc being absent -- fail loud.
        pytest.fail(f"{relglob} missing under SECURITY_MISC_REPO={REPO}")
    ## Installed path: the tree's genmkfile '#...-shared' suffix is stripped on
    ## install, so drop the trailing glob '*' and anchor at the filesystem root.
    installed = "/" + relglob.rstrip("*")
    if os.path.exists(installed):
        return installed
    pytest.skip(f"security-misc not present (no checkout, not installed): {relglob}")
    return None  ## unreachable; pytest.fail/skip raises


def _parse_ssh_config_algos(path):
    """Return {directive: [algo, ...]} for the crypto directives in an ssh config."""
    found = {}
    with open(path, encoding="ascii") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            keyword, value = parts[0], parts[1].strip()
            for directive in CRYPTO_DIRECTIVES:
                if keyword.lower() == directive.lower():
                    found[directive] = [item for item in value.split(",") if item]
    return found


def _parse_policy_algos(path):
    """Return {'host keys','key exchanges','ciphers','macs': [algo, ...]}."""
    found = {}
    keys = ("host keys", "key exchanges", "ciphers", "macs")
    with open(path, encoding="ascii") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            name, value = line.split("=", 1)
            name = name.strip().lower()
            if name in keys:
                found[name] = [item.strip() for item in value.split(",") if item.strip()]
    return found


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_port(port, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.0)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def _wait_listen(port, timeout=10.0):
    """Wait for a LISTEN socket on 'port' WITHOUT connecting to it.

    ssh-audit -c audits the first client that connects and then exits, so a
    connect-probe would be consumed as that client ('did not receive banner').
    Read the listen state from /proc/net/tcp instead.
    """
    target = f":{port:04X}"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for proc_file in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(proc_file, encoding="ascii") as handle:
                    lines = handle.readlines()[1:]
            except OSError:
                continue
            for line in lines:
                fields = line.split()
                if len(fields) > 3 and fields[1].endswith(target) and fields[3] == "0A":
                    return True
        time.sleep(0.2)
    return False


def _client_audit(policy, ssh_config):
    """Drive ssh-audit client-audit against a connecting ssh client.

    ssh_config is the ssh -F config to offer (the security-misc drop-in), or
    None for a stock default client. Returns (ssh_audit_returncode, output).
    """
    ssh_audit = _require("ssh-audit")
    ssh = _require("ssh")
    ## Retry on a fresh port if the listener does not come up (ephemeral-port
    ## bind-after-close race), same as _start_sshd.
    for _attempt in range(3):
        port = _free_port()
        auditor = subprocess.Popen(
            [ssh_audit, "-c", "--policy", policy, "--port", str(port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if not _wait_listen(port):
            auditor.terminate()
            auditor.wait(timeout=10)
            continue
        ssh_cmd = [ssh, "-F", ssh_config if ssh_config else "/dev/null"]
        ssh_cmd += [
            "-p", str(port),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            "auditee@127.0.0.1",
            "true",
        ]
        ## The connection fails auth; that is fine, the kex exchange has already
        ## exposed the client's algorithm offer to ssh-audit.
        subprocess.run(ssh_cmd, capture_output=True, text=True)
        try:
            stdout, _ = auditor.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            auditor.kill()
            stdout, _ = auditor.communicate()
        return auditor.returncode, stdout
    pytest.fail("ssh-audit client-audit listener did not come up after retries")
    return None, None  ## unreachable; pytest.fail raises


def _start_sshd(tmp_path, directives):
    """Run an unprivileged sshd on a loopback high port; return (Popen, port).

    Picks the port itself and retries on a fresh one if the listener does not
    come up, absorbing the inherent bind-after-close race in ephemeral port
    selection (another process can grab the number in that window).
    """
    sshd = "/usr/sbin/sshd"
    if not os.path.exists(sshd):
        pytest.fail(f"required dependency not found: {sshd} (openssh-server)")
    hostkey = os.path.join(tmp_path, "ssh_host_ed25519_key")
    subprocess.run(
        [_require("ssh-keygen"), "-t", "ed25519", "-f", hostkey, "-N", "", "-q"],
        check=True,
    )
    config_path = os.path.join(tmp_path, "sshd_config")
    log_path = os.path.join(tmp_path, "sshd.log")
    last_log = ""
    for _attempt in range(3):
        port = _free_port()
        lines = [
            f"Port {port}",
            "ListenAddress 127.0.0.1",
            f"HostKey {hostkey}",
            f"PidFile {os.path.join(tmp_path, 'sshd.pid')}",
        ]
        for keyword, value in directives.items():
            lines.append(f"{keyword} {value}")
        with open(config_path, "w", encoding="ascii") as handle:
            handle.write("\n".join(lines) + "\n")
        proc = subprocess.Popen(
            [sshd, "-D", "-f", config_path, "-E", log_path]
        )
        if _wait_port(port):
            return proc, port
        proc.terminate()
        proc.wait(timeout=10)
        try:
            with open(log_path, encoding="ascii") as handle:
                last_log = handle.read()
        except OSError:
            last_log = ""
    pytest.fail(f"test sshd did not come up after retries\n{last_log}")
    return None, None  ## unreachable; pytest.fail raises


@pytest.fixture(name="server_config_algos")
def _server_config_algos():
    return _parse_ssh_config_algos(
        _resolve("etc/ssh/sshd_config.d/30_security-misc.conf*")
    )


@pytest.fixture(name="client_config_algos")
def _client_config_algos():
    return _parse_ssh_config_algos(
        _resolve("etc/ssh/ssh_config.d/30_security-misc.conf*")
    )


def _server_directives(server_config_algos):
    ## sshd only understands the server-relevant directives; PubkeyAcceptedAlgorithms
    ## is a client concept for host-based auth here and is not needed for the audit.
    wanted = ("KexAlgorithms", "Ciphers", "MACs", "HostKeyAlgorithms")
    directives = {k: ",".join(server_config_algos[k]) for k in wanted if k in server_config_algos}
    return directives


def test_server_config_passes_policy(tmp_path, server_config_algos):
    """A server carrying security-misc's crypto directives matches server.policy."""
    _require("ssh-audit")
    tool = _resolve("usr/bin/ssh-audit-test*")
    policy = _resolve("usr/share/security-misc/ssh-audit/server.policy*")
    proc, port = _start_sshd(str(tmp_path), _server_directives(server_config_algos))
    try:
        result = subprocess.run(
            ["bash", tool, "--policy", policy, "--port", str(port), "--", "127.0.0.1"],
            capture_output=True,
            text=True,
        )
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    assert result.returncode == 0, (
        f"ssh-audit-test rejected the security-misc server config:\n"
        f"{result.stdout}\n{result.stderr}"
    )


def test_stock_server_fails_policy(tmp_path):
    """Canary: a stock (default-crypto) sshd must FAIL the policy."""
    _require("ssh-audit")
    tool = _resolve("usr/bin/ssh-audit-test*")
    policy = _resolve("usr/share/security-misc/ssh-audit/server.policy*")
    ## No crypto directives -> OpenSSH defaults (nistp, ecdsa, rsa, sha1, ...).
    proc, port = _start_sshd(str(tmp_path), {})
    try:
        result = subprocess.run(
            ["bash", tool, "--policy", policy, "--port", str(port), "--", "127.0.0.1"],
            capture_output=True,
            text=True,
        )
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    assert result.returncode != 0, (
        "canary failed: ssh-audit-test PASSED a stock unhardened sshd; "
        "the policy is not actually constraining anything"
    )


def test_server_config_no_weak_algorithms(tmp_path, server_config_algos):
    """Defense in depth: ssh-audit reports zero warn/fail findings for the server."""
    ssh_audit = _require("ssh-audit")
    proc, port = _start_sshd(str(tmp_path), _server_directives(server_config_algos))
    try:
        result = subprocess.run(
            [ssh_audit, "--port", str(port), "--level", "warn", "--", "127.0.0.1"],
            capture_output=True,
            text=True,
        )
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    ## ssh-audit exits non-zero when any finding at/above the requested level exists.
    assert result.returncode == 0, (
        f"ssh-audit reported warn/fail findings for the security-misc server config:\n"
        f"{result.stdout}"
    )


def test_client_config_passes_policy():
    """The security-misc ssh_config client matches client.policy (client-audit mode)."""
    client_config = _resolve("etc/ssh/ssh_config.d/30_security-misc.conf*")
    policy = _resolve("usr/share/security-misc/ssh-audit/client.policy*")
    returncode, output = _client_audit(policy, client_config)
    assert returncode == 0, (
        f"ssh-audit rejected the security-misc client config:\n{output}"
    )


def test_stock_client_fails_policy():
    """Canary: a stock (default-crypto) ssh client must FAIL the client policy."""
    policy = _resolve("usr/share/security-misc/ssh-audit/client.policy*")
    returncode, _output = _client_audit(policy, None)
    assert returncode != 0, (
        "canary failed: ssh-audit PASSED a stock default ssh client; "
        "the client policy is not actually constraining anything"
    )


def test_policy_matches_server_config(server_config_algos):
    """Drift guard: server.policy algorithm lists equal the shipped sshd config."""
    policy = _parse_policy_algos(
        _resolve("usr/share/security-misc/ssh-audit/server.policy*")
    )
    assert [a for a in policy["key exchanges"] if a not in KEX_PSEUDO] == \
        server_config_algos["KexAlgorithms"]
    assert policy["ciphers"] == server_config_algos["Ciphers"]
    assert policy["macs"] == server_config_algos["MACs"]
    assert policy["host keys"] == server_config_algos["HostKeyAlgorithms"]


def test_policy_matches_client_config(client_config_algos):
    """Drift guard: client.policy algorithm lists equal the shipped ssh config."""
    policy = _parse_policy_algos(
        _resolve("usr/share/security-misc/ssh-audit/client.policy*")
    )
    assert [a for a in policy["key exchanges"] if a not in KEX_PSEUDO] == \
        client_config_algos["KexAlgorithms"]
    assert policy["ciphers"] == client_config_algos["Ciphers"]
    assert policy["macs"] == client_config_algos["MACs"]
    assert policy["host keys"] == client_config_algos["HostKeyAlgorithms"]
