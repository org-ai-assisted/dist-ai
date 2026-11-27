#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Mount-namespace propagation invariant behind security-misc's exec hardening.

security-misc's security model combines two facts:
- remount-secure remounts sensitive paths with 'mount --make-private' (MS_PRIVATE)
  plus the hardening options (incl. noexec at level 3), in the GLOBAL/boot mount
  namespace;
- pam_namespace (namespace.d/30_security-misc.conf) unshares a PER-SESSION mount
  namespace for every uid != 0 login.

A direct consequence governs where a Tor Browser '~/.tb' exec-exception remount
must run: the login session already holds its OWN mount namespace, and a remount
performed in the GLOBAL namespace AFTER login does NOT appear in it. Two
independent reasons, either sufficient: /home is MS_PRIVATE so no mount event
propagates to the session; and lifting noexec is a REMOUNT option change, which
does not cross a namespace boundary even under shared propagation (verified). So a
global-ns remount at TB launch (privleapd as root) cannot lift noexec for TB; only
a SESSION-LOCAL remount can. The one way the session CAN gain exec is inheritance:
a remount done BEFORE it unshares (a pre-login boot service), which is a different
mechanism with its own ~/.tb-existence and timing constraints.

This test proves that invariant on the running kernel, hermetically, with the
exact remount-secure mount shape (make-private + noexec), inside a mapped-root
user+mount namespace (no real root, no host mounts touched). It is a regression
guard: if a global-ns remount ever reached an already-unshared session namespace
(B_SESSION), the design premise -- and remount-secure's cross-namespace isolation
-- would have broken.

Unprivileged user namespaces are REQUIRED. Their absence is an environment bug to
fix (e.g. 'kernel.apparmor_restrict_unprivileged_userns=0' on ubuntu-24.04
runners), not a reason to skip -- a skipped invariant reads green while proving
nothing.
"""

import os
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE = os.path.join(HERE, "namespace_propagation_probe.bash")


def _userns_probe() -> "subprocess.CompletedProcess[str]":
    return subprocess.run(
        ["unshare", "--map-root-user", "--", "true"],
        capture_output=True, text=True, check=False)


def _userns_env_diag() -> str:
    ## The governing knobs + caps, so a failure names its OWN cause instead of a
    ## guess. max_user_namespaces=0 (exhausted/hardened), unprivileged_userns_clone=0
    ## (legacy Debian switch), a set CapEff bit or the apparmor sysctl each fail
    ## unshare differently; reporting them turns "unavailable" into a diagnosis.
    bits = []
    try:
        who = subprocess.run(["id"], capture_output=True, text=True, check=False)
        bits.append("id=%s" % who.stdout.strip())
    except OSError as exc:
        bits.append("id=<%s>" % exc)
    for path in (
            "/proc/sys/user/max_user_namespaces",
            "/proc/sys/kernel/unprivileged_userns_clone",
            "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"):
        try:
            with open(path, encoding="ascii") as handle:
                bits.append("%s=%s" % (path, handle.read().strip()))
        except OSError as exc:
            bits.append("%s=<%s>" % (path, exc.strerror or exc))
    try:
        with open("/proc/self/status", encoding="ascii") as handle:
            for line in handle:
                if line.startswith(("CapEff", "CapBnd")):
                    bits.append(line.strip().replace("\t", " "))
    except OSError:
        pass
    return " | ".join(bits)


class NamespacePropagationTest(unittest.TestCase):
    def setUp(self) -> None:
        if not os.path.isfile(PROBE):
            raise AssertionError("probe missing: %s" % PROBE)
        probe = _userns_probe()
        if probe.returncode != 0:
            ## Not a skip: the invariant must actually be exercised. A CI lacking
            ## unprivileged user namespaces is misconfigured, not exempt. Report
            ## the ACTUAL failure (unshare stderr + governing /proc knobs + caps),
            ## never a guessed cause -- the real reason drives the fix.
            self.fail(
                "unprivileged user namespaces unavailable (unshare rc=%d): "
                "cannot exercise the namespace-propagation invariant.\n"
                "unshare stderr: %s\nenv: %s\n"
                "Enable them (ubuntu-24.04: sysctl "
                "kernel.apparmor_restrict_unprivileged_userns=0); this is an "
                "environment bug, not a reason to skip."
                % (probe.returncode, probe.stderr.strip(), _userns_env_diag()))

    def _run_probe(self):
        result = subprocess.run(
            ["unshare", "--map-root-user", "--mount", "--", "bash", "--", PROBE],
            capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(
            result.returncode, 0,
            "probe exited %d\nSTDOUT:\n%s\nSTDERR:\n%s"
            % (result.returncode, result.stdout, result.stderr))
        data = {}
        for line in result.stdout.splitlines():
            key, sep, value = line.partition("=")
            if sep:
                data[key.strip()] = value.strip()
        self.assertEqual(
            data.get("PROBE_OK"), "1",
            "probe did not complete:\n%s" % result.stdout)
        return data, result

    @staticmethod
    def _has_noexec(opts: str) -> bool:
        return "noexec" in opts.split(",")

    def test_global_ns_remount_does_not_reach_session_ns(self) -> None:
        data, result = self._run_probe()
        for key in (
                "GLOBAL_HOME_OPTS", "GLOBAL_TB_PRE_OPTS", "A_SESSION_TB_OPTS",
                "GLOBAL_TB_AFTER_A_OPTS", "B_GLOBAL_TB_OPTS", "B_SESSION_TB_OPTS"):
            self.assertIn(key, data, "probe omitted %s:\n%s" % (key, result.stdout))

        ## Premises: /home noexec (level 3) and a fresh ~/.tb inherits it.
        self.assertTrue(
            self._has_noexec(data["GLOBAL_HOME_OPTS"]),
            "global /home must be noexec: %r" % data["GLOBAL_HOME_OPTS"])
        self.assertTrue(
            self._has_noexec(data["GLOBAL_TB_PRE_OPTS"]),
            "a fresh ~/.tb must inherit /home noexec: %r" % data["GLOBAL_TB_PRE_OPTS"])

        ## Mechanism A: a session-local remount makes ~/.tb exec for that session...
        self.assertFalse(
            self._has_noexec(data["A_SESSION_TB_OPTS"]),
            "session-local remount must make ~/.tb exec in the session: %r"
            % data["A_SESSION_TB_OPTS"])
        ## ...without leaking back into the global namespace (make-private holds).
        self.assertTrue(
            self._has_noexec(data["GLOBAL_TB_AFTER_A_OPTS"]),
            "a session-local remount must not leak into the global namespace: %r"
            % data["GLOBAL_TB_AFTER_A_OPTS"])

        ## Mechanism B: the global remount DID drop noexec in the global namespace...
        self.assertFalse(
            self._has_noexec(data["B_GLOBAL_TB_OPTS"]),
            "global remount should drop noexec in the global namespace: %r"
            % data["B_GLOBAL_TB_OPTS"])
        ## ...but the already-unshared session namespace never sees it. This is the
        ## invariant: a launch-time global-ns remount cannot lift noexec for TB.
        self.assertTrue(
            self._has_noexec(data["B_SESSION_TB_OPTS"]),
            "REGRESSION: a global-ns remount reached an already-unshared session "
            "namespace (mechanism B would then work), contradicting the "
            "cross-namespace isolation premise: %r" % data["B_SESSION_TB_OPTS"])


if __name__ == "__main__":
    unittest.main()
