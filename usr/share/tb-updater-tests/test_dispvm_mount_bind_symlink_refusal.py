#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Behavioral proof that the tb-updater dispvm home binds refuse a symlinked
mountpoint.

The other dispvm tests STUB mount (record argv), so the suite asserted the
no-canonicalize directive is PRESENT but never that it WORKS. This test runs
REAL 'mount --bind' in a private mount namespace (companion dispvm_bind_probe.sh)
to prove the mechanism dispvm relies on, AND its envelope:

  * plain 'mount --bind' onto a BARE dir-symlink target -> FOLLOWS (the CWE-59
    root symlink-follow LPE). CANARY / positive control: if this does not
    follow, the environment cannot exhibit the bug and the proof is vacuous.
  * 'mount --no-canonicalize --bind' (bare target)       -> REFUSES.
  * 'mount --bind -o X-mount.nocanonicalize' (bare)      -> REFUSES (equivalent;
    the form the shipped dispvm uses).
  * same option but a TRAILING-SLASH target              -> FOLLOWS. Envelope
    limit: a trailing slash/dot makes the kernel resolve THROUGH the symlink at
    mount(2) time, outside mount(8)'s no-canonicalize. dispvm is unaffected -- it
    passes bare dir targets AND the '[ -L ]' reject (pre-mount, pre-session)
    catches every symlink form first; no-canonicalize is only a backstop.

Full envelope (file-symlink etc.): org-ai-assisted/mount-nocanonicalize-symlink-refusal.

Namespace availability: CI provides a user+mount namespace by design (the
reusable-dist-ai-tests container adds SYS_ADMIN + unconfines apparmor/seccomp),
and running as root provides one anywhere. Unlike dm-help-steps-tests (whose
runner self-elevates to root), this pytest suite runs non-root, so on a hardened
non-root host unprivileged user namespaces may be denied outright -- a genuine
environment limitation, not a code defect. There it SKIPS rather than false-red;
it still runs for real in CI and as root, and the authoritative, hard-gated
behavioral proof lives in org-ai-assisted/mount-nocanonicalize-symlink-refusal.
"""

import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE = os.path.join(HERE, "dispvm_bind_probe.sh")

## Generous: three unshare+mount runs, each trivial.
PROBE_TIMEOUT = 120.0

## Exit status the probe uses when no mount namespace can be created.
NO_NAMESPACE_RC = 3


def _verdicts(stdout):
    """Parse the probe's 'MODE=<m> VERDICT=<v>' lines into {mode: verdict}."""
    result = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("MODE="):
            continue
        fields = dict(tok.split("=", 1) for tok in line.split() if "=" in tok)
        if "MODE" in fields and "VERDICT" in fields:
            result[fields["MODE"]] = fields["VERDICT"]
    return result


def test_dispvm_mount_bind_symlink_refusal():
    if not os.path.isfile(PROBE):
        pytest.fail(f"probe script missing: {PROBE}")
    proc = subprocess.run(["bash", PROBE], capture_output=True, text=True,
                          check=False, timeout=PROBE_TIMEOUT)

    if proc.returncode == NO_NAMESPACE_RC or "VERDICT=NO_MOUNT_NAMESPACE" in proc.stdout:
        ## Genuine environment limitation (hardened non-root host: unprivileged
        ## user namespaces denied). CI and root runs DO provide a namespace and
        ## run for real; the hard-gated proof is the dedicated evidence repo.
        pytest.skip("no mount namespace available (run as root or in a "
                    "userns-capable environment such as CI)")

    assert proc.returncode == 0, (
        f"probe failed rc={proc.returncode}\n"
        f"stdout={proc.stdout}\nstderr={proc.stderr}")

    verdicts = _verdicts(proc.stdout)

    ## A mode whose positive control (binding a NORMAL dir) failed cannot speak
    ## to the symlink case -- never let that read as a refusal.
    control_failed = [m for m, v in verdicts.items() if v == "CONTROL_FAILED"]
    assert not control_failed, (
        f"positive control mount failed for mode(s) {control_failed} -- the mount "
        f"form could not bind a normal dir, so its symlink result is meaningless "
        f"(unsupported option or broken env)\n{proc.stdout}")

    ## Canary / positive control: without a no-canonicalize directive the bind
    ## MUST follow the symlink, or the environment cannot exhibit the bug and the
    ## two refusals below would pass vacuously.
    assert verdicts.get("plain") == "FOLLOWED_VULNERABLE", (
        f"canary failed: plain 'mount --bind' must FOLLOW a symlinked target; "
        f"got {verdicts.get('plain')!r}\n{proc.stdout}")

    assert verdicts.get("flag") == "REFUSED_SAFE", (
        f"'mount --no-canonicalize --bind' must REFUSE a symlinked target; "
        f"got {verdicts.get('flag')!r}\n{proc.stdout}")

    assert verdicts.get("opt") == "REFUSED_SAFE", (
        f"'mount --bind -o X-mount.nocanonicalize' (the dispvm form) must REFUSE "
        f"a bare dir-symlink target; got {verdicts.get('opt')!r}\n{proc.stdout}")

    ## Envelope limit (why dispvm must use bare targets): a trailing slash makes
    ## the kernel resolve through the symlink, outside no-canonicalize.
    assert verdicts.get("opt_slash") == "FOLLOWED_VULNERABLE", (
        f"a TRAILING-SLASH target must FOLLOW despite X-mount.nocanonicalize "
        f"(documents the envelope limit); got {verdicts.get('opt_slash')!r}\n{proc.stdout}")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
