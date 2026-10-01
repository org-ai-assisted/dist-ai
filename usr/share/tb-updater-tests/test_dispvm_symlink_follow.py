#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression guard for a root symlink-follow LPE (CWE-59) in tb-updater 'dispvm'.

'dispvm' runs as root from tb-updater-dispvm.service at early boot, only in a
Qubes DispVM, and provisions Tor Browser mount points under /home/<user>. A
Qubes DispVM home is a clone of the DVM Template home, so the unprivileged user
can pre-plant a symlink at .tb / .cache / .cache/tb before the root service
runs. The old code did a bare root 'chown user:user /home/user/.tb' (and
.cache, .cache/tb) with no --no-dereference, so root followed the symlink and
chowned an arbitrary target to the user -- a user->root primitive.

The fix creates the directories AS the user (setpriv, so a symlink can never be
chown-escalated -- EPERM), and guards the root 'mount --bind' targets with an
'[ -L ]' reject. This test drives the REAL 'main' from the shipped script (via
extract_bash_function -- no drift), stubbing only the root/Qubes externals:

  * Symlink case: a pre-planted symlink at a mount point makes the run exit
    nonzero (the reject-guard trips), and no root operation follows it into the
    victim. Old code continued (rc 0) and chowned the victim -> FAILS.
  * Benign case: every root 'chown' of a /home path uses '--no-dereference'
    (so a symlink there could never be followed). Old code chowned the home
    paths WITHOUT '--no-dereference' -> FAILS.
  * Pre-existing '.cache' case: a '.cache' that already exists must be
    ownership-fixed with '--no-dereference' (not aborted, not followed). Old
    code chowned it WITHOUT '--no-dereference' -> FAILS.
  * Session-active case: once the user session (qubes-gui-agent.service) is up
    -- e.g. an upgrade restart -- the mount setup must be skipped entirely, so a
    logged-in attacker cannot win a check-to-use race against 'mount --bind'.
    Old code did no such check and chowned/mounted anyway -> FAILS.
"""

import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import tb_updater_testlib as T  # noqa: E402

try:
    DISPVM = T.dispvm_script()
except SystemExit:
    pytest.skip("tb-updater dispvm not available", allow_module_level=True)


## Stub only the root/Qubes externals so 'main' flows past its early-exit gates
## into the mount-point provisioning. 'mkdir'/'test' stay real so the guard sees
## the real filesystem objects; 'chown'/'mount' record their argv instead of
## acting (no root needed; the symlink-safety is observable from the argv).
PREAMBLE = r"""
ischroot() { return 1; }
has() { return 0; }
qubesdb-read() {
   case "$1" in
      /name) printf '%s\n' "test" ;;
      /qubes-vm-persistence) printf '%s\n' "none" ;;
      /default-user) printf '%s\n' "user" ;;
      *) printf '%s\n' "" ;;
   esac
}
check_valid_linux_user_account_name() { return 0; }
systemctl() { return "${STUB_SYSTEMCTL_RC:-1}"; }
chown() { printf 'CHOWN %s\n' "$*" >> "${REC}"; return 0; }
mount() { printf 'MOUNT %s\n' "$*" >> "${REC}"; return 0; }
"""


def _drive(tmp_path, *, planted=None, victim=None, precreate=(), extra_env=None):
    """Drive the real dispvm 'main' with /home and /var/cache/tb-binary
    redirected into tmp_path. When `planted` is given (e.g. '.tb'), pre-plant it
    as a symlink to `victim` inside the fake home first; each name in `precreate`
    is created as a real directory under the fake home first.

    Returns (CompletedProcess, home_dir, rec_lines)."""
    home = tmp_path / "home"
    (home / "user").mkdir(parents=True)
    cache_src = tmp_path / "tb-binary"
    cache_src.mkdir()
    rec = tmp_path / "rec.log"
    rec.write_text("")

    for rel in precreate:
        (home / "user" / rel).mkdir(parents=True, exist_ok=True)
    if planted is not None:
        link = home / "user" / planted
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(victim)

    replace = {
        "/home/${user_name}": "${TB_TEST_HOME}/${user_name}",
        "/var/cache/tb-binary": str(cache_src),
    }
    env = {"TB_TEST_HOME": str(home), "REC": str(rec)}
    if extra_env:
        env.update(extra_env)
    proc = T.drive_bash_function(DISPVM, "main", preamble=PREAMBLE,
                                 replace=replace, env=env)
    return proc, home, rec.read_text().splitlines()


@pytest.mark.parametrize("planted", [".tb", ".cache", ".cache/tb"])
def test_planted_symlink_is_refused(tmp_path, planted):
    """A pre-planted symlink at ANY of the three mount points (.tb, .cache,
    .cache/tb) must abort the run (guard trips); root must never follow it into
    the victim."""
    victim = tmp_path / "victim"
    victim.mkdir()
    proc, _home, rec_lines = _drive(tmp_path, planted=planted, victim=victim)

    assert proc.returncode != 0, (
        f"run did not refuse symlink at {planted!r}; "
        f"rc={proc.returncode}\nstdout={proc.stdout}\nstderr={proc.stderr}\n"
        f"rec={rec_lines}"
    )
    ## No recorded chown/mount may target the victim the symlink points at.
    victim_str = str(victim)
    assert not any(victim_str in line for line in rec_lines), (
        f"root operation followed the symlink into {victim_str}: {rec_lines}"
    )


def test_home_chowns_use_no_dereference(tmp_path):
    """Every root 'chown' of a user-home path must use '--no-dereference', so a
    pre-planted symlink at that path can never be followed."""
    proc, home, rec_lines = _drive(tmp_path)

    assert proc.returncode == 0, (
        f"benign run failed; rc={proc.returncode}\n"
        f"stdout={proc.stdout}\nstderr={proc.stderr}\nrec={rec_lines}"
    )
    home_str = str(home)
    home_chowns = [line for line in rec_lines
                   if line.startswith("CHOWN ") and home_str in line]
    ## Guard against a vacuous pass: the fix does chown the home mount points.
    assert home_chowns, f"expected the mount points to be chowned: {rec_lines}"
    unsafe = [line for line in home_chowns if "--no-dereference" not in line]
    assert not unsafe, (
        f"root chowned a user-home path without --no-dereference "
        f"(symlink-follow surface): {unsafe}"
    )


def test_preexisting_cache_is_owned_safely_not_aborted(tmp_path):
    """A '.cache' that already exists must be ownership-fixed as root with
    '--no-dereference' (so the unprivileged mkdir of .cache/tb can proceed), not
    left to abort the run and not chowned in a symlink-following way."""
    proc, home, rec_lines = _drive(tmp_path, precreate=[".cache"])

    assert proc.returncode == 0, (
        f"pre-existing .cache aborted the run; rc={proc.returncode}\n"
        f"stdout={proc.stdout}\nstderr={proc.stderr}\nrec={rec_lines}"
    )
    cache_path = str(home / "user" / ".cache")
    cache_chowns = [line for line in rec_lines
                    if line.startswith("CHOWN ") and line.endswith(cache_path)]
    assert cache_chowns, (
        f"pre-existing .cache was not ownership-fixed: {rec_lines}"
    )
    assert all("--no-dereference" in line for line in cache_chowns), (
        f".cache chown did not use --no-dereference: {cache_chowns}"
    )


def test_skips_setup_when_user_session_active(tmp_path):
    """Once the user session is up (a restart during login, e.g. an upgrade),
    the mount setup is skipped entirely -- no chown, no mount -- removing the
    check-to-use race a logged-in attacker could otherwise exploit."""
    proc, home, rec_lines = _drive(tmp_path, extra_env={"STUB_SYSTEMCTL_RC": "0"})

    assert proc.returncode == 0, (
        f"session-active run failed; rc={proc.returncode}\n"
        f"stdout={proc.stdout}\nstderr={proc.stderr}\nrec={rec_lines}"
    )
    home_str = str(home)
    touched = [line for line in rec_lines
               if home_str in line and
               (line.startswith("CHOWN ") or line.startswith("MOUNT "))]
    assert not touched, (
        f"mount setup ran despite an active user session (race window): {touched}"
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
