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
  * Benign case: no 'chown' targets a /home path at all (only the root-owned
    /var/cache/tb-binary tree is chowned). Old code chowned the home paths ->
    FAILS.
  * Pre-existing '.cache' case: a '.cache' that already exists must be
    ownership-fixed as root with '--no-dereference' (not aborted, not followed).
    Old code chowned it WITHOUT '--no-dereference' -> FAILS.
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
## the real filesystem objects; 'setpriv' is a pass-through that runs the command
## after '--' as the test user (a real privilege drop is neither possible nor
## needed here); 'chown'/'mount' record their argv instead of acting.
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
id() {
   case "$1" in
      -u) printf '%s\n' "1000" ;;
      -g) printf '%s\n' "1000" ;;
   esac
}
setpriv() {
   while [ "$1" != "--" ]; do shift; done
   shift
   "$@"
}
chown() { printf 'CHOWN %s\n' "$*" >> "${REC}"; return 0; }
mount() { printf 'MOUNT %s\n' "$*" >> "${REC}"; return 0; }
"""


def _drive(tmp_path, *, planted=None, victim=None, precreate=()):
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


def test_benign_run_never_chowns_a_home_path(tmp_path):
    """With no symlink planted, no 'chown' may target a /home path: the fix
    creates them as the user, chowning only the root-owned tb-binary tree."""
    proc, home, rec_lines = _drive(tmp_path)

    assert proc.returncode == 0, (
        f"benign run failed; rc={proc.returncode}\n"
        f"stdout={proc.stdout}\nstderr={proc.stderr}\nrec={rec_lines}"
    )
    home_str = str(home)
    offending = [line for line in rec_lines
                 if line.startswith("CHOWN ") and home_str in line]
    assert not offending, (
        f"root chowned a user-home path (symlink-follow surface): {offending}"
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


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
