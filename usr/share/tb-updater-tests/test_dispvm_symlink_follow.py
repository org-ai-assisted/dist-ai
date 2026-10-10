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
runs. A bare root 'chown user:user /home/user/.tb' (or .cache, .cache/tb)
would follow that symlink and chown an arbitrary target to the user -- a
user->root primitive.

dispvm refuses a symlink at any mount point ('[ -L ]' reject before any root
write or bind) and chowns with --no-dereference. This test sources the REAL
dispvm (source-able: main does not auto-run, strict mode stays inside main)
and calls 'main', stubbing only the root/Qubes externals and pointing the
script's path globals at a scratch tree:

  * Symlink case: a pre-planted symlink at a mount point makes the run exit
    nonzero (the reject-guard trips), and no root operation follows it into the
    victim. Old code continued (rc 0) and chowned the victim -> FAILS.
  * Benign case: every root 'chown' of a /home path uses '--no-dereference'
    (so a symlink there could never be followed). Old code chowned the home
    paths WITHOUT '--no-dereference' -> FAILS.
  * Pre-existing '.cache' case: a '.cache' that already exists must be
    ownership-fixed with '--no-dereference' (not aborted, not followed). Old
    code chowned it WITHOUT '--no-dereference' -> FAILS.
  * Packaging contract: the mount TOCTOU is closed by running the service ONLY
    at boot -- debian/rules pins 'dh_installsystemd --no-start' for
    tb-updater-dispvm.service so dpkg never starts/restarts it during a live
    session. Old rules had no such override -> FAILS.
  * Run-once (defense in depth): every attempt (success OR a guard-rejected
    run) stamps a tamper-proof sentinel in root-owned tmpfs /run, and the unit
    skips on that (ConditionPathExists), so ANY re-run this boot is a no-op --
    covering a manual restart (incl. retry of a failed first run) that
    --no-start does not. Old code/unit had neither -> FAILS.
  * Home binds + symlink reject: the user-home bind mounts are raw
    'mount --bind' onto /home/<user>/.tb and .cache/tb (there is no way to stop
    mount dereferencing a symlinked mount point). Their safety rests on the
    '[ -L ] ... exit 1' reject loop that runs BEFORE the binds -- refusing a
    pre-planted symlink at any mount point -- plus the boot-only run-once
    execution above. This test asserts that structural model (binds are raw
    'mount --bind'; the reject precedes them); the behavioral refusal itself is
    driven by test_planted_symlink_is_refused.
"""

import os
import re
import subprocess
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


## Runs after sourcing the real dispvm. Stubs only the root/Qubes externals so
## 'main' flows past its early-exit gates into the mount-point provisioning;
## the real 'has' and account-name validator run. 'mkdir'/'[' stay real so the
## guard sees the real filesystem objects; 'chown'/'mount'/'touch' record their
## argv instead of acting (no root needed; the symlink-safety is observable from
## the argv). The script's path globals are pointed at the scratch tree.
SETUP = r"""
ischroot() { return 1; }
qubesdb-read() {
   case "$1" in
      /name) printf '%s\n' "test" ;;
      /qubes-vm-persistence) printf '%s\n' "none" ;;
      /default-user) printf '%s\n' "user" ;;
      *) printf '%s\n' "" ;;
   esac
}
chown() { printf 'CHOWN %s\n' "$*" >> "${REC}"; return 0; }
mount() { printf 'MOUNT %s\n' "$*" >> "${REC}"; return 0; }
touch() { printf 'TOUCH %s\n' "$*" >> "${REC}"; return 0; }
home_base_dir="${TB_TEST_HOME}"
tb_binary_cache_dir="${TB_TEST_CACHE}"
"""

## Containment rests on the subject reading these globals. A dispvm without
## them would run 'mkdir' against the REAL /home, so refuse to drive it.
REQUIRE = (
    '[[ -v home_base_dir && -v tb_binary_cache_dir ]] || {\n'
    '   printf \'%s\\n\' "dispvm lacks home_base_dir/tb_binary_cache_dir" >&2\n'
    f'   exit {T.DRIVE_UNUSABLE}\n'
    '}'
)


def _drive(tmp_path, *, planted=None, victim=None, precreate=()):
    """Drive the real dispvm 'main' with its home_base_dir and
    tb_binary_cache_dir globals pointed into tmp_path. When `planted` is given (e.g. '.tb'), pre-plant it
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

    env = {"TB_TEST_HOME": str(home), "TB_TEST_CACHE": str(cache_src),
           "REC": str(rec)}
    proc = T.drive_sourced_function(DISPVM, "main", setup=SETUP,
                                    require=REQUIRE, env=env)
    assert proc.returncode != T.DRIVE_UNUSABLE, proc.stderr
    return proc, home, rec.read_text().splitlines()


def test_path_globals_default_to_production_paths():
    """Every behavioral test overrides the path globals, so pin their shipped
    values: a wrong default would make a real DispVM skip provisioning while
    the scratch-tree tests stay green."""
    proc = T.drive_sourced_function(
        DISPVM, "true", require=REQUIRE,
        setup='printf \'%s|%s\' "${home_base_dir}" "${tb_binary_cache_dir}"')
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "/home|/var/cache/tb-binary", proc.stdout


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


def test_dispvm_service_not_started_by_dpkg():
    """The mount TOCTOU is closed by running the service ONLY at boot (before any
    user/qrexec process). debian/rules must pin 'dh_installsystemd --no-start'
    for tb-updater-dispvm.service so dpkg never starts/restarts it mid-session."""
    repo = os.environ.get("TB_UPDATER_REPO", "").strip()
    if not repo:
        pytest.skip("debian/rules is only available from a checkout (TB_UPDATER_REPO)")
    rules = os.path.join(repo, "debian", "rules")
    if not os.path.isfile(rules):
        pytest.skip(f"debian/rules not found ({rules})")
    with open(rules, encoding="utf-8") as handle:
        text = handle.read()
    ## A dh_installsystemd invocation carrying both --no-start and the dispvm
    ## unit, in either order.
    pat = re.compile(
        r"dh_installsystemd\b(?=[^\n]*--no-start)"
        r"(?=[^\n]*tb-updater-dispvm\.service)[^\n]*"
    )
    assert pat.search(text), (
        "debian/rules must pin 'dh_installsystemd --no-start "
        "tb-updater-dispvm.service' so dpkg never starts/restarts the unit "
        "during a live session (mount --bind check-to-use race, CWE-59)"
    )


SENTINEL = "/run/tb-updater-dispvm.done"


@pytest.mark.parametrize("planted", [None, ".tb"])
def test_stamps_run_once_sentinel_even_when_rejected(tmp_path, planted):
    """The /run sentinel is stamped on ANY attempt -- a clean run AND a run the
    symlink guard rejects -- so a failed first attempt cannot be retried into
    the mount race by a manual restart. (Stamping only on success left that
    hole.) Here the rejected case is the one that fails on the old code."""
    victim = None
    if planted is not None:
        victim = tmp_path / "victim"
        victim.mkdir()
    _proc, _home, rec_lines = _drive(tmp_path, planted=planted, victim=victim)

    touched = [line for line in rec_lines
               if line.startswith("TOUCH ") and line.endswith(SENTINEL)]
    assert touched, (
        f"run-once sentinel {SENTINEL} was not stamped (planted={planted!r}): "
        f"{rec_lines}"
    )


def test_dispvm_unit_skips_on_sentinel():
    """The unit must refuse to re-run once the sentinel exists
    (ConditionPathExists), so a restart cannot re-enter the mount setup."""
    repo = os.environ.get("TB_UPDATER_REPO", "").strip()
    if not repo:
        pytest.skip("unit file only available from a checkout (TB_UPDATER_REPO)")
    unit = os.path.join(repo, "usr/lib/systemd/system/tb-updater-dispvm.service")
    if not os.path.isfile(unit):
        pytest.skip(f"unit file not found ({unit})")
    with open(unit, encoding="utf-8") as handle:
        text = handle.read()
    assert re.search(rf"^ConditionPathExists=!{re.escape(SENTINEL)}\s*$",
                     text, re.MULTILINE), (
        f"tb-updater-dispvm.service must carry "
        f"'ConditionPathExists=!{SENTINEL}' for run-once-per-boot"
    )


def test_home_binds_are_raw_mount_guarded_by_symlink_reject():
    """The user-home bind mounts are raw 'mount --bind' onto /home/<user>/.tb and
    .cache/tb. There is no way to stop mount dereferencing a symlinked mount
    point, so their safety rests on (a) the '[ -L ] ... exit 1' reject loop that
    runs BEFORE the binds and refuses a pre-planted symlink at any mount point,
    and (b) the service running only at early boot (asserted by the run-once and
    --no-start tests). This asserts that structural model: each home bind is a
    raw 'mount --bind' and the symlink reject precedes every one of them. The
    behavioral refusal itself is driven by test_planted_symlink_is_refused."""
    with open(DISPVM, encoding="utf-8") as handle:
        text = handle.read()
    lines = text.splitlines()

    ## Locate the reject's 'if [ -L "${tb_mount_point}" ]; then' OPENER -- anchored
    ## to the real if-statement line, so a bare match in a comment cannot stand in
    ## for it. Removing the guard is the regression this guards against.
    reject_idx = None
    for i, line in enumerate(lines):
        if re.match(r'\s*if \[ -L "\$\{tb_mount_point\}" \]; then\s*$', line):
            reject_idx = i
            break
    assert reject_idx is not None, (
        f'dispvm must guard the mount points with an '
        f'\'if [ -L "${{tb_mount_point}}" ]; then\' reject before binding: {DISPVM}'
    )
    ## The guard body (up to its closing 'fi') must exit nonzero on a planted
    ## symlink -- bounded to the block so an 'exit' elsewhere cannot satisfy it.
    guard_body = []
    for line in lines[reject_idx + 1:]:
        if re.match(r'\s*fi\b', line):
            break
        guard_body.append(line)
    assert any(re.match(r'\s*exit [1-9][0-9]*\b', b) for b in guard_body), (
        f"the symlink reject must 'exit' nonzero on a planted symlink: {DISPVM}"
    )

    ## Each persistent-cache bind is a raw 'mount --bind' onto the home mount
    ## point, and must appear AFTER the symlink reject.
    for target in (".tb", ".cache/tb"):
        pat = re.compile(
            rf'mount --bind\b[^\n]*"\$\{{tb_binary_cache_dir\}}/{re.escape(target)}"'
            rf'\s+"\$\{{home_base_dir\}}/\$\{{user_name\}}/{re.escape(target)}"')
        bind_idxs = [i for i, line in enumerate(lines) if pat.search(line)]
        assert bind_idxs, (
            f"the {target} home bind must be a raw 'mount --bind ... "
            f"${{home_base_dir}}/${{user_name}}/{target}': {DISPVM}"
        )
        assert reject_idx < min(bind_idxs), (
            f"the symlink reject (line {reject_idx + 1}) must precede the "
            f"{target} bind (line {min(bind_idxs) + 1}) so a symlinked mount "
            f"point is refused before any bind"
        )


def _helper_scripts_root() -> str:
    return os.environ.get("HELPER_SCRIPTS_PATH", "").strip() or "/"


def test_executed_with_missing_helper_fails_closed(tmp_path):
    """Executed (the boot oneshot) with strings.bsh/has.bsh unresolvable, dispvm
    must abort nonzero. Failing open would 'exit 0' at the 'has qubesdb-read'
    gate and skip the bind mounts while the unit reports success."""
    libexec = tmp_path / "usr" / "libexec" / "helper-scripts"
    libexec.mkdir(parents=True)
    (libexec / "check_runtime.bsh").symlink_to(os.path.join(
        _helper_scripts_root(), "usr/libexec/helper-scripts/check_runtime.bsh"))
    env = dict(os.environ, HELPER_SCRIPTS_PATH=str(tmp_path))
    proc = subprocess.run(["bash", DISPVM], capture_output=True, text=True,
                          env=env, check=False, timeout=T.DRIVE_TIMEOUT)
    assert proc.returncode != 0, (
        "dispvm exited 0 with its helpers missing:\n" + proc.stderr)


def test_sourcing_leaves_caller_shell_options_alone():
    """Sourcing must not switch on errexit/nounset/xtrace in the caller."""
    env = dict(os.environ, HELPER_SCRIPTS_PATH=_helper_scripts_root())
    proc = subprocess.run(
        ["bash", "-c",
         'source "$1" || exit 3\nprintf "%s" "$-"', "bash", DISPVM],
        capture_output=True, text=True, env=env, check=False,
        timeout=T.DRIVE_TIMEOUT)
    assert proc.returncode == 0, proc.stderr
    leaked = set("eux") & set(proc.stdout)
    assert not leaked, f"sourcing leaked shell options: {sorted(leaked)}"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
