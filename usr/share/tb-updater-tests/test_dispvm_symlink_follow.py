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
  * Home binds + symlink reject: each user-home bind mount carries a
    no-canonicalize directive -- either the 'mount --no-canonicalize' flag or
    the equivalent '-o X-mount.nocanonicalize' option (man mount: the flag
    entry points at the option; proven equivalent in
    org-ai-assisted/mount-nocanonicalize-symlink-refusal) -- onto
    /home/<user>/.tb and .cache/tb (bare dir paths). It makes mount REFUSE a
    BARE dir-symlink target at the mount layer (a trailing slash/dot or a file
    symlink is outside this envelope -- see the repo above); it does NOT guard
    the bind SOURCE. So safety rests PRIMARILY on (a) the '[ -L ] ... exit 1'
    reject loop that runs BEFORE the binds and refuses any symlink form at every
    bind SOURCE or TARGET path, and (b) the boot-only run-once execution above;
    the no-canonicalize directive is a mount-layer backstop for the bare-target
    race. This test asserts that
    structural model (each home bind carries a no-canonicalize directive; the
    reject precedes them); the behavioral refusal is driven by
    test_planted_symlink_is_refused / test_planted_symlink_in_cache_source_is_refused
    (stubbed mount) and proven against REAL mount by
    test_dispvm_mount_bind_symlink_refusal.
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
qubes_rw_home_base_dir="${TB_TEST_RW}"
"""

## Containment rests on the subject reading these globals. A dispvm without them
## would run 'mkdir'/'[ -L ]' against the REAL /home and /rw/home, so refuse to
## drive it.
REQUIRE = (
    '[[ -v home_base_dir && -v tb_binary_cache_dir && -v qubes_rw_home_base_dir ]] || {\n'
    '   printf \'%s\\n\' "dispvm lacks home_base_dir/tb_binary_cache_dir/qubes_rw_home_base_dir" >&2\n'
    f'   exit {T.DRIVE_UNUSABLE}\n'
    '}'
)


def _shell_commands(text):
    """Yield (line_index, command) for each shell command in `text`.

    Per physical line: drop a trailing '# comment', then split on the command
    separators ';' '&&' '||' '|' so a flag check binds to the ONE command it
    governs. The regression this guards is a required flag moved onto a sibling
    command on the same line -- 'true --no-canonicalize | mount --bind ...' --
    which a line-wide token check would miss. Used on the real dispvm bash SCRIPT
    (its mount/chown lines); the debian/rules Makefile is handled separately by
    _check_dispvm_no_start, not by this shell matcher.

    A SIMPLE separator match, NOT a shell parser. It deliberately does NOT model
    '&' backgrounding, redirections ('2>&1'), quoting, or backslash line
    continuations: the real dispvm script puts each guarded mount/chown call on
    its own line with none of these, so handling them would be reinventing a bash
    parser (and splitting on '&' or joining '\\'-continuations was shown to
    MIS-parse '2>&1' and a '# comment' continuation). A guarded line written with
    those constructs is out of scope -- caught by review, not by this matcher."""
    out = []
    for i, line in enumerate(text.splitlines()):
        code = line.split("#", 1)[0]
        for cmd in re.split(r';|&&|\|\||\|', code):
            cmd = cmd.strip()
            if cmd:
                out.append((i, cmd))
    return out


def _drive(tmp_path, *, planted=None, cache_planted=None, rw_planted=None,
           victim=None, precreate=()):
    """Drive the real dispvm 'main' with its home_base_dir, tb_binary_cache_dir
    and qubes_rw_home_base_dir globals pointed into tmp_path. When `planted` is given
    (e.g. '.tb'), pre-plant it as a symlink to `victim` inside the fake home
    first; `cache_planted` pre-plants inside the fake bind SOURCE (the tb-binary
    cache); `rw_planted` pre-plants inside the fake /rw/home remount base. Each
    name in `precreate` is created as a real directory under the fake home first.

    Returns (CompletedProcess, home_dir, rec_lines)."""
    home = tmp_path / "home"
    (home / "user").mkdir(parents=True)
    cache_src = tmp_path / "tb-binary"
    cache_src.mkdir()
    rw_home = tmp_path / "rw-home"
    (rw_home / "user").mkdir(parents=True)
    rec = tmp_path / "rec.log"
    rec.write_text("")

    for rel in precreate:
        (home / "user" / rel).mkdir(parents=True, exist_ok=True)
    if planted is not None:
        link = home / "user" / planted
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(victim)
    if cache_planted is not None:
        clink = cache_src / cache_planted
        clink.parent.mkdir(parents=True, exist_ok=True)
        clink.symlink_to(victim)
    if rw_planted is not None:
        rlink = rw_home / "user" / rw_planted
        rlink.parent.mkdir(parents=True, exist_ok=True)
        rlink.symlink_to(victim)

    env = {"TB_TEST_HOME": str(home), "TB_TEST_CACHE": str(cache_src),
           "TB_TEST_RW": str(rw_home), "REC": str(rec)}
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
        setup='printf \'%s|%s|%s\' "${home_base_dir}" "${tb_binary_cache_dir}"'
              ' "${qubes_rw_home_base_dir}"')
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "/home|/var/cache/tb-binary|/rw/home", proc.stdout


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
    ## The reject aborts BEFORE any root chown/mount, so none may be recorded
    ## (the /run sentinel TOUCH precedes the reject loop and is allowed). This is
    ## the real guard: a followed symlink records the UNRESOLVED argv, so a
    ## 'victim not in argv' check would pass vacuously.
    root_ops = [line for line in rec_lines
                if line.startswith(("CHOWN ", "MOUNT "))]
    assert not root_ops, (
        f"a root chown/mount ran despite the symlink reject: {root_ops}"
    )


@pytest.mark.parametrize("cache_planted", [".tb", ".cache", ".cache/tb"])
def test_planted_symlink_in_cache_source_is_refused(tmp_path, cache_planted):
    """A pre-planted symlink at a bind SOURCE under the tb-binary cache (.tb,
    .cache, .cache/tb) must also abort the run. 'chown --recursive' makes the
    cache user-owned and a DispVM cache is a DVM-Template clone, so the source
    side is user-plantable too; mount --no-canonicalize does NOT guard the bind
    source, so the '[ -L ]' reject must cover the cache paths. Old code's reject
    loop checked only the /home targets -> FAILS."""
    victim = tmp_path / "victim"
    victim.mkdir()
    proc, _home, rec_lines = _drive(tmp_path, cache_planted=cache_planted,
                                    victim=victim)

    assert proc.returncode != 0, (
        f"run did not refuse symlinked cache source at {cache_planted!r}; "
        f"rc={proc.returncode}\nstdout={proc.stdout}\nstderr={proc.stderr}\n"
        f"rec={rec_lines}"
    )
    ## Same real guard as the target case: no root chown/mount may run after the
    ## reject (a followed source symlink records the unresolved argv, so a
    ## 'victim not in argv' check would be vacuous).
    root_ops = [line for line in rec_lines
                if line.startswith(("CHOWN ", "MOUNT "))]
    assert not root_ops, (
        f"a root chown/mount ran despite the source symlink reject: {root_ops}"
    )


@pytest.mark.parametrize("rw_planted", [".tb", ".cache", ".cache/tb"])
def test_planted_symlink_in_rw_home_is_refused(tmp_path, rw_planted):
    """A pre-planted symlink at a /rw/home remount path (.tb, .cache, .cache/tb)
    must abort the run. The /rw/home copies are user-writable, so a symlink there
    would make the root 'mount -o remount,nosuid,nodev' follow it (apply the
    flags to an attacker-chosen mount, or crash under errexit). The reject loop
    must cover the remount paths, not only the bind source/target."""
    victim = tmp_path / "victim"
    victim.mkdir()
    proc, _home, rec_lines = _drive(tmp_path, rw_planted=rw_planted, victim=victim)

    assert proc.returncode != 0, (
        f"run did not refuse symlinked /rw/home path at {rw_planted!r}; "
        f"rc={proc.returncode}\nstdout={proc.stdout}\nstderr={proc.stderr}\n"
        f"rec={rec_lines}"
    )
    root_ops = [line for line in rec_lines
                if line.startswith(("CHOWN ", "MOUNT "))]
    assert not root_ops, (
        f"a root chown/mount ran despite the /rw/home symlink reject: {root_ops}"
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


DISPVM_UNIT = "tb-updater-dispvm.service"

## A recipe line this check cannot model: any shell separator / redirection, any
## quote, any make or command substitution ('$'), or a non-leading '#' (make
## passes a recipe '#' to the shell, so it is part of a word there, NOT a
## comment). Such a line is REFUSED (reported), never silently passed -- honest
## scope beats a fragile Makefile/shell parser that lies. A backslash
## continuation is handled before this, by a dedicated refuse.
_COMPLEX_RECIPE = re.compile(r"""[;|&<>'"`$#]""")


def _check_dispvm_no_start(rules_text):
    """Problems (empty list => safe) with the dpkg start-guard for the dispvm
    unit in a debian/rules Makefile. Security property: dpkg must never start or
    restart tb-updater-dispvm.service mid-session (reopens the mount --bind
    check-to-use race, CWE-59), so every dh_installsystemd call that governs the
    unit must carry --no-start.

    HONEST SCOPE, not a parser. It BLESSES exactly one invocation shape -- an
    'override_dh_installsystemd:' target (defined once, a bare rule with no
    prerequisite or target-specific variable) whose recipe lines are each
    'dh_installsystemd [--no-start] <unit>...' (command token exactly
    'dh_installsystemd', every argument either '--no-start' or a plain unit
    name) -- and REFUSES everything else rather than model debhelper's option
    grammar or make/shell syntax. Refused (reported, never silently passed): no
    override (dh auto-runs dh_installsystemd and STARTS the unit); a
    dh_installsystemd outside the override (hook target / sequencer); a Make
    conditional ('ifeq' etc. -- a dead branch must not read as a live target) or
    a 'DH_OPTIONS' assignment (injects options this check never sees); a recipe
    line with a quote, separator, substitution, '#' or backslash continuation;
    and any dh_installsystemd call with an env/path prefix or an unmodeled option
    ('--name X' swallows --no-start, '-p pkg' / '-X unit' still start the dispvm
    unit, '--restart-after-upgrade' restarts it). Nothing is faked green: an
    unmodeled rules file fails loud for human review. OUT OF SCOPE (the run-once
    sentinel and the '[ -L ]' reject are the real race guards, not this one): a
    unit pulled in by another unit's '[Install] Also=', and the generated
    maintainer scripts -- it checks the rules SOURCE under make's 'an override
    replaces the auto call' rule.

    Problems are category-prefixed ('missing-override', 'unparseable:',
    'missing-no-start:', 'no-governing-invocation:') so a canary can assert the
    exact failure mode."""
    lines = rules_text.splitlines()
    problems = []

    ## Make conditionals and DH_OPTIONS change which recipe runs or what options
    ## dh_installsystemd receives; not modeled -> refuse (never read a dead 'ifeq'
    ## branch as a live target, nor miss an injected flag).
    for i, line in enumerate(lines):
        if re.match(r'\s*(?:ifeq|ifneq|ifdef|ifndef|else|endif)\b', line):
            problems.append(f"unparseable: Make conditional at line {i + 1} "
                            f"({line.strip()!r}); which recipe runs is not modeled")
        if "DH_OPTIONS" in line:
            problems.append(f"unparseable: DH_OPTIONS at line {i + 1} can inject "
                            f"dh_installsystemd options this check cannot see")
    if problems:
        return problems

    ## The override target: defined exactly once, as a bare rule (nothing after
    ## the colon -- no prerequisite, no target-specific variable). Else not modeled.
    override_lines = [i for i, line in enumerate(lines)
                      if re.match(r'override_dh_installsystemd\s*:', line)]
    if not override_lines:
        return [f"missing-override: debian/rules has no "
                f"'override_dh_installsystemd' target, so 'dh' auto-runs "
                f"dh_installsystemd and STARTS {DISPVM_UNIT} (mount race, CWE-59)"]
    override_idx = override_lines[0]
    if (len(override_lines) > 1 or not
            re.match(r'override_dh_installsystemd\s*:\s*$', lines[override_idx])):
        return ["unparseable: override_dh_installsystemd is defined more than "
                "once or carries a prerequisite / target-specific variable; "
                "not modeled"]

    ## Its recipe: the consecutive TAB-indented lines right after it (a non-tab
    ## line ends the recipe).
    recipe = []
    recipe_span = set()
    for i in range(override_idx + 1, len(lines)):
        if not lines[i].startswith("\t"):
            break
        recipe.append((i, lines[i]))
        recipe_span.add(i)

    ## dh_installsystemd driven anywhere but the override -- a stray command or an
    ## execute_before/after hook target -- means the dh sequencer handles systemd
    ## in a way this check does not model: refuse, do not guess.
    for i, line in enumerate(lines):
        if re.match(r'execute_(?:before|after)_dh_installsystemd\s*:', line):
            problems.append(f"unparseable: '{line.strip()}' hook target is not "
                            f"modeled (dh sequencer)")
        if i in recipe_span:
            continue
        if re.search(r'\bdh_installsystemd\b', line.split("#", 1)[0]):
            problems.append(f"unparseable: 'dh_installsystemd' outside "
                            f"override_dh_installsystemd (line {i + 1}: "
                            f"{line.strip()!r}); dh sequencer not modeled")

    ## A plain unit-name operand (debhelper matches the installed unit FILE name,
    ## e.g. 'tb-updater-dispvm.service'); never starts with '-'.
    unit_re = re.compile(r'^[A-Za-z0-9@._][A-Za-z0-9@._-]*$')

    governed_ok = 0
    for i, line in recipe:
        ## Strip leading tab(s) and a leading make recipe prefix ('-'/'@'/'+').
        ## Do NOT strip a '#': make passes a recipe '#' to the shell verbatim, so
        ## a LEADING '#' is a shell-comment line (skip) but a '#' elsewhere is
        ## part of a word -> refused via _COMPLEX_RECIPE below.
        code = re.sub(r'^[-@+]+', '', line.lstrip("\t")).strip()
        if not code or code.startswith("#"):
            continue  # blank or a full-line shell comment
        ## A backslash continuation can SPLIT the command name across lines
        ## ('dh_install\' + 'systemd ...'), hiding it from the token check -- so
        ## refuse before looking for the 'dh_installsystemd' word.
        if code.endswith("\\"):
            problems.append(f"unparseable: override recipe line {i + 1} is a "
                            f"backslash line-continuation ({code!r}); not modeled")
            continue
        if not re.search(r'\bdh_installsystemd\b', code):
            continue  # an unrelated command in the override recipe
        if _COMPLEX_RECIPE.search(code):
            problems.append(f"unparseable: override recipe line {i + 1} uses a "
                            f"construct this check does not model ({code!r}); "
                            f"write a plain 'dh_installsystemd [--no-start] <unit>...'")
            continue
        tokens = code.split()
        ## BLESSED shape only: command token exactly 'dh_installsystemd', every
        ## argument '--no-start' or a plain unit name. REFUSE anything else -- an
        ## env/path prefix ('FOO=1 dh_...', '/usr/bin/dh_...') or a value-taking /
        ## unmodeled option ('--name X' swallows --no-start, '-p pkg' / '-X unit'
        ## still start the dispvm unit, '--restart-after-upgrade' restarts it).
        ## Classifying these would reinvent debhelper's option parser; refuse.
        if (tokens[0] != "dh_installsystemd"
                or any(t != "--no-start" and not unit_re.match(t)
                       for t in tokens[1:])):
            problems.append(f"unparseable: override recipe line {i + 1} is a "
                            f"dh_installsystemd call in a form this check does not "
                            f"model ({code!r}); write a plain "
                            f"'dh_installsystemd [--no-start] <unit>...'")
            continue
        units = [t for t in tokens[1:] if t != "--no-start"]
        ## Governs the dispvm unit iff it names the unit OR is bare (no unit
        ## operand -> debhelper processes ALL installed units, incl the dispvm one).
        governs = (not units) or (DISPVM_UNIT in units)
        if not governs:
            continue
        if "--no-start" not in tokens[1:]:
            problems.append(f"missing-no-start: override recipe line {i + 1} "
                            f"governs {DISPVM_UNIT} without --no-start ({code!r}); "
                            f"dpkg would start/restart it mid-session (CWE-59)")
            continue
        governed_ok += 1

    if not problems and governed_ok == 0:
        problems.append(f"no-governing-invocation: no dh_installsystemd in "
                        f"override_dh_installsystemd installs {DISPVM_UNIT} with "
                        f"--no-start, so the unit is not pinned "
                        f"enabled-but-not-started")
    return problems


## Real safe form (the shape of the shipped debian/rules): the dispvm unit pinned
## --no-start, a second unguarded unit that does NOT govern the dispvm one.
_SAFE_RULES = (
    "#!/usr/bin/make -f\n"
    "%:\n"
    "\tdh $@\n"
    "\n"
    "override_dh_installsystemd:\n"
    "\tdh_installsystemd --no-start tb-updater-dispvm.service\n"
    "\tdh_installsystemd tb-updater-first-boot.service\n"
)


def test_check_dispvm_accepts_safe_forms():
    ## Real shipped form, and a bare 'dh_installsystemd --no-start' (governs all
    ## units incl the dispvm one, but carries --no-start).
    assert _check_dispvm_no_start(_SAFE_RULES) == []
    bare_ok = "override_dh_installsystemd:\n\tdh_installsystemd --no-start\n"
    assert _check_dispvm_no_start(bare_ok) == []


def test_check_dispvm_ignores_make_variable_assignment():
    ## (d) FALSE-FAIL in the old flat split: a top-level make assignment whose
    ## name begins 'dh_installsystemd' matched startswith() and was flagged as a
    ## missing-no-start invocation. It is not a command -> must NOT be flagged.
    rules = ("dh_installsystemd_unit = tb-updater-dispvm.service\n"
             "override_dh_installsystemd:\n"
             "\tdh_installsystemd --no-start tb-updater-dispvm.service\n")
    assert _check_dispvm_no_start(rules) == []


@pytest.mark.parametrize("recipe", [
    ## (a) FALSE-PASS in the old flat split: a bare invocation (no unit operand)
    ## carries no literal unit name, so the old filter ignored it although it
    ## starts EVERY unit incl the dispvm one. Here beside a correctly-pinned line,
    ## so the old check passed green while the bare call reopened the race.
    "\tdh_installsystemd --no-start tb-updater-dispvm.service\n\tdh_installsystemd\n",
    ## An explicit invocation missing the pin.
    "\tdh_installsystemd tb-updater-dispvm.service\n",
])
def test_check_dispvm_flags_missing_no_start(recipe):
    rules = "override_dh_installsystemd:\n" + recipe
    problems = _check_dispvm_no_start(rules)
    assert problems and all(p.startswith("missing-no-start:") for p in problems), problems


@pytest.mark.parametrize("recipe", [
    ## (c) a quoted echo of a fake invocation -- the old quote-blind split turned
    ## the quoted string into a command.
    "\techo '; dh_installsystemd --no-start tb-updater-dispvm.service'\n",
    ## (b) a piped / separated second invocation on one physical line.
    "\tdh_installsystemd --no-start tb-updater-dispvm.service | cat\n",
    "\tdh_installsystemd --no-start tb-updater-dispvm.service; true\n",
    ## make substitution and a redirection.
    "\tdh_installsystemd --no-start $(DISPVM_UNIT)\n",
    "\tdh_installsystemd --no-start tb-updater-dispvm.service > /dev/null\n",
])
def test_check_dispvm_refuses_complex_recipe_line(recipe):
    rules = "override_dh_installsystemd:\n" + recipe
    problems = _check_dispvm_no_start(rules)
    assert problems and all(p.startswith("unparseable:") for p in problems), problems


@pytest.mark.parametrize("recipe", [
    ## '--name' takes an argument, so Getopt binds '--no-start' as its value and
    ## the call has NO real --no-start (verified against debhelper 13.24.2); a
    ## classifier that counted '--no-start' as a flag would false-pass.
    "\tdh_installsystemd --name --no-start tb-updater-dispvm.service\n",
    ## A '-p pkg' restriction with no unit operand still starts EVERY unit in the
    ## package incl the dispvm one; a classifier misreads 'pkg' as a unit operand.
    "\tdh_installsystemd --no-start tb-updater-dispvm.service\n"
    "\tdh_installsystemd -p tb-updater\n",
    ## '-X unit' excludes only the named unit; the dispvm unit is still started.
    "\tdh_installsystemd --no-start tb-updater-dispvm.service\n"
    "\tdh_installsystemd -X tb-updater-first-boot.service\n",
    ## '--restart-after-upgrade' restarts the unit on upgrade even with --no-start.
    "\tdh_installsystemd --no-start --restart-after-upgrade tb-updater-dispvm.service\n",
    ## An env prefix or an absolute path is still a real invocation debhelper runs.
    "\tFOO=1 dh_installsystemd tb-updater-dispvm.service\n",
    "\t/usr/bin/dh_installsystemd tb-updater-dispvm.service\n",
])
def test_check_dispvm_refuses_unmodeled_invocation(recipe):
    ## Modeling debhelper's option grammar is the parser-reinvention this check
    ## avoids: any dh_installsystemd call outside the blessed
    ## 'dh_installsystemd [--no-start] <unit>...' shape is refused, not classified.
    rules = "override_dh_installsystemd:\n" + recipe
    problems = _check_dispvm_no_start(rules)
    assert any(p.startswith("unparseable:") for p in problems), problems


@pytest.mark.parametrize("rules", [
    ## (ai-review) A backslash continuation splitting the command name across
    ## lines ('dh_install\\' + 'systemd ...') -- make joins them into a real,
    ## unguarded call; a per-line token check would miss it.
    "override_dh_installsystemd:\n"
    "\tdh_installsystemd --no-start tb-updater-dispvm.service\n"
    "\tdh_install\\\nsystemd tb-updater-dispvm.service\n",
    ## A '#' inside a shell word is NOT a comment to the shell, so make runs the
    ## separated second (unguarded) command after it.
    "override_dh_installsystemd:\n"
    "\tdh_installsystemd --no-start tb-updater-dispvm.service\n"
    "\techo marker#x; dh_installsystemd tb-updater-dispvm.service\n",
    ## A Make conditional: the dead branch's override must not read as live (dh
    ## would then auto-run an unguarded dh_installsystemd).
    "ifeq (1,0)\noverride_dh_installsystemd:\n"
    "\tdh_installsystemd --no-start tb-updater-dispvm.service\nendif\n"
    "%:\n\tdh $@\n",
    ## DH_OPTIONS injects '--restart-after-upgrade' into the otherwise-pinned call.
    "override_dh_installsystemd:\n"
    "\tdh_installsystemd --no-start tb-updater-dispvm.service\n"
    "override_dh_installsystemd: export DH_OPTIONS = --restart-after-upgrade\n",
    ## The override defined twice / with a target-specific variable after the colon.
    "override_dh_installsystemd:\n"
    "\tdh_installsystemd --no-start tb-updater-dispvm.service\n"
    "override_dh_installsystemd: SOMEVAR = x\n",
])
def test_check_dispvm_refuses_unmodeled_makefile(rules):
    ## Modeling make's conditionals, variables, continuations and comment rules
    ## is the parser-reinvention this check avoids: anything but a plain bare
    ## override of simple dh_installsystemd lines is refused, not interpreted.
    problems = _check_dispvm_no_start(rules)
    assert any(p.startswith("unparseable:") for p in problems), problems


def test_check_dispvm_flags_missing_override():
    problems = _check_dispvm_no_start("#!/usr/bin/make -f\n%:\n\tdh $@\n")
    assert problems and all(p.startswith("missing-override") for p in problems), problems


def test_check_dispvm_refuses_stray_invocation():
    ## A dh_installsystemd outside the override (here an execute-after hook) means
    ## the dh sequencer drives systemd handling this check does not model.
    rules = ("override_dh_installsystemd:\n"
             "\tdh_installsystemd --no-start tb-updater-dispvm.service\n"
             "execute_after_dh_installsystemd:\n"
             "\tdh_installsystemd tb-updater-dispvm.service\n")
    problems = _check_dispvm_no_start(rules)
    assert any(p.startswith("unparseable:") for p in problems), problems


def test_dispvm_service_not_started_by_dpkg():
    """The mount TOCTOU is closed by running the service ONLY at boot (before any
    user/qrexec process). debian/rules must pin 'dh_installsystemd --no-start'
    for tb-updater-dispvm.service so dpkg never starts/restarts it mid-session.
    Checked by _check_dispvm_no_start (honest-scope Makefile check)."""
    repo = os.environ.get("TB_UPDATER_REPO", "").strip()
    if not repo:
        pytest.skip("debian/rules is only available from a checkout (TB_UPDATER_REPO)")
    rules = os.path.join(repo, "debian", "rules")
    if not os.path.isfile(rules):
        pytest.skip(f"debian/rules not found ({rules})")
    with open(rules, encoding="utf-8") as handle:
        text = handle.read()
    problems = _check_dispvm_no_start(text)
    assert not problems, (
        "debian/rules must pin 'dh_installsystemd --no-start "
        "tb-updater-dispvm.service' so dpkg never starts/restarts the unit "
        "during a live session (mount --bind check-to-use race, CWE-59):\n"
        + "\n".join(problems)
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


def _has_nocanonicalize(cmd):
    """True if a single mount command carries a no-canonicalize directive that
    protects the mount TARGET, as a proper token: the '--no-canonicalize' CLI
    flag, or the '-o ...,X-mount.nocanonicalize' option in its bare or '=target'
    form. man mount: 'X-mount.nocanonicalize[=type]' with type 'source' or
    'target'; bare disables canonicalization for BOTH. The '=source' form (and
    the invalid '=all', silently ignored) leaves the TARGET canonicalized, so
    mount follows a symlinked target -- those do NOT protect the home bind and
    are REJECTED (verified against real mount in
    org-ai-assisted/mount-nocanonicalize-symlink-refusal). A whole-token match,
    not a bare substring (the command is already comment-stripped and
    separator-split by _shell_commands)."""
    if re.search(r'(?<![\w.-])--no-canonicalize(?![\w.-])', cmd):
        return True
    ## Bare or '=target' only; '=source'/'=all'/'=other' trailing '=' fails the
    ## negative lookahead (which includes '=') so they do not match.
    return bool(re.search(
        r'(?<![\w.-])X-mount\.nocanonicalize(?:=target)?(?![\w.=-])', cmd))


@pytest.mark.parametrize("cmd", [
    'mount --no-canonicalize --bind -o nosuid,nodev -- /s /t',
    'mount --bind -o nosuid,nodev,X-mount.nocanonicalize -- /s /t',
    'mount --bind -o nosuid,nodev,X-mount.nocanonicalize=target -- /s /t',
])
def test_has_nocanonicalize_accepts_target_protecting_forms(cmd):
    assert _has_nocanonicalize(cmd), cmd


@pytest.mark.parametrize("cmd", [
    ## No directive at all.
    'mount --bind -o nosuid,nodev -- /s /t',
    ## '=source' disables canonicalization for the SOURCE only -- target still
    ## followed; '=all' is not a valid type and is silently ignored. Neither
    ## protects the home-bind target, so neither may be accepted as the defense.
    'mount --bind -o nosuid,nodev,X-mount.nocanonicalize=source -- /s /t',
    'mount --bind -o nosuid,nodev,X-mount.nocanonicalize=all -- /s /t',
    'mount --bind -o nosuid,nodev,X-mount.nocanonicalize=anything -- /s /t',
])
def test_has_nocanonicalize_rejects_non_target_forms(cmd):
    assert not _has_nocanonicalize(cmd), cmd


def test_home_binds_nocanonicalize_and_symlink_reject():
    """Each user-home bind mount carries a no-canonicalize directive (the
    'mount --no-canonicalize' flag or the equivalent '-o X-mount.nocanonicalize'
    option) onto /home/<user>/.tb and .cache/tb (bare dir paths). It makes mount
    refuse a BARE dir-symlink target at the mount layer (a trailing slash/dot or
    file symlink is outside this envelope); it does NOT guard the bind source. So
    their safety rests PRIMARILY on (a) the '[ -L ] ... exit 1' reject loop that
    runs BEFORE the binds and refuses any symlink form at any bind source or
    target, and (b) the service running only at early boot (asserted by the
    run-once and --no-start tests); the no-canonicalize directive is a mount-layer
    backstop for the bare-target race. This asserts that structural model: each home bind carries
    a no-canonicalize directive and the symlink reject precedes every one of
    them. The behavioral refusal is driven by test_planted_symlink_is_refused /
    test_planted_symlink_in_cache_source_is_refused (stubbed mount) and proven
    against REAL mount by test_dispvm_mount_bind_symlink_refusal."""
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

    ## Each persistent-cache bind is a 'mount ... --bind' onto the home mount
    ## point, must carry a no-canonicalize directive, and must appear AFTER the
    ## symlink reject.
    for target in (".tb", ".cache/tb"):
        pat = re.compile(
            rf'\bmount\b.*--bind\b.*"\$\{{tb_binary_cache_dir\}}/{re.escape(target)}"'
            rf'\s+"\$\{{home_base_dir\}}/\$\{{user_name\}}/{re.escape(target)}"')
        ## Scan per SHELL COMMAND, not per line: _shell_commands isolates each
        ## 'mount ... --bind ...' invocation past line continuations, comments
        ## and separators. A line-wide regex would let
        ## 'mount --no-canonicalize; mount --bind ...' (or '... | mount --bind')
        ## capture the flag from a DIFFERENT command while the bind lacks it.
        ## The target MUST be a BARE dir path. A trailing slash or '/.' makes the
        ## kernel resolve THROUGH a symlinked mountpoint at mount(2) time, defeating
        ## the no-canonicalize backstop (the [ -L ] reject still guards it, but keep
        ## the backstop intact). A separator sneaks in two ways: INSIDE the closing
        ## quote ("...tb/"), or CONCATENATED after it in any quoting form ("...tb"/,
        ## "...tb"'/', "...tb"$'/', "...tb"\/ -- all one word '.../tb/' to the shell).
        ## Catch the inside form directly; for the outside form, flag a closing quote
        ## immediately followed by a separator-introducing char (/ ' " $ \) -- the
        ## only ways to concatenate a separator. A word TERMINATOR (space ; & | < > ))
        ## ends the operand and is NOT flagged, so a bare target does not false-fail.
        ## SCOPE: a realistic source-edit backstop, not a shell parser -- a separator
        ## hidden behind a '#' (cut as a comment by _shell_commands) or a second
        ## differently-quoted bind to the same target are out of scope; the [ -L ]
        ## reject + no-canonicalize remain the real guards. Independent of pat, which
        ## only matches the bare spelling.
        trailing = [lines[i] for i, cmd in _shell_commands(text)
                    if re.search(rf'--bind\b.*"\$\{{home_base_dir\}}/\$\{{user_name\}}'
                                 rf'/{re.escape(target)}(?:/[./]*"|"(?=[/\x27"$\\]))', cmd)]
        assert not trailing, (
            f"the {target} home bind target has a trailing slash/dot, which defeats "
            f"the no-canonicalize backstop; pass a bare dir path: {trailing} ({DISPVM})")

        binds = [(i, cmd) for i, cmd in _shell_commands(text) if pat.search(cmd)]
        bind_idxs = [i for i, _cmd in binds]
        assert bind_idxs, (
            f"the {target} home bind must be a 'mount ... --bind ... "
            f"${{home_base_dir}}/${{user_name}}/{target}': {DISPVM}"
        )
        ## The mount-layer symlink-refusal guard: every home bind must pass a
        ## no-canonicalize directive -- the '--no-canonicalize' flag or the
        ## equivalent '-o X-mount.nocanonicalize' option (removing it reopens a
        ## symlinked-mountpoint follow). The directive must be an argument of THIS
        ## single mount command -- one on a different command
        ## ('mount --no-canonicalize; mount --bind ...') or in a trailing comment
        ## cannot satisfy it (whole-token, per _has_nocanonicalize).
        for i, cmd in binds:
            assert _has_nocanonicalize(cmd), (
                f"the {target} home bind must carry a no-canonicalize directive "
                f"(--no-canonicalize or -o X-mount.nocanonicalize) as a mount "
                f"argument so mount refuses a symlinked mountpoint: "
                f"{lines[i]!r} ({DISPVM})"
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
