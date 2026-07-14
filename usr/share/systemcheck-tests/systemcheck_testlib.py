#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Shared helpers for the systemcheck test suite.

Resolves the systemcheck sources under test:
  * SYSTEMCHECK_REPO=/path/to/systemcheck -> <repo>/usr/libexec/systemcheck
  * unset                                 -> /usr/libexec/systemcheck (installed)

Also provides a helper to extract a single top-level bash function from a .bsh
fragment and run it in isolation (the fragments cannot be sourced wholesale
because they source sibling files by absolute path).
"""

import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


def systemcheck_dir() -> str:
    """Return the directory holding the systemcheck .bsh fragments."""
    repo = os.environ.get("SYSTEMCHECK_REPO", "").strip()
    if repo:
        cand = os.path.join(repo, "usr", "libexec", "systemcheck")
        if os.path.isdir(cand):
            return cand
        ## SKIP (exit 77) rather than FAIL when the checkout does not have the
        ## expected layout -- mirrors the dist-ai suite convention.
        print(
            f"SYSTEMCHECK_REPO={repo!r} has no usr/libexec/systemcheck; skipping.",
            file=sys.stderr,
        )
        sys.exit(77)
    installed = "/usr/libexec/systemcheck"
    if os.path.isdir(installed):
        return installed
    print("systemcheck sources not found (set SYSTEMCHECK_REPO); skipping.",
          file=sys.stderr)
    sys.exit(77)


def bsh_files() -> list[str]:
    """Absolute paths of every *.bsh fragment plus the log-checker script."""
    directory = systemcheck_dir()
    out = []
    for name in sorted(os.listdir(directory)):
        if name.endswith(".bsh") or name == "log-checker":
            out.append(os.path.join(directory, name))
    return out


def _has_bash_shebang(path: str) -> bool:
    """True if the file's first line is a bash shebang."""
    try:
        with open(path, "rb") as handle:
            first_line = handle.readline(256)
    except OSError:
        return False
    return first_line.startswith(b"#!") and b"bash" in first_line


def bash_scripts() -> list[str]:
    """Absolute paths of EVERY bash script shipped by systemcheck, not just the
    *.bsh fragments: the fragments, the log-checker, the main `systemcheck`
    entrypoint, and every other file carrying a bash shebang (canary,
    canary-daemon, check-env, check_tor_running, crypt-check, pkexec-test,
    updatecheck-daemon, user-sysmaint-split-check, ...).

    Source tree (SYSTEMCHECK_REPO set): walk the checkout, skipping VCS and
    Debian packaging directories. Installed: use the package file list from
    `dpkg -L systemcheck` so no prefix has to be guessed.
    """
    repo = os.environ.get("SYSTEMCHECK_REPO", "").strip()
    if repo and os.path.isdir(repo):
        ## Validate the checkout layout (and SKIP if wrong) exactly like the
        ## installed branch below, so a mis-set SYSTEMCHECK_REPO cannot be
        ## silently walked as if it were the systemcheck source tree.
        systemcheck_dir()
        candidates = []
        skip_dirs = {".git", ".github", "debian"}
        for dirpath, dirs, names in os.walk(repo):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for name in names:
                candidates.append(os.path.join(dirpath, name))
    else:
        ## Trigger the standard SKIP if the sources are not present at all.
        systemcheck_dir()
        try:
            proc = subprocess.run(
                ["dpkg", "-L", "systemcheck"],
                capture_output=True, text=True, check=False,
            )
        except FileNotFoundError:
            ## No dpkg (non-Debian host): SKIP rather than crash, matching the
            ## suite's missing-sources convention.
            print("dpkg not found; cannot enumerate installed scripts; skipping.",
                  file=sys.stderr)
            sys.exit(77)
        if proc.returncode != 0:
            ## Surface the real error instead of silently yielding an empty
            ## list that looks like "package has no files".
            print(f"dpkg -L systemcheck failed (rc={proc.returncode}): "
                  f"{proc.stderr.strip()}", file=sys.stderr)
        candidates = proc.stdout.splitlines()

    scripts = []
    for path in sorted(set(candidates)):
        if not os.path.isfile(path):
            continue
        if path.endswith(".bsh") or os.path.basename(path) == "log-checker" \
                or _has_bash_shebang(path):
            scripts.append(path)
    return scripts


def read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


_FUNC_RE_TMPL = r"^%s\(\) \{\n(.*?)^\}"


def extract_bash_function(path: str, name: str) -> str:
    """
    Return the full definition of a top-level bash function `name` from `path`.
    Assumes the closing brace is at column 0 (the fragment style). Raises
    LookupError if not found.
    """
    text = read(path)
    match = re.search(_FUNC_RE_TMPL % re.escape(name), text, re.DOTALL | re.MULTILINE)
    if not match:
        raise LookupError(f"function {name!r} not found in {path}")
    return f"{name}() {{\n{match.group(1)}}}\n"


def run_bash_function(func_def: str, call: str, env_setup: str = "") -> str:
    """
    Source `func_def`, run `env_setup`, then `call`; return stdout (stripped).
    Runs under a strict-ish bash but WITHOUT nounset (the fragments rely on
    optional globals).
    """
    script = f"set -o errexit\nset -o pipefail\n{env_setup}\n{func_def}\n{call}\n"
    result = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


## Helpers from preparation.bsh that the check fragments call. The scenario
## runner pulls the REAL definitions (so emit_status_line / emit_message output
## is exercised for real) rather than stubbing them.
_EMIT_HELPERS = (
    "output_if_verbose",
    "html_link",
    "emit_status_line",
    "emit_message",
    "leaprun_cmd_describe",
    "remediation_instructions",
    "if_you_know_what_you_are_doing_funct",
)

## Records every message emission. $output_x / $output_cli are variables holding
## a command name, so pointing them at this function captures the severity and
## message a check would have sent to msgcollector, without needing msgcollector.
_SCENARIO_PREAMBLE = r"""
set +e
output_opts=()
__systemcheck_rec() {
  local channel="-" sev="-" msg="" have_msg=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --messagex) channel="x"; shift ;;
      --messagecli) channel="cli"; shift ;;
      --typex|--typecli) sev="${2:--}"; shift 2 2>/dev/null || shift ;;
      --message) msg="${2:-}"; have_msg=1; shift 2 2>/dev/null || shift ;;
      *) shift ;;
    esac
  done
  if [ "$have_msg" = 1 ]; then
    printf 'REC\t%s\t%s\t%s\n' "$channel" "$sev" "${msg//$'\n'/\\n}"
  fi
}
output_x=__systemcheck_rec
output_cli=__systemcheck_rec
output_general=true
verbose="${verbose:-1}"
silent="${silent:-0}"
EXIT_CODE="${EXIT_CODE:-0}"
status_ok='<font color="green">OK.</font>'
PROJECT_NAME="${PROJECT_NAME:-Kicksecure}"
PROJECT_HOMEPAGE="${PROJECT_HOMEPAGE:-https://www.kicksecure.com}"
who_ami="${who_ami:-user}"
"""


class ScenarioResult:
    """The captured emissions of one check-function run."""

    def __init__(self, records, exit_code, stdout, stderr):
        ## records: list of (channel, severity, message) tuples.
        self.records = records
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr

    def severities(self) -> set:
        return {sev for _c, sev, _m in self.records if sev != "-"}

    def has_severity(self, severity: str) -> bool:
        return any(sev == severity for _c, sev, _m in self.records)

    def messages(self) -> list:
        return [msg for _c, _s, msg in self.records]

    def joined(self) -> str:
        return "\n".join(self.messages())


def _all_functions(path: str) -> str:
    """Concatenated definitions of every top-level function in `path`, so a
    check can call its sibling helpers (e.g. check_hostname_field)."""
    names = re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\(\) \{", read(path))
    return "\n".join(extract_bash_function(path, name) for name in dict.fromkeys(names))


def _assemble_scenario_script(check_file: str, call: str, env_setup: str,
                              stubs: str, prefix: str = "") -> str:
    prep = os.path.join(systemcheck_dir(), "preparation.bsh")
    helper_defs = "\n".join(extract_bash_function(prep, h) for h in _EMIT_HELPERS)
    check_defs = _all_functions(check_file)
    return "\n".join([
        _SCENARIO_PREAMBLE, prefix, stubs, env_setup, helper_defs, check_defs,
        call, 'printf "EXITCODE\\t%s\\n" "${EXIT_CODE:-0}"',
    ])


def _parse_scenario_output(proc) -> ScenarioResult:
    records = []
    exit_code = None
    for line in proc.stdout.splitlines():
        if line.startswith("REC\t"):
            _tag, channel, sev, msg = line.split("\t", 3)
            records.append((channel, sev, msg))
        elif line.startswith("EXITCODE\t"):
            exit_code = line.split("\t", 1)[1]
    return ScenarioResult(records, exit_code, proc.stdout, proc.stderr)


def run_check_scenario(check_file: str, call: str, env_setup: str = "",
                       stubs: str = "") -> ScenarioResult:
    """Run one check function in isolation and capture what it emits.

    check_file : absolute path of the check_*.bsh fragment.
    call       : the function invocation, e.g. "check_dpkg".
    env_setup  : bash setting the globals that steer the branch under test.
    stubs      : bash defining stub commands (leaprun, dpkg, hostname, ...) that
                 the check calls as bare names.

    Absolute-path guards (e.g. `[ -f /usr/share/qubes/marker-vm ]`) and binaries
    called by absolute path cannot be steered this way; use
    run_check_scenario_isolated for those.
    """
    script = _assemble_scenario_script(check_file, call, env_setup, stubs)
    ## timeout so a check that blocks on a missing stub (or a bad parse) fails
    ## the test loudly instead of wedging the whole suite/CI run.
    proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                          timeout=30)
    return _parse_scenario_output(proc)


_BWRAP_OK = None


def bwrap_available() -> bool:
    """True if bubblewrap can create an unprivileged mount namespace here.
    Cached; used to SKIP the isolated tests on restricted CI."""
    global _BWRAP_OK
    if _BWRAP_OK is None:
        _BWRAP_OK = False
        if shutil.which("bwrap"):
            try:
                probe = subprocess.run(
                    ["bwrap", "--bind", "/", "/", "--dev", "/dev",
                     "--proc", "/proc", "--tmpfs", "/tmp",
                     "bash", "-c", "true"],
                    capture_output=True, timeout=15)
                _BWRAP_OK = probe.returncode == 0
            except (OSError, subprocess.SubprocessError):
                _BWRAP_OK = False
    return _BWRAP_OK


def run_check_scenario_isolated(check_file: str, call: str, env_setup: str = "",
                                stubs: str = "", hide_dirs=(), create_files=(),
                                bind_execs=None) -> ScenarioResult:
    """Like run_check_scenario, but inside a bubblewrap mount namespace so
    absolute-path guards and binaries can be neutralized:

      hide_dirs    : directories overlaid with an empty writable tmpfs, so the
                     files under them disappear -- e.g. '/usr/share/qubes' makes
                     the marker-vm guard file absent (the non-Qubes branch).
      create_files : absolute paths to create AFTER the overlays (e.g. make
                     '/usr/share/qubes/marker-vm' PRESENT); the parent must be a
                     hide_dirs tmpfs so it is writable.
      bind_execs   : {abs_path: script_body} fake executables bound over the
                     real absolute-path binaries a check calls (e.g.
                     '/usr/libexec/systemcheck/crypt-check').

    SkipTest when bubblewrap or user namespaces are unavailable.
    """
    if not bwrap_available():
        raise unittest.SkipTest(
            "bubblewrap unavailable or unprivileged user namespaces disabled")
    bind_execs = bind_execs or {}
    touches = "\n".join(
        f"mkdir -p -- {shlex.quote(os.path.dirname(p))} && touch -- {shlex.quote(p)}"
        for p in create_files)
    script = _assemble_scenario_script(check_file, call, env_setup, stubs,
                                       prefix=touches)
    cmd = ["bwrap", "--bind", "/", "/", "--dev", "/dev", "--proc", "/proc"]
    for directory in hide_dirs:
        cmd += ["--tmpfs", directory]
    tmp_paths = []
    try:
        for abs_path, body in bind_execs.items():
            fd, tmp = tempfile.mkstemp(prefix="fake_exec_")
            os.write(fd, body.encode())
            os.close(fd)
            os.chmod(tmp, 0o755)
            tmp_paths.append(tmp)
            cmd += ["--ro-bind", tmp, abs_path]
        cmd += ["bash", "-c", script]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
    finally:
        for tmp in tmp_paths:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return _parse_scenario_output(proc)


class SystemcheckTestBase(unittest.TestCase):
    """Base class exposing the resolved source directory + file list."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.dir = systemcheck_dir()
        cls.files = bsh_files()
        cls.preparation = os.path.join(cls.dir, "preparation.bsh")
