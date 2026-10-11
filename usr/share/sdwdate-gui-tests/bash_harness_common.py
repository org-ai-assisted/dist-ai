#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Shared helpers for the sdwdate-gui bash-script unit tests.

The three sdwdate-gui-qubes-* scripts are source-able: their strict-mode block
and their main loop run only when the script is executed, not when it is
sourced. A test therefore sources the real script in a bash harness and calls
its functions directly -- no copy, no path rewriting. These helpers locate the
script, resolve the helper-scripts package so check_runtime.bsh sources
in-tree, and run a harness that sources the script and calls into it.
"""

import os
import subprocess
import tempfile
import textwrap
from pathlib import Path


def locate_script(name: str) -> Path:
    """
    Resolve usr/libexec/sdwdate-gui/<name> relative to the importable
    sdwdate_gui module, mirroring how the package installs it.
    """

    try:
        import sdwdate_gui  # pylint: disable=import-outside-toplevel
    except ModuleNotFoundError as exc:  # pragma: no cover
        import subject_guard  # pylint: disable=import-outside-toplevel

        subject_guard.skip_if_subject_absent(exc)
    start = Path(sdwdate_gui.__file__).resolve()
    for ancestor in start.parents:
        candidate = ancestor / 'libexec' / 'sdwdate-gui' / name
        if candidate.is_file():
            return candidate
    ## The module imported, so the sdwdate-gui package IS present; a missing
    ## libexec script is a broken install, not an absent subject. Fail loud --
    ## a SkipTest here reads as success (dist-ai CLAUDE.md: a required subject's
    ## absence is FATAL, never a silent skip) and would mask the bash tests
    ## vanishing while the python tests still pass the suite green.
    ## The module imported, so the sdwdate-gui package IS present; a missing
    ## libexec script is a broken install, not an absent subject. Fail loud --
    ## a SkipTest here reads as success (dist-ai CLAUDE.md: a required subject's
    ## absence is FATAL, never a silent skip) and would mask the bash tests
    ## vanishing while the python tests still pass the suite green.
    raise RuntimeError(
        f"sdwdate_gui is importable but its '{name}' script is missing from "
        'the package layout; the sdwdate-gui install is broken'
    )


def helper_scripts_path(script: Path) -> str:
    """
    Resolve the helper-scripts package root so the script's
    'source ${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/check_runtime.bsh'
    resolves in-tree. Returns '' (the installed absolute path) when the sibling
    package checkout is not found.
    """

    for ancestor in script.parents:
        candidate = ancestor / 'helper-scripts'
        if (
            candidate
            / 'usr'
            / 'libexec'
            / 'helper-scripts'
            / 'check_runtime.bsh'
        ).is_file():
            return str(candidate)
    return ''


def run_sourced(
    script: Path, body: str, env_extra: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    """
    Run a bash harness that sources `script` and then executes `body` (a shell
    snippet, dedented automatically). SDWDATE_GUI_SCRIPT holds the script path
    for the harness to source. Returns the CompletedProcess.
    """

    env = dict(os.environ)
    env['SDWDATE_GUI_SCRIPT'] = str(script)
    hsp = helper_scripts_path(script)
    if hsp:
        env['HELPER_SCRIPTS_PATH'] = hsp
    if env_extra:
        env.update(env_extra)

    harness = '#!/bin/bash\n' + textwrap.dedent(body)
    with tempfile.NamedTemporaryFile(
        'w', suffix='.sh', delete=False, encoding='utf-8'
    ) as handle:
        handle.write(harness)
        harness_path = handle.name
    try:
        return subprocess.run(
            ['/bin/bash', harness_path],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    finally:
        os.unlink(harness_path)
