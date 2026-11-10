#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Static lint of anon-ws-disable-stacked-tor's W^X hardening -- core lane (no root,
no systemd), via the shared dist_ai_wx_lint engine.

The socket-proxyd units are GENERATED. This lints the GENERATOR OUTPUT:
  * ALL usr/lib/systemd/system/anon-ws-disable-stacked-tor_autogen_*.service
    (the 20 shipped autogen proxyds), each asserted against the autogen profile
    (NoExecPaths includes /dev);
  * the hand-written main anon-ws-disable-stacked-tor.service (a different
    NoExecPaths: no /dev, adds the daemon's own writable state dir /var/lib/tor;
    its root ExecStartPre is PermissionsStartOnly-exempt, W^X applies to ExecStart);
  * AND the generator source itself, so a future regeneration cannot silently
    drop the block.

memfd_create is `~`-denied -> SIGSYS (default), correct for these write-nothing
socket-proxyd leaf units. Resolved via ANON_WS_DISABLE_STACKED_TOR_REPO, else the
installed path.
"""

import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_LIB = os.path.join(
    os.path.dirname(os.path.dirname(HERE)), 'lib', 'python3', 'dist-packages')
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

# pylint: disable=wrong-import-position
from dist_ai_wx_lint import (  # noqa: E402
    Lint, denylist_findings, read_text, resolve_unit, self_check)

AUTOGEN_NOEXEC = '/run /tmp /var/tmp /dev/shm /dev'
MAIN_NOEXEC = '/run /tmp /var/tmp /dev/shm /var/lib/tor'

## The block the generator MUST emit (so a regen stays hardened). Kept to the
## directive lines, not the surrounding here-string, so a cosmetic edit does not
## false-fail.
GENERATOR_REQUIRED = (
    'MemoryDenyWriteExecute=yes',
    'SystemCallArchitectures=native',
    'LockPersonality=yes',
    'SystemCallFilter=~memfd_create',
    'NoExecPaths=/run /tmp /var/tmp /dev/shm /dev',
    'NoNewPrivileges=yes',
)


def main() -> int:
    self_check()
    lint = Lint('anon-ws-disable-stacked-tor W^X static lint')

    systemd_dir, repo_set = resolve_unit(
        'ANON_WS_DISABLE_STACKED_TOR_REPO', 'usr/lib/systemd/system')
    autogens = sorted(glob.glob(os.path.join(
        systemd_dir, 'anon-ws-disable-stacked-tor_autogen_*.service')))
    if repo_set:
        lint.assert_true(
            'generated autogen socket-proxyd units present',
            bool(autogens), 'none under %s' % systemd_dir)
    for path in autogens:
        lint.lint_file(
            path, repo_set,
            lambda text: denylist_findings(text, noexecpaths=AUTOGEN_NOEXEC))

    lint.check_unit(
        'ANON_WS_DISABLE_STACKED_TOR_REPO',
        'usr/lib/systemd/system/anon-ws-disable-stacked-tor.service',
        lambda text: denylist_findings(text, noexecpaths=MAIN_NOEXEC))

    ## Lint the generator SOURCE too: the shipped autogen units are regenerated at
    ## runtime with the real gateway IP, so the generator is the true source of
    ## truth for the block -- assert it still emits every directive. SCOPE: this is
    ## a SECONDARY "the directive is still emitted at all" guard; the AUTHORITATIVE
    ## semantic lint is on the emitted autogen .service files above (denylist_findings
    ## fail-closes on a weakened block). So trailing content after a matched directive
    ## on the generator line does not weaken the gate -- a real regression reaches the
    ## emitted files and is caught there.
    gen_path, gen_repo_set = resolve_unit(
        'ANON_WS_DISABLE_STACKED_TOR_REPO',
        'usr/libexec/anon-ws-disable-stacked-tor/systemd-unit-files-generator')
    if os.path.isfile(gen_path):
        ## Match each directive as a WHOLE token on a NON-comment source line,
        ## terminated by end-of-line, whitespace, or the here-string's closing
        ## quote -- so a commented-out copy (# SystemCallFilter=...) or a longer
        ## value ('/dev' vs '/dev/pts') cannot false-match a raw substring.
        gen_lines = [ln.strip() for ln in read_text(gen_path).splitlines()
                     if not ln.strip().startswith('#')]
        for directive in GENERATOR_REQUIRED:
            pattern = re.compile('^' + re.escape(directive) + r'(?:$|\s|")')
            lint.assert_true(
                'generator emits %r' % directive,
                any(pattern.match(line) for line in gen_lines))
        lint.checked += 1
    elif gen_repo_set:
        lint.assert_true('generator present', False, 'missing: %s' % gen_path)

    return lint.finish()


if __name__ == '__main__':
    raise SystemExit(main())
