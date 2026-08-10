#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Static regression invariants over the systemcheck sources. Each locks in a
hardening / cleanup fix so it cannot silently regress.
"""

import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

from systemcheck_testlib import (
    SystemcheckTestBase,
    extract_bash_function,
    read,
)

## Shell-quote a Python string for safe interpolation into a bash harness.
_q = shlex.quote


def _message_lines(text: str):
    """Yield (lineno, line) for lines that are user-facing (not `true` debug
    statements and not full-line comments)."""
    for num, line in enumerate(text.split('\n'), 1):
        stripped = line.lstrip()
        if stripped.startswith('true ') or stripped.startswith('#'):
            continue
        yield num, line


class TestRegressionInvariants(SystemcheckTestBase):

    def test_no_ascii_arrow_breadcrumbs(self) -> None:
        """' -> ' renders as '-_' in the CLI (strip-markup neuters '>')."""
        for path in self.files:
            for num, line in _message_lines(read(path)):
                self.assertNotIn(
                    ' ->', line,
                    f"{os.path.basename(path)}:{num} still uses a ' ->' arrow",
                )

    def test_no_whonix_gateway_typo(self) -> None:
        for path in self.files:
            self.assertNotIn('Whonix-Gatway', read(path),
                             f"'Whonix-Gatway' typo in {path}")

    def test_output_opts_always_quoted(self) -> None:
        """Unquoted ${output_opts[@]} is SC2068 and re-splits."""
        pat = re.compile(r'(?<!")\$\{output_opts\[@\]\}')
        for path in self.files:
            for num, line in enumerate(read(path).split('\n'), 1):
                self.assertIsNone(
                    pat.search(line),
                    f"{os.path.basename(path)}:{num} unquoted output_opts",
                )

    def test_no_literal_ok_status_token(self) -> None:
        """OK result tokens must use $status_ok, not a literal ok./OK./Ok."""
        bad = re.compile(r'(Result: (Success|OK|Ok|ok)\.|, (ok|OK|Ok)\.)')
        for path in self.files:
            for num, line in _message_lines(read(path)):
                if 'status_ok' in line:
                    continue
                self.assertIsNone(
                    bad.search(line),
                    f"{os.path.basename(path)}:{num} literal OK token: {line.strip()!r}",
                )

    def test_status_ok_defined(self) -> None:
        self.assertRegex(read(self.preparation),
                         r"status_ok='<font color=\"green\">OK\.</font>'")

    def test_shared_helpers_defined(self) -> None:
        """The shared preparation.bsh helpers the check fragments rely on must
        all be defined at column 0."""
        text = read(self.preparation)
        for func in (
            'output_if_verbose',
            'html_link',
            'emit_status_line',
            'emit_message',
            'leaprun_cmd_describe',
            'remediation_instructions',
        ):
            self.assertRegex(text, rf"(?m)^{func}\(\) \{{", f"{func} missing")

    def test_log_checker_neutralizes_journal_html_before_br_add(self) -> None:
        """Behavioral: run the REAL log-checker check_service_logs over crafted
        journal content carrying HTML-active bytes ('<script>', '<a href>') and
        assert the rendered output is HTML-neutralized (no active '<tag>'
        survives) yet newlines still became '<br />'. A source-order lint (the
        old test) passes even when a reorder leaves the sanitize-string output
        unused, so drive the real code and observe what it emits.

        Collaborators stubbed (non-subject): leaprun (privileged journal read)
        and safe-rm (a cross-package tool absent on plain CI). The sanitizer
        (sanitize-string) and the '<br />' inserter (br_add_to_file) are the REAL
        helper-scripts tools -- so the neutralization is exercised end to end.
        """
        log_checker = os.path.join(self.dir, 'log-checker')
        if not os.path.exists(log_checker):
            self.skipTest('log-checker not present')
        ## The subject sanitizes with the bare `sanitize-string` tool; resolve it
        ## on PATH (the runner puts helper-scripts' usr/bin there). Absent ->
        ## SKIP, never a false green: an unsanitized run would pass vacuously.
        sanitize = shutil.which('sanitize-string')
        if sanitize is None:
            self.skipTest('sanitize-string not on PATH (wire helper-scripts)')
        ## helper-scripts root = <root>/usr/bin/sanitize-string; strings.bsh
        ## (br_add_to_file / stcatn helpers, sourced by absolute path in the real
        ## script) lives at <root>/usr/libexec/helper-scripts/strings.bsh.
        hs_root = os.path.dirname(os.path.dirname(os.path.dirname(sanitize)))
        strings_bsh = os.path.join(
            hs_root, 'usr', 'libexec', 'helper-scripts', 'strings.bsh')
        if not os.path.exists(strings_bsh):
            self.skipTest(f"helper-scripts strings.bsh not found at {strings_bsh}")

        ## Extract the REAL function (anti-vacuous: a rename/refactor that drops
        ## it raises LookupError, failing the test loudly instead of passing).
        func_def = extract_bash_function(log_checker, 'check_service_logs')
        self.assertIn('sanitize-string', func_def,
                      'check_service_logs no longer sanitizes journal output')

        ## Crafted journal content: each line matches the search pattern
        ## (error/warn...) so it survives the filters, carries HTML-active bytes,
        ## and embeds a plaintext marker that sanitization keeps -- proving the
        ## real code processed the fixture (anti-vacuous).
        marker_one = 'SANITIZECANARYONE'
        marker_two = 'SANITIZECANARYTWO'
        journal = (
            f'error <script>alert({marker_one})</script>\n'
            f'warning <a href="http://evil.example">{marker_two}</a>\n'
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            harness = '\n'.join([
                'set -o errexit',
                'set -o nounset',
                'set -o errtrace',
                f"export HELPER_SCRIPTS_PATH={_q(hs_root)}",
                f"export TMPDIR={_q(tmpdir)}",
                f"export TMP={_q(tmpdir)}",
                f"source {_q(strings_bsh)}",
                ## Privileged journal reader: emit the crafted content for the
                ## boot read; nothing for the apparmor-info read.
                'leaprun() {',
                '  case "$1" in',
                '    read-journalctl-logs-this-boot|read-journalctl-logs-last-boot)',
                f"      printf '%s' {_q(journal)} ;;",
                '    *) : ;;',
                '  esac',
                '}',
                ## safe-rm is a cross-package binary not present on plain CI;
                ## mock the collaborator with coreutils rm so the path runs
                ## everywhere. Not a production fallback -- a test double.
                'safe-rm() { command rm "$@"; }',
                ## These journal-ignore lists come from config the real script
                ## sources; supply non-matching entries so the fixture survives.
                'journal_ignore_fixed_list=( "ZZZ_NEVER_MATCH_FIXED_ZZZ" )',
                'journal_ignore_patterns_list=( "ZZZ_NEVER_MATCH_PATTERN_ZZZ" )',
                func_def,
                'check_service_logs this_boot',
            ])
            proc = subprocess.run(['bash', '-c', harness],
                                  capture_output=True, text=True, timeout=60)

        self.assertEqual(
            proc.returncode, 0,
            f"log-checker run failed (rc={proc.returncode}): {proc.stdout}")
        out = proc.stdout

        ## Anti-vacuous: the markers prove the real code actually processed the
        ## crafted journal (not an empty/short-circuited run passing on nothing).
        self.assertIn(marker_one, out,
                      f"fixture did not reach the output; got: {out!r}")
        self.assertIn(marker_two, out,
                      f"fixture did not reach the output; got: {out!r}")

        ## Newlines were converted to '<br />' tags.
        self.assertIn('<br />', out, f"no '<br />' in rendered output: {out!r}")

        ## HTML neutralized: no active tag from the journal content survives. The
        ## only legitimate '<' is the injected '<br />'; strip those, then any
        ## remaining '<' is raw journal markup that reached the GUI setHtml path.
        residue = out.replace('<br />', '')
        self.assertNotIn('<', residue,
                         f"raw journal markup survived sanitization: {out!r}")
        self.assertNotIn('<script', out,
                         f"'<script' survived sanitization: {out!r}")
        self.assertNotIn('<a ', out,
                         f"'<a ' anchor survived sanitization: {out!r}")

    def test_no_legacy_stcatn_sanitization_comment(self) -> None:
        """The misleading 'sanitized by ... stcatn' claim must stay gone,
        regardless of how it is reflowed or re-indented (stcatn strips ANSI,
        not HTML, so it never sanitized markup)."""
        services = os.path.join(self.dir, 'check_services.bsh')
        if os.path.exists(services):
            self.assertIsNone(
                re.search(r'sanitized\s+by\s+(?:##\s*)?stcatn', read(services)),
                "check_services.bsh still claims content is 'sanitized by stcatn'",
            )

    def test_parse_cmd_no_duplicate_short_option(self) -> None:
        """No short option (-x) may head two different case patterns -- that was
        the -f/--function vs -f/--mode bug."""
        parse = os.path.join(self.dir, 'parse_cmd.bsh')
        if not os.path.exists(parse):
            self.skipTest('parse_cmd.bsh not present')
        shorts = []
        for line in read(parse).split('\n'):
            stripped = line.strip()
            if not stripped.endswith(')'):
                continue
            ## Collect every short option in a case head, including multi-alias
            ## heads like `-h | --help | -\?)` that the old single-alias regex
            ## missed.
            for token in stripped[:-1].split('|'):
                ## Normalize an escaped `-\?` case head to `-?` so the `?`
                ## short option is captured too, not just alphabetic ones.
                token = token.strip().replace(r'\?', '?')
                if re.fullmatch(r'-[A-Za-z?]', token):
                    shorts.append(token)
        dupes = {s for s in shorts if shorts.count(s) > 1}
        self.assertEqual(dupes, set(), f"duplicate short options: {dupes}")


if __name__ == '__main__':
    unittest.main()
