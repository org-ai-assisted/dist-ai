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
import unittest

from systemcheck_testlib import SystemcheckTestBase, read


def _message_lines(text: str):
    """Yield (lineno, line) for lines that are user-facing (not `true` debug
    statements and not full-line comments)."""
    for num, line in enumerate(text.split("\n"), 1):
        stripped = line.lstrip()
        if stripped.startswith("true ") or stripped.startswith("#"):
            continue
        yield num, line


class TestRegressionInvariants(SystemcheckTestBase):

    def test_no_ascii_arrow_breadcrumbs(self) -> None:
        """' -> ' renders as '-_' in the CLI (strip-markup neuters '>')."""
        for path in self.files:
            for num, line in _message_lines(read(path)):
                self.assertNotIn(
                    " ->", line,
                    f"{os.path.basename(path)}:{num} still uses a ' ->' arrow",
                )

    def test_no_whonix_gateway_typo(self) -> None:
        for path in self.files:
            self.assertNotIn("Whonix-Gatway", read(path),
                             f"'Whonix-Gatway' typo in {path}")

    def test_output_opts_always_quoted(self) -> None:
        """Unquoted ${output_opts[@]} is SC2068 and re-splits."""
        pat = re.compile(r'(?<!")\$\{output_opts\[@\]\}')
        for path in self.files:
            for num, line in enumerate(read(path).split("\n"), 1):
                self.assertIsNone(
                    pat.search(line),
                    f"{os.path.basename(path)}:{num} unquoted output_opts",
                )

    def test_no_literal_ok_status_token(self) -> None:
        """OK result tokens must use $status_ok, not a literal ok./OK./Ok."""
        bad = re.compile(r'(Result: (Success|OK|Ok|ok)\.|, (ok|OK|Ok)\.)')
        for path in self.files:
            for num, line in _message_lines(read(path)):
                if "status_ok" in line:
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
            "output_if_verbose",
            "html_link",
            "emit_status_line",
            "emit_message",
            "leaprun_cmd_describe",
            "remediation_instructions",
        ):
            self.assertRegex(text, rf"(?m)^{func}\(\) \{{", f"{func} missing")

    def test_log_checker_sanitizes_before_br_add(self) -> None:
        """Journal content must be HTML-neutralized BEFORE br_add_to_file bakes
        in <br/> tags (else the GUI setHtml path is injectable)."""
        log_checker = os.path.join(self.dir, "log-checker")
        if not os.path.exists(log_checker):
            self.skipTest("log-checker not present")
        ## Ignore comment lines so a comment that mentions br_add_to_file does
        ## not skew the order comparison against the actual calls.
        code = "\n".join(
            line for line in read(log_checker).split("\n")
            if not line.lstrip().startswith("#")
        )
        san = code.find("sanitize-string")
        bra = code.find('br_add_to_file "')
        self.assertNotEqual(san, -1, "log-checker does not sanitize journal output")
        self.assertNotEqual(bra, -1, "log-checker has no br_add_to_file call")
        self.assertLess(san, bra,
                        "sanitize-string must run before br_add_to_file")

    def test_no_legacy_stcatn_sanitization_comment(self) -> None:
        """The misleading 'sanitized by ... stcatn' claim must stay gone,
        regardless of how it is reflowed or re-indented (stcatn strips ANSI,
        not HTML, so it never sanitized markup)."""
        services = os.path.join(self.dir, "check_services.bsh")
        if os.path.exists(services):
            self.assertIsNone(
                re.search(r"sanitized by\s+(?:##\s*)?stcatn", read(services)),
                "check_services.bsh still claims content is 'sanitized by stcatn'",
            )

    def test_parse_cmd_no_duplicate_short_option(self) -> None:
        """No short option (-x) may head two different case patterns -- that was
        the -f/--function vs -f/--mode bug."""
        parse = os.path.join(self.dir, "parse_cmd.bsh")
        if not os.path.exists(parse):
            self.skipTest("parse_cmd.bsh not present")
        shorts = []
        for line in read(parse).split("\n"):
            stripped = line.strip()
            if not stripped.endswith(")"):
                continue
            ## Collect every short option in a case head, including multi-alias
            ## heads like `-h | --help | -\?)` that the old single-alias regex
            ## missed.
            for token in stripped[:-1].split("|"):
                if re.fullmatch(r"-[a-zA-Z]", token.strip()):
                    shorts.append(token.strip())
        dupes = {s for s in shorts if shorts.count(s) > 1}
        self.assertEqual(dupes, set(), f"duplicate short options: {dupes}")


if __name__ == "__main__":
    unittest.main()
