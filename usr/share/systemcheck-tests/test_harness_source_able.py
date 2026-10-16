#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Guard for the harness's OWN source-ability assumption.

The suite sources the REAL systemcheck scripts to define their functions for
`declare -f` analysis and unit calls. That is sound only when sourcing has no
side effects. A library fragment just defines functions; an ENTRYPOINT
(systemcheck, updatecheck, canary, log-checker) ends by dispatching its main,
which is harmless on source ONLY behind the
``was_executed "${BASH_SOURCE[0]}"`` guard. WITHOUT that guard, merely sourcing
it runs the whole tool UNSANDBOXED on the host (live network checks, file writes,
cleanup) -- the exact fabricated-signal + host-exposure a review found when the
suite sourced a stale installed `systemcheck` that predated the guard.

systemcheck_testlib refuses a non-source-able subject up front
(`_assert_source_able`, enforced in run_sourced + the scenario assembler + the
log-checker harness). These tests pin that contract with synthetic fixtures
(test doubles for the guard, not subject copies) AND confirm the REAL, guarded
entrypoint is accepted -- so the guard neither runs an unguarded tool nor
false-refuses a correctly guarded one.
"""

import os
import shutil
import tempfile
import unittest

from systemcheck_testlib import (
    SystemcheckTestBase,
    _assert_source_able,
    read,
    run_sourced,
)

## The one canonical source-guard line (the `sourceable` skill's form).
_GUARD = 'if was_executed "${BASH_SOURCE[0]}"; then\n  main "$@"\nfi\n'


class TestAssertSourceAble(unittest.TestCase):
    """_assert_source_able: refuse a subject that executes merely by being
    sourced; accept libraries and correctly guarded entrypoints."""

    def _write(self, text: str) -> str:
        fd, path = tempfile.mkstemp(suffix='.bsh')
        self.addCleanup(os.unlink, path)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(text)
        return path

    def test_library_fragment_is_source_able(self) -> None:
        ## No top-level main dispatch -> always safe to source.
        path = self._write('#!/bin/bash\nmyfunc() { echo hi; }\n')
        _assert_source_able(path)  # must not raise

    def test_guarded_entrypoint_is_source_able(self) -> None:
        ## main dispatch present but behind the was_executed guard -> safe.
        path = self._write('#!/bin/bash\nmain() { echo hi; }\n' + _GUARD)
        _assert_source_able(path)  # must not raise

    def test_unguarded_entrypoint_is_refused(self) -> None:
        ## main dispatch with no guard -> sourcing would run the tool; refuse.
        path = self._write('#!/bin/bash\nmain() { echo hi; }\nmain "$@"\n')
        with self.assertRaisesRegex(AssertionError, 'refusing to source'):
            _assert_source_able(path)

    def test_prefixed_main_dispatch_is_refused(self) -> None:
        ## The real dispatch is `systemcheck_main "$@"`; the prefixed form must
        ## be caught too when unguarded.
        path = self._write(
            '#!/bin/bash\nsystemcheck_main() { echo hi; }\nsystemcheck_main "$@"\n')
        with self.assertRaisesRegex(AssertionError, 'refusing to source'):
            _assert_source_able(path)

    def test_guard_text_only_in_a_comment_is_refused(self) -> None:
        ## The guard string in a COMMENT while the real dispatch is unguarded must
        ## not satisfy the check -- a whole-file substring test accepted it (the
        ## dispatch then runs on source). The guard must enclose the dispatch.
        path = self._write(
            '#!/bin/bash\n'
            '# use was_executed "${BASH_SOURCE[0]}" to guard the dispatch\n'
            'main() { echo hi; }\n'
            'main "$@"\n')
        with self.assertRaisesRegex(AssertionError, 'refusing to source'):
            _assert_source_able(path)

    def test_same_line_guard_is_source_able(self) -> None:
        ## The guard may open on the dispatch line itself (a valid, if unusual,
        ## guarded form); it must be accepted.
        path = self._write(
            '#!/bin/bash\nmain() { echo hi; }\n'
            'if was_executed "${BASH_SOURCE[0]}"; then main "$@"; fi\n')
        _assert_source_able(path)  # must not raise

    def test_guard_text_in_trailing_comment_on_dispatch_is_refused(self) -> None:
        ## The guard string in a TRAILING comment on the UNGUARDED dispatch line
        ## must not vouch for it -- a same-line substring check accepted it, so the
        ## tool ran on source (fail-open). The guard must actually enclose it.
        path = self._write(
            '#!/bin/bash\nmain() { echo hi; }\n'
            'main "$@"   # TODO: wrap in was_executed "${BASH_SOURCE[0]}"\n')
        with self.assertRaisesRegex(AssertionError, 'refusing to source'):
            _assert_source_able(path)

    def test_post_condition_and_dispatch_is_refused(self) -> None:
        ## A dispatch AFTER a `&&` short-circuit runs the tool on source when the
        ## condition holds, yet does not begin the line -- a line-anchored scan
        ## skipped it (fail-open). A whole-line scan must catch it.
        path = self._write(
            '#!/bin/bash\nmain() { echo hi; }\n'
            '[ -n "${SYSTEMCHECK_RUN:-}" ] && main "$@"\n')
        with self.assertRaisesRegex(AssertionError, 'refusing to source'):
            _assert_source_able(path)

    def test_conditional_then_dispatch_unguarded_is_refused(self) -> None:
        ## A dispatch inside a non-was_executed `if ...; then main "$@"; fi` also
        ## runs on source when the condition holds; the `if` prefix must not let it
        ## pass unchecked just because the line does not start with `main`.
        path = self._write(
            '#!/bin/bash\nmain() { echo hi; }\n'
            'if running_as_tool; then main "$@"; fi\n')
        with self.assertRaisesRegex(AssertionError, 'refusing to source'):
            _assert_source_able(path)

    def test_same_line_comment_echoing_guard_is_refused(self) -> None:
        ## Hardens the same-line-guard acceptance: a TRAILING comment that echoes
        ## the full `if was_executed "${BASH_SOURCE[0]}"; then` guard text must not
        ## vouch for an unguarded dispatch (the guard must ENCLOSE the dispatch, not
        ## merely co-occur on the line).
        path = self._write(
            '#!/bin/bash\nmain() { echo hi; }\n'
            'main "$@"  # if was_executed "${BASH_SOURCE[0]}"; then (old guard)\n')
        with self.assertRaisesRegex(AssertionError, 'refusing to source'):
            _assert_source_able(path)

    def test_metachar_preceded_comment_echoing_guard_is_refused(self) -> None:
        ## The dispatch is terminated by `;` and the guard phrase sits in a comment
        ## whose `#` follows the `;` with NO space (a real bash comment). A
        ## whitespace-only comment strip left this un-stripped, so the guard text
        ## falsely vouched for the dispatch -- an unguarded `main "$@"` that runs on
        ## source. The full-line shape match must refuse it.
        path = self._write(
            '#!/bin/bash\nmain() { echo hi; }\n'
            'main "$@";# if was_executed "${BASH_SOURCE[0]}"; then\n')
        with self.assertRaisesRegex(AssertionError, 'refusing to source'):
            _assert_source_able(path)

    def test_closed_guard_then_bare_dispatch_is_refused(self) -> None:
        ## The guard opens AND closes (`then :; fi`), then a BARE dispatch follows on
        ## the same line -- it runs on source, unguarded. A co-occurrence check (guard
        ## text present + a dispatch present) wrongly accepted it; requiring the guard
        ## to ENCLOSE the dispatch refuses it.
        path = self._write(
            '#!/bin/bash\nmain() { echo hi; }\n'
            'if was_executed "${BASH_SOURCE[0]}"; then :; fi; main "$@"\n')
        with self.assertRaisesRegex(AssertionError, 'refusing to source'):
            _assert_source_able(path)


class TestRunSourcedRefusesExecutingSubject(unittest.TestCase):
    """run_sourced must refuse an unguarded entrypoint BEFORE sourcing it, so
    the tool never runs on the host."""

    def test_run_sourced_refuses_and_never_executes(self) -> None:
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        marker = os.path.join(tmp, 'tool-ran')
        fd, script = tempfile.mkstemp(suffix='.bsh')
        self.addCleanup(os.unlink, script)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            ## If this ever gets SOURCED, main runs and drops the marker -- the
            ## canary proving the harness did NOT run it.
            handle.write(
                '#!/bin/bash\n'
                f'main() {{ : > {marker!r}; }}\n'
                'main "$@"\n')
        with self.assertRaisesRegex(AssertionError, 'refusing to source'):
            run_sourced([script], 'true')
        self.assertFalse(
            os.path.exists(marker),
            'run_sourced executed the unguarded subject instead of refusing it')


class TestRealEntrypointIsSourceAble(SystemcheckTestBase):
    """The real, guarded `systemcheck` entrypoint must pass the harness
    source-guard -- the positive side of the guard: no false-refuse of a
    correctly guarded tool.

    This is a STATIC check. The orchestrator sources its ~40 fragments at module
    top level via hardcoded /usr/libexec paths, so actually SOURCING it to prove
    systemcheck_main gets defined requires staging the checkout under bubblewrap;
    that behavioral proof lives in the systemcheck-tests-bwrap suite
    (TestSourceableContract.test_defines_functions_without_running). Here we only
    assert the guard shape the harness relies on."""

    def test_systemcheck_main_body_is_readable(self) -> None:
        systemcheck = os.path.join(self.dir, 'systemcheck')
        ## No false-refuse: _assert_source_able accepts the real, correctly
        ## guarded entrypoint (it would raise on an unguarded dispatch).
        _assert_source_able(systemcheck)  # must not raise
        text = read(systemcheck)
        ## systemcheck_main is defined at column 0, and the was_executed
        ## source-guard is present -- so sourcing defines the function without
        ## dispatching the tool.
        self.assertRegex(text, r'(?m)^systemcheck_main\(\) \{',
                         'systemcheck_main not defined at column 0')
        self.assertRegex(
            text, r'(?m)^if was_executed "\$\{BASH_SOURCE\[0\]\}"; then',
            'was_executed source-guard missing from the entrypoint')


if __name__ == '__main__':
    unittest.main()
