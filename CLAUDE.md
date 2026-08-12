# dist-ai test conventions

Regression/fuzz suites for derivative-maker packages. Suites: `usr/share/<component>-tests/`.
Runners: `usr/bin/<component>-tests*`. Orchestrator: `usr/bin/dist-ai-tests-all`.

## Test the REAL package scripts -- no synthetic copies

- Drive the ACTUAL scripts from the checkout, never a copy. No `cp`/`install`/`mkdir`
  of a package script into `/usr/libexec` or a temp tree; no script body re-embedded in
  the test. A copy drifts from the source.
- Scripts resolve siblings and helper-scripts via overridable bases:
  `${MSGCOLLECTOR_REPO:-}/usr/libexec/msgcollector/...` and
  `${HELPER_SCRIPTS_PATH:-}/usr/libexec/helper-scripts/...` (unset -> `/usr/libexec`, i.e.
  production is byte-identical). `dist-ai-tests-all`'s wire exports both, pointed at the
  checkouts, so a suite runs the tree in place with nothing written to `/usr/libexec`.
- Extraction (`extract_bash_function` reads the CURRENT script text -> no drift) is
  acceptable for a targeted unit, but the whole real script end-to-end is more faithful --
  prefer it where the script can run headless.

## Require dependencies -- do not stub or reimplement them

- Assume real dependencies (helper-scripts etc.) are present; `exit 77` (SKIP) if genuinely
  absent. Check e.g. `[ -r "${HELPER_SCRIPTS_PATH:-}/usr/libexec/helper-scripts/strings.bsh" ]`.
- NEVER reimplement a helper-scripts function (`is_whole_number`, `has`,
  `validate_safe_filename`, ...). Source the real file or `extract_bash_function` it -- a
  reimplementation drifts (e.g. `is_whole_number` rejects leading zeros; a hand copy did not).
- Stubs ONLY for genuine unit-test isolation -- an external GUI (`yad`, `notify-send`), a
  root/network action, a sink that records output, or forcing a branch of the REAL function.
  Never to paper over a dependency you could simply require.

## Other

- No duplication: shared setup belongs in a sourced helper, not copy-pasted per suite.
- Legacy-free: no dead code, no "was"/"formerly"/"used to" comments. Comment the current WHY.
- Report `N pass, 0 fail, 0 skip`; an unauthorized skip is a failure, not green.

## Known follow-ups (audit, msgcollector-tests is the clean model)

- No shared shell harness: `pass`/`fail` counters + subject-resolution are copy-pasted
  across ~44 `*_test.sh`. Wanted: `dist-ai-tests-common/harness.bash`.
- Fidelity: `session_type_dispatch_test.sh` extracts a trace-line-delimited block (fragile
  -- use a `# BEGIN/END` sentinel or drive real msgdispatcher); `check_returns_not_exits_test.sh`
  re-tests at lower fidelity what `unit_tests_test.sh` already sources.
- Reimplemented `has` remains in `anon-gw-anonymizer-config-tests`, `setup-dist-tests`;
  a stub-mode `validate_safe_filename` in `onion_grater_profile_test.sh` -- require + skip 77 instead.
