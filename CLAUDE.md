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
- Do not extract shell functions (`extract_bash_function`, sed/awk body cuts). To unit-test
  a function, make the subject source-able (**sourceable** skill) and source the real file;
  prefer driving the whole real script end-to-end where it can run headless.

## Require dependencies -- do not stub or reimplement them

- Assume real dependencies are present. A REQUIRED dependency's absence
  (helper-scripts, shfmt, a tool the suite cannot run without) is an ENVIRONMENT
  BUG -> `exit 1` (FATAL), NEVER a skip: a required tool that vanished must fail
  loudly, not quietly stop gating. `exit 77` (SKIP) is ONLY for a genuinely
  OPTIONAL target (an `--e2e`-only service, an opt-in component) AND must carry a
  per-skip `## style-ok: allow-skip: <why optional>` waiver, or R-220 fails the
  gate. Adding an unwaived `exit 77` to go green is the exact silent-pass this
  closes.
- NEVER reimplement a helper-scripts function (`is_whole_number`, `has`,
  `validate_safe_filename`, ...). Source the real file -- a
  reimplementation drifts (e.g. `is_whole_number` rejects leading zeros; a hand copy did not).
- Stubs ONLY for genuine unit-test isolation -- an external GUI (`yad`, `notify-send`), a
  root/network action, a sink that records output, or forcing a branch of the REAL function.
  Never to paper over a dependency you could simply require.

## Other

- No duplication: shared setup belongs in a sourced helper, not copy-pasted per suite.
- Legacy-free: no dead code, no "was"/"formerly"/"used to" comments. Comment the current WHY.
- Report `N pass, 0 fail, 0 skip`; an unauthorized skip is a failure, not green.
- Process-liveness in a test: source `dist-ai-tests-common/proc-lib.bash` and use `proc_dead`
  (a killed-but-unreaped ZOMBIE counts as dead) / `proc_diag`, NEVER a bare `kill -0` -- `kill -0`
  reports a zombie as alive, so a correctly-killed orphan flakes as a false "survivor" under a
  slow-reaping CI-container PID 1. Reproduce a suspected flake with
  `dist-ai-flake-hunt --parallel N --load -- <test>` (reruns under contention, captures failures).

## Known follow-ups (audit, msgcollector-tests is the clean model)

- No shared shell harness: `pass`/`fail` counters + subject-resolution are copy-pasted
  across ~44 `*_test.sh`. Wanted: `dist-ai-tests-common/harness.bash`.
- Fidelity: `session_type_dispatch_test.sh` extracts a trace-line-delimited block (fragile
  -- use a `# BEGIN/END` sentinel or drive real msgdispatcher); `check_returns_not_exits_test.sh`
  re-tests at lower fidelity what `unit_tests_test.sh` already sources.
- Reimplemented `has` remains in `anon-gw-anonymizer-config-tests`, `setup-dist-tests`;
  a stub-mode `validate_safe_filename` in `onion_grater_profile_test.sh` -- require + skip 77 instead.
