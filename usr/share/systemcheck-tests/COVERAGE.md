# systemcheck test coverage

<!-- AI-Assisted -->

Map of what the suite exercises and where the gaps are. Run everything with:

    SYSTEMCHECK_REPO=/path/to/systemcheck python3 -m pytest usr/share/systemcheck-tests/ -q

## Test layers

1. **Syntax** (`test_syntax.py`) - `bash -n` over EVERY bash script systemcheck
   ships: the `*.bsh` fragments, `log-checker`, the `systemcheck` entrypoint,
   and the sibling scripts (canary, check-env, crypt-check, pkexec-test, ...).
2. **Static invariants** (`test_regression_invariants.py`) - locks in hardening
   / cleanup fixes (output_opts quoting, the shared `$status_ok` token, no
   literal OK tokens, no `->` breadcrumbs, shared helpers defined, log-checker
   sanitizes before br_add, parse_cmd has no duplicate short option).
3. **Helper unit tests** (`test_bash_helpers.py`) - `leaprun_cmd_describe`,
   `remediation_instructions` run in isolation.
4. **Scenario / path tests** (`test_check_scenarios.py`) - run a check function
   in isolation via `run_check_scenario`, stub the commands it calls, and assert
   the SEVERITY it emits (info vs warning vs error) plus `$EXIT_CODE`, driving
   each check down its info / warning / error branches.

## Checks with scenario (branch) coverage

| Check | info | warning | error | notes |
|-------|------|---------|-------|-------|
| check_environment_variables | yes | yes | -   | + verbose-gating + both-channels assertions |
| check_man                   | yes | yes | -   | |
| check_dpkg                  | yes | -   | yes | error fails the run even when not verbose |
| check_hostname              | yes | -   | yes | all-ok / all-wrong / single-field-wrong / machine-skip |
| check_meta_packages         | yes | yes | -   | |
| check_unwanted_packages     | yes | yes | -   | |
| check_user_sysmaint_split   | yes | -   | -   | Installed / Not installed + USER/SYSMAINT session |

## Coverage gaps (ranked)

**G1. Checks gated on absolute-path files cannot be steered in isolation.**
`run_check_scenario` can stub bare commands and set globals, but not a guard
like `[ -f /usr/share/qubes/marker-vm ]`, `[ -d /sys/firmware/efi ]`, or
`[ -f /run/qubes/... ]`. On a Qubes dev host these checks skip; on a bare-metal
CI host they would run against real state (non-deterministic). Affected:
check_full_disk_encryption, check_grub_security, check_secure_boot,
check_tirdad_module, the check_qubes.* family, check_stream_isolation,
check_anondate, check_control_port_filter, check_network_interfaces,
check_warrant_canary, check_unrestricted_mode_in_template, and the check_tor.*
family. FIX: a mount-namespace harness variant (bwrap / `unshare -rm`) that
binds empty tmpfs over the guard paths so the branch under the guard runs
deterministically. Caveat: CI must permit user namespaces.

**G2. Checks that invoke a binary by absolute path are not stubbable.**
A bash function stub only shadows bare names. Affected: check_full_disk_encryption
(`/usr/libexec/systemcheck/crypt-check`), check_apparmor
(`/usr/bin/disallowed-test`). FIX: prepend a fake bin dir to `PATH` AND have the
check call the tool by bare name (small systemcheck refactor), or drop a fake
executable at the absolute path inside a mount-namespace harness (see G1).

**G3. Async / multi-stage checks are only smoke-tested.**
check_operating_system (backgrounds `leaprun apt-get-update`, waits, then
branches on the exit code) and check_tor_bootstrap (progress-bar wait loops)
have many branches reachable only by orchestrating timing and multiple stubbed
stages. Currently covered only by the live `systemcheck --cli` integration run.

**G4. Tractable-but-not-yet-covered checks.** These are stubbable today and are
the cheapest coverage wins to add next: check_timezone (zoneinfo/localtime
files under a temp HOME), check_nonfree (vrms), check_spectre_meltdown,
check_virtualizer, check_entropy.

## Adding a scenario test

    r = run_check_scenario(
        os.path.join(self.dir, "check_foo.bsh"), "check_foo",
        env_setup="vm_lower_case_short=machine\nverbose=1",
        stubs="somecmd() { return 1; }")
    self.assertTrue(r.has_severity("error"))
    self.assertEqual(r.exit_code, "1")

`r.records` is a list of `(channel, severity, message)`; helpers: `has_severity`,
`severities`, `messages`, `joined`.
