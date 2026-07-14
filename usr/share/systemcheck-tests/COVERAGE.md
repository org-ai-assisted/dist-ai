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
5. **Isolated scenario tests** - `run_check_scenario_isolated` runs the same way
   but inside a bubblewrap mount namespace, so checks gated on absolute-path
   files (`[ -f /usr/share/qubes/marker-vm ]`) or that call a binary by absolute
   path can be steered: overlay a tmpfs to hide a guard file, `touch` one to make
   it present, or bind a fake executable over the real one. These SkipTest when
   bubblewrap / unprivileged user namespaces are unavailable.

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
| check_grub_security         | yes | yes | -   | isolated: Enabled/Disabled + qubes/VM skip |
| check_full_disk_encryption  | yes | -   | -   | isolated: Enabled/Partial/Disabled via fake crypt-check |
| check_tirdad_module         | yes | yes | -   | isolated: loaded / missing-fails / qubes-benign |

## Coverage gaps (ranked)

**G1. Checks gated on absolute-path files (PARTLY CLOSED).** Plain
`run_check_scenario` can stub bare commands and set globals, but not a guard like
`[ -f /usr/share/qubes/marker-vm ]`, `[ -d /sys/firmware/efi ]`, or
`[ -f /run/qubes/... ]`. `run_check_scenario_isolated` now handles these via a
bubblewrap mount namespace and is applied to check_grub_security,
check_full_disk_encryption, and check_tirdad_module. STILL TODO (same harness,
just more scenarios): check_secure_boot (`/sys/firmware/efi` + mokutil + the
`dkms_mok_variables_set` sourced helper), the check_qubes.* family,
check_stream_isolation, check_anondate, check_control_port_filter,
check_network_interfaces, check_warrant_canary, check_unrestricted_mode_in_template,
and the check_tor.* family.

**G2. Checks that invoke a binary by absolute path (PARTLY CLOSED).** A bash
function stub only shadows bare names. `run_check_scenario_isolated(bind_execs=)`
binds a fake executable over the absolute path; done for
check_full_disk_encryption's `/usr/libexec/systemcheck/crypt-check`. STILL TODO:
check_apparmor (`/usr/bin/disallowed-test`).

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

For a check gated on an absolute path, use the isolated runner:

    r = run_check_scenario_isolated(
        os.path.join(self.dir, "check_foo.bsh"), "check_foo",
        env_setup="systemcheck_virtualizer_detected=none",
        hide_dirs=["/usr/share/qubes"],                       # make marker-vm absent
        place=[("/usr/share/qubes/marker-vm", "", False),     # or make it present
               ("/usr/libexec/systemcheck/foo",              # replace a binary
                "#!/bin/bash\nexit 1\n", True)])

`r.records` is a list of `(channel, severity, message)`; helpers: `has_severity`,
`severities`, `messages`, `joined`.
