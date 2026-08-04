# privleap-tests

Security regression tests and fuzzers for [privleap](https://github.com/Kicksecure/privleap),
the Kicksecure privilege manager (a root daemon that runs root-configured
actions on request from unprivileged users over per-user Unix sockets).

## Threat model

The only untrusted input is an unprivileged local user writing bytes to
**their own** comm socket (mode `0600`). Config files, PAM configuration, and
the filesystem are root-owned and trusted. The goal of these tests is to
**avoid arbitrary code execution**: a parser bug or an authorization bypass on
that socket is the path by which attacker-controlled input could crash the
daemon or run a command it should not.

Accordingly the fuzzers target exactly the two surfaces an unprivileged
caller can reach:

- the **server-side wire-protocol parser**
  (`PrivleapSession.get_msg` and the framing / tokenizer it calls), and
- the **authorization engine**
  (`authorize_user` / `auth_signal_request` / `is_user_allowed`).

Availability is in scope too. privleapd is how an unprivileged account reaches
a root action, so a daemon that stops answering is a denial of service against
every caller, and a daemon that keeps its systemd watchdog happy while it has
stopped answering is worse: nothing external reports it. The liveness suite
(`unit_test.py`) covers that class directly.

Config parsing and the client tools are covered by `config_test.py` and
`client_test.py`. Config input is root-only and so is not an attack surface,
but it is where an administrator's intent becomes the daemon's authorization
rules, and a parser that drops or mis-merges a rule grants access nobody asked
to grant. `shim.py`/PAM stays out of scope here (it needs root and a real PAM
stack); the e2e backends exercise it.

## Commands

| Command | Root? | What it does |
|---|---|---|
| `privleap-tests` | no | In-process suite, fixed seed (CI): parser fuzzer, authorizer property test, daemon liveness regressions, config parser tests, client tool tests. |
| `privleap-tests-fuzz` | no | Randomized parser fuzzer (hand-rolled, no deps), random seed, coverage report. |
| `privleap-tests-fuzz-atheris` | no | Atheris (libFuzzer) **coverage-guided** parser fuzzer. Needs `pip install atheris`. |
| `privleap-tests-session-fuzz` | sudo | Stateful, concurrent fuzzer of the live daemon's **session state machine** (message sequences, threading), in a private mount namespace. |
| `privleap-tests-e2e` | sudo | Live `privleapd` over a real socket, in a private mount namespace (no host mutation). |
| `privleap-tests-e2e-systemd` | sudo | Same phases against the **real `privleapd.service`** via systemd (production-faithful; mutates + restores the live service). |

| `privleap-tests-coverage` | sudo | Runs both lanes under coverage and reports how much of privleap the suites actually reach. |

All commands target the installed privleap by default. Set `PRIVLEAP_REPO` to a
derivative-maker checkout root (the directory containing
`usr/lib/python3/dist-packages/privleap/`) to test that tree instead.

## Coverage

`privleap-tests-coverage` reports the combined figure. As of the last
measured run both lanes together reach **88%** of privleap
(`privleap.py` 91%, `privleapd.py` 86%, `leapctl.py` 96%, `leaprun.py` 91%,
`shim.py` 70%). The daemon and shim figures come from the live-daemon lane and
cannot be produced any other way.

What that number does NOT cover, and why:

- `main()`'s full startup path opens the real state directory and requires
  root.
- `if __name__ == '__main__'` guards cannot be reached by an import-based
  suite at all.

Getting the live-daemon lane to contribute took four fixes, each hidden behind
the last, and each worth knowing about before touching this again:

1. `setup_env_injection()` mounts a tmpfs over the calling account's home. A
   checkout normally lives there, so the bootstrap, the daemon binary and the
   tests directory all vanished mid-run. `mount_tmpfs_preserving()` binds them
   aside and back.
2. `privleapd_path()` checked for the checkout AFTER that mount, found
   nothing, and silently ran the INSTALLED daemon while reporting a pass for
   the checkout. It now resolves once, before any mount, and refuses to fall
   back.
3. privleapd sets `umask(0o077)` at startup, on purpose, so the coverage data
   its processes write is `0600 root:root` and an unprivileged `coverage
   combine` cannot read it. The runner takes ownership first. That failure was
   invisible because the runner discarded combine's output -- do not
   reintroduce that.
4. privleapd runs the shim from a hardcoded absolute path, which is right for
   a privilege-escalation daemon but means a checkout's shim is never the one
   executed. The harness bind-mounts the checkout's copy over it, and a
   `[paths]` alias maps the executed path back so the data is attributed
   rather than dropped.

So 100% is not a reachable target for this lane, and a reported 100% would
mean the measurement was wrong rather than the coverage complete.

## Files

- `pl_testlib.py` -- shared resolver (installed vs `PRIVLEAP_REPO` vs checkout),
  result accumulator, and account helpers.
- `test_property.py` -- Hypothesis property tests of the pure parser helpers
  (argument-count codec round-trip; `validate_id` charset/length invariants).
  Run by the `privleap-tests` launcher via pytest when `python3-pytest` and
  `python3-hypothesis` are present, skipped cleanly otherwise.
- `parser_fuzz.py` -- server-side wire-protocol fuzzer / property test
  (hand-rolled random + mutational, no external dependency).
- `fuzz_privleap.py` -- Atheris (libFuzzer) coverage-guided harness for the same
  server-side parser, following the ecosystem `fuzz_<pkg>.py` convention
  (`atheris.instrument_imports()` + `FuzzedDataProvider` + `TestOneInput`). It
  feeds each input to a real server-side `get_msg()` and lets only genuine
  findings escape (an uncontrolled exception, or an explicitly-raised type
  confusion / ill-formed accepted message), so Atheris reports them as crashes;
  libFuzzer's own `-timeout` catches a parser hang. Atheris is not in Debian
  (`pip install atheris`); the harness is also ClusterFuzzLite-ready
  (`compile_python_fuzzer fuzz_privleap.py`).
- `authorizer_test.py` -- authorization-engine property test / fuzzer.
- `unit_test.py` -- daemon liveness regressions, in process and without root:
  the systemd watchdog path, the epoll registration bookkeeping, the socket
  list synchronisation between the main and control threads, the action output
  pump, and the constant-time authentication failure delay. Includes an
  in-process daemon that runs privleapd's real main and control loops against
  a sandboxed state directory, so registration defects that only appear in how
  those threads interleave can be reproduced. Every check here is written to
  fail against the code as it was before the corresponding fix.
- `config_test.py` -- configuration parser and config loading: every
  documented rejection, exact parsing of a valid file, unknown accounts being
  skipped rather than granted, duplicate collapsing, the root-ownership
  permission check, and the daemon's merge / refuse behaviour across files.
- `daemon_test.py` -- privleapd's control-message handling and startup
  lifecycle: which accounts get a comm socket and which are refused, destroy
  and prune outcomes, group membership being re-read on every check, control
  session dispatch, the reload result, the second-daemon and state-directory
  startup checks, and the command line. Run by the `privleap-tests` launcher.
- `client_test.py` -- the `leapctl` and `leaprun` client tools driven in
  process against a scripted stand-in daemon: every server reply the protocol
  allows mapped to its exit code and output, and a missing, silent or
  protocol-confused daemon producing a clean non-zero exit rather than a hang
  or a traceback.
- `e2e_lib.py` -- shared live-daemon setup (namespace re-exec, daemon launch,
  config), client, fuzz barrage, and the A/B/C/D security phases, used by the
  e2e backends and the session fuzzer.
- `session_fuzz.py` -- stateful, concurrent fuzzer of the live daemon's session
  state machine: random and directed message sequences (TERMINATE-first,
  signal-then-terminate, double-signal, check-then-signal, partial/interleaved
  sends) from many worker threads at once, asserting the daemon never crashes
  or wedges and that an unauthorized action is never executed regardless of
  ordering. This covers the threading / session-sequencing surface the
  single-frame parser fuzzers do not.
- `e2e.py` -- namespace backend: privleapd as a subprocess in a private mount
  namespace (re-execs under `sudo unshare`); no host mutation.
- `e2e_systemd.py` -- systemd backend: the real `privleapd.service` driven by
  systemd; mutates and restores the live service for a production-faithful run
  (real `Type=notify` env, watchdog, unit sandboxing). Adds a phase E that
  observes the genuine systemd service environment reaching the action.

## Invariants checked

Parser (`parser_fuzz.py`):

- **No crash**: any exception other than a controlled `ValueError` /
  `ConnectionAbortedError` / `socket.timeout` is a finding.
- **No hang**: each `get_msg` is guarded by a `SIGALRM` watchdog.
- **No type confusion**: an accepted message must be a type legal to receive on
  that socket, and its fields must re-validate.
- **No false rejects**: everything the real serializer emits round-trips.
- A documented, non-exploitable laxity is surfaced as a NOTE: trailing bytes
  after a zero-argument message (e.g. `TERMINATE 0`) are ignored.

Authorizer (`authorizer_test.py`):

- **P1** a non-root caller is never authorized for a restricted action without
  a matching user or group rule (the anti-ACE invariant);
- **P2** root is always authorized; **P3** an unrestricted action authorizes
  any existing user; **P4** named-user and named-group grants are honoured;
- **P5** nonexistent authorized names are skipped, a missing caller yields
  `USER_MISSING`, neither crashes;
- equivalence to an independent reference model over thousands of randomized
  action/caller pairs; and oracle hardening (unknown vs forbidden action are
  both `None`).

Live daemon (`e2e.py` / `e2e_systemd.py`, shared phases in `e2e_lib.py`):

- an unauthorized action's command never runs (asserted by sentinel-file
  absence), an authorized one does, and the daemon survives a malformed-frame
  barrage with its authorization intact (the systemd backend detects a crash
  even though `Restart=always` would mask it, by watching `NRestarts`); and
- **PAM / environment injection is impossible**: the harness plants
  `LD_PRELOAD`, `BASH_ENV`, and marker variables in the calling user's
  `~/.pam_environment` and in `/etc/environment` (both isolated to the
  namespace), runs an action as root, and asserts none of them reach the
  action's environment and the `BASH_ENV` hook is never sourced. This holds
  because `privleapd`'s PAM stack contains no `pam_env.so`, the client
  protocol carries no environment, and an action's environment source is
  always the same user it runs as. (Defense-in-depth note, confirmed by the
  systemd backend's phase E: under the real service `shim.py` forwards
  `privleapd`'s entire launch environment to the action without sanitising
  systemd's `NOTIFY_SOCKET` / `WATCHDOG_*` -- they are visibly present in the
  action's env. Not exploitable: they are not attacker-controlled and
  `NotifyAccess=main` rejects the action's PID -- but starting from a minimal
  env would be cleaner.)

## Reproducing a finding

The randomized harnesses print their seed. Re-run with
`--seed <N> --iterations <M>` to reproduce deterministically.

## Where this lives

All of the privleap fuzz/property/e2e tooling lives here in `dist-ai` (the
AI-assisted test-tooling package), not in the privleap source package. The
privleap repo (a derivative-maker submodule) carries only a minimal GitHub CI
workflow that checks out this package and runs these harnesses against a PR
(`PRIVLEAP_REPO=<checkout>`). Keep it that way: new harness/property/fuzz code
goes here; the product packages stay clean.
