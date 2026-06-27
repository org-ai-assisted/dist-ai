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

Accordingly the harnesses target exactly the two surfaces an unprivileged
caller can reach:

- the **server-side wire-protocol parser**
  (`PrivleapSession.get_msg` and the framing / tokenizer it calls), and
- the **authorization engine**
  (`authorize_user` / `auth_signal_request` / `is_user_allowed`).

Config-file parsing, the client tools, and `shim.py`/PAM are out of scope here
(config input is root-only); the upstream autopkgtest covers protocol
sequencing and config parsing.

## Commands

| Command | Root? | What it does |
|---|---|---|
| `privleap-tests` | no | In-process suite, fixed seed (CI): parser fuzzer + authorizer property test. |
| `privleap-tests-fuzz` | no | Randomized parser fuzzer (hand-rolled, no deps), random seed, coverage report. |
| `privleap-tests-fuzz-atheris` | no | Atheris (libFuzzer) **coverage-guided** parser fuzzer. Needs `pip install atheris`. |
| `privleap-tests-e2e` | sudo | Live `privleapd` over a real socket, in a private mount namespace (no host mutation). |
| `privleap-tests-e2e-systemd` | sudo | Same phases against the **real `privleapd.service`** via systemd (production-faithful; mutates + restores the live service). |

All commands target the installed privleap by default. Set `PRIVLEAP_REPO` to a
derivative-maker checkout root (the directory containing
`usr/lib/python3/dist-packages/privleap/`) to test that tree instead.

## Files

- `pl_testlib.py` -- shared resolver (installed vs `PRIVLEAP_REPO` vs checkout),
  result accumulator, and account helpers.
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
- `e2e_lib.py` -- shared live-daemon setup, client, fuzz barrage, and the
  A/B/C/D security phases, used by both e2e backends.
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
