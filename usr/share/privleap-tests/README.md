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
| `privleap-tests-fuzz` | no | Randomized parser fuzzer, random seed, coverage report. |
| `privleap-tests-e2e` | sudo | Live `privleapd` over a real socket, in a private mount namespace. |

All commands target the installed privleap by default. Set `PRIVLEAP_REPO` to a
derivative-maker checkout root (the directory containing
`usr/lib/python3/dist-packages/privleap/`) to test that tree instead.

## Files

- `pl_testlib.py` -- shared resolver (installed vs `PRIVLEAP_REPO` vs checkout),
  result accumulator, and account helpers.
- `parser_fuzz.py` -- server-side wire-protocol fuzzer / property test.
- `authorizer_test.py` -- authorization-engine property test / fuzzer.
- `e2e.py` -- live-daemon end-to-end test (re-execs under `sudo unshare`).

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

Live daemon (`e2e.py`):

- an unauthorized action's command never runs (asserted by sentinel-file
  absence), an authorized one does, and the daemon survives a malformed-frame
  barrage with its authorization intact.

## Reproducing a finding

The randomized harnesses print their seed. Re-run with
`--seed <N> --iterations <M>` to reproduce deterministically.
