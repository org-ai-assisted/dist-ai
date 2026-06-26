# onion-grater profile tests

Reproduction and regression tests for the Whonix
[onion-grater](https://github.com/Whonix/onion-grater) Tor control port filter
profiles, covering the June 2026 deanonymization fix and the follow-up
argument-injection hardening.

## What it tests

onion-grater sits between a Whonix-Workstation and the Gateway's Tor control
port. Each profile whitelists control commands with a regex that is matched as
`re.match(pattern + "$", arg_str)` -- an anchored fullmatch against the
command's **entire** argument string. A trailing wildcard (`.*` / `.+`) on a
command that accepts multiple space-separated tokens therefore lets a
compromised Workstation smuggle extra parameters through the filter to Tor.
That is the class of bug fixed in the Bisq `SETCONF DisableNetwork.*` rule
(upstream commit `a0bc80d`) and in the follow-up tightening of `DEL_ONION`,
`HSFETCH`, `onion_client_auth_add`, and `AUTHCHALLENGE`.

The harness imports the **real** onion-grater module (profile normalization,
the `get_rule` matcher, and the response rewriters) and replays each
application's command sequence through it. For every profile it asserts:

- the legitimate commands the app sends are ALLOWED (proxied to Tor), and
- crafted injection variants are BLOCKED (`510 Command filtered`).

It also reproduces each fixed bug directly: the historical (vulnerable) pattern
and the new pattern are both run through the real matcher, showing the old one
allowed the injection, the new one blocks it, and the legitimate form still
passes. The bootstrap-phase response-rewrite typo (`=*`, which never matched,
versus `=.*`) is reproduced the same way.

No root, no network, and no real Tor are required -- the only stubbed component
is Tor itself, which is exactly what a test must not mutate. The security
boundary being tested (`get_rule` returning a rule -> proxied to Tor, versus
`None` -> filtered) is the real code path.

## Running

The in-process unit/reproduction suite (no root, no network, no real tor):

    onion-grater-tests                 # installed
    python3 onion_grater_profile_test.py   # from a checkout

It targets the **installed** onion-grater (`/usr/lib/onion-grater` +
`/usr/share/doc/onion-grater-merger/examples`) by default. Override with:

    ONION_GRATER_REPO=/path/to/onion-grater-checkout onion-grater-tests

Exit `0` means every check passed, `1` means a check failed, `77` means the
onion-grater source was not found (skip).

## Validating that the tests are not vacuous

Run the suite against the pre-fix tree to confirm it actually catches the
regression (the injection cases flip to ALLOW and the bootstrap rewrite goes
dead):

    cd ~/derivative-maker/packages/whonix/onion-grater
    git worktree add --detach /tmp/og-prefix <pre-fix-commit>
    ONION_GRATER_REPO=/tmp/og-prefix onion-grater-tests   # -> RESULT: FAIL
    git worktree remove --force /tmp/og-prefix

## Full-stack end-to-end test (`e2e.py`)

`e2e.py` runs the real moving parts rather than the matcher in
isolation: a throwaway offline `tor` (DisableNetwork 1, no egress) with a
cookie-authenticated control port, the real `onion-grater` binary filtering it,
and a real Tor control-protocol client connecting over the veth network
(`10.200.1.0/24`) so the `hosts: ['*']` profiles match exactly as a
Whonix-Workstation would. It proves:

- **A.** OLD Bisq profile (`SETCONF DisableNetwork.*`): an injected second
  keyword reaches Tor and changes its config -- the deanonymization vector,
  reproduced live (verified by reading the value back directly from Tor).
- **B.** NEW Bisq profile (`SETCONF DisableNetwork=[01]`): the same injection is
  blocked with `510` and never reaches Tor; the legitimate form still works.
- **C.** onionshare `ADD_ONION`: the legitimate request is rewritten and proxied
  (Tor returns a ServiceID); a `Flags=` injection variant is blocked.

It needs `sudo` (to create `/etc/onion-grater.d/`, the hardcoded drop-in path,
and to add the veth IP) and `tor`. It cleans up both afterwards.

    onion-grater-tests-e2e        # 8/8 checks, RESULT: PASS
    python3 e2e.py                # equivalently, from a checkout

It starts its own Tor on port 9052 and does not touch any system Tor instance.
`e2e.py` also serves as the shared harness module imported by the app drivers
and probes below; runtime artifacts go to a temp dir (override with
`OG_TEST_WORKDIR`), never the source tree.

## Real-application drivers

These run an actual application through the filter, importing the `e2e.py`
harness. They need the app installed plus `sudo` and `tor`. Run directly, e.g.
`python3 /usr/share/onion-grater-tests/bitcoind_drive.py`.

`bitcoind_drive.py` drives the real `bitcoind` against `40_bitcoind.yml`: it
points bitcoind's `-torcontrol` at the filtered control port and confirms
bitcoind's startup `ADD_ONION NEW:ED25519-V3 Port=8333,127.0.0.1:8334` is
matched, rewritten to `Port=8333,<client-address>:8334 Flags=DiscardPK`, and
proxied -- Tor returns a ServiceID and bitcoind advertises its `.onion`
(3/3 PASS with Bitcoin Core 30.2). `bitcoin-qt` uses the identical `torcontrol`
code path, so this covers it too. Note: bitcoind 30.2 rejects the removed
`-upnp` option (Core 29.0+), and onion-grater's forced `Flags=DiscardPK` makes
the onion non-persistent across restarts (the intended Whonix trade-off).

## Adversarial security probes

These fuzz the filter mechanism itself (sudo + tor; run directly):

- `probe_bypass.py` -- with a deliberately minimal profile, throws crafted lines
  (keyword injection via space/tab/NUL/CR/quoting, multi-key, trailing args,
  command smuggling, case/separator tricks) and checks whether any reach Tor.
  Result: none do; the anchored matcher holds.
- `probe_rewrite.py` -- attacks the `ADD_ONION` rewrite: tries to escape the
  forced `{client-address}` target and to leak the onion private key past the
  response redaction. Result: target is inescapable, key never leaks.
- `verify_dos.py` -- measures onion-grater CPU while a client holds a stalled
  partial line open, to confirm the busy-loop DoS (fixed in onion-grater
  `b2ef612`) stays fixed (idle, not ~100% of a core). Safe: bounded 2s window.

## Note: profiles can be stale for current app versions

Driving the real `onionshare-cli` (2.6.3) through the filter showed it connect
and issue real control commands, but the shipped `40_onionshare.yml` blocks
`GETINFO version` and `SETEVENTS ... STATUS_SERVER`, which current onionshare
requires, so it never reaches `ADD_ONION`. That is a pre-existing
profile-staleness (availability) issue, independent of the security fixes, and
worth reporting upstream separately. The security behaviour of the onionshare
`ADD_ONION` path itself is covered by scenario C above and by the unit tests.
