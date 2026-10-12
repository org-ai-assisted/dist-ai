<!--
Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted
-->

# sdwdate-gui live end-to-end test plan (Qubes multi-VM)

## Why this is a document, not a gating suite

The automated lanes verify everything that runs without a real Qubes install:

- `sdwdate-gui-tests` (unit, offscreen) -- client event loop, wire protocol,
  menu/RPC wiring, config parse, reconnect backoff, the bash glue functions
  (proxy connect, enabled-check, proxy-role); 100% python line coverage.
- `sdwdate-gui-tests-fuzz` -- randomized/malformed wire input, no-crash +
  registration invariants.
- `sdwdate-gui-tests-integration` -- the real tray icon on a headless X11
  systray host and a headless Wayland compositor (left/right click opens the
  menu; the Wayland menu opt-out).

What NONE of those can reach: the cross-qube qrexec round-trip through the
static `sdwdate-gui.Connect` socket service, a connector VM appearing and
disappearing on its own schedule, and the menu actions firing real RPC into a
real client VM. That needs live qubes, so it is an operator-driven plan with
exact commands and pass criteria.

These are DISRUPTIVE steps (they stop/restart time sync and power VMs off and
on). Run them on a test session, not while the machine is doing real work.

## The architecture under test

- The gateway exposes its running server's UNIX socket as a native qrexec
  SOCKET service via a STATIC symlink `/etc/qubes-rpc/sdwdate-gui.Connect` ->
  `/run/user/1000/sdwdate-gui/sdwdate-gui-server.socket`. There is NO
  endpoint-maintainer service and NO ConnectCheck responder.
- The workstation client connects to its local systemd socket, which
  socket-activates `sdwdate-gui-qubes-proxy`; the proxy execs
  `qrexec-client-vm <gateway> sdwdate-gui.Connect` and bridges stdio.
- A down or disabled gateway has no server socket, so `sdwdate-gui.Connect`
  fails fast (qrexec exit 125). The client reconnects with CAPPED EXPONENTIAL
  BACKOFF (1s doubling to 60s), so a persistently-unavailable gateway is retried
  at most ~1/minute -- there is no responder to block gateway-side, the backoff
  is what prevents a dom0 policy-log flood.
- `disable=true` on any VM makes `sdwdate-gui.service`'s ExecCondition skip the
  unit, so neither server nor client starts. To a workstation a disabled gateway
  is indistinguishable from a down one and is handled identically (backoff).

## Topology and roles

- `sys-whonix` -- the Whonix GATEWAY. Runs the sdwdate-gui SERVER tray app and
  ships the static `/etc/qubes-rpc/sdwdate-gui.Connect` symlink.
- A WORKSTATION connector VM (e.g. `anon-whonix`) -- runs the sdwdate-gui CLIENT
  plus the proxy services (`sdwdate-gui-qubes-proxy` via the socket unit,
  `sdwdate-gui-qubes-proxy-helper`). It reaches the gateway over
  `sdwdate-gui.Connect`.
- A second connector VM -- to exercise multiple clients and independent up/down
  timing.
- `dom0` -- observation only: the qrexec policy decisions are logged here.

## Observation points (open these first, keep them running)

- O1 dom0 policy log (the bug surface -- Connect retry spam):

      # in dom0
      sudo journalctl -f | grep -i 'sdwdate-gui'

  Healthy: at most a handful of `sdwdate-gui.Connect` lines around an actual
  connect, and on a down/disabled gateway a SLOWING trickle (1s, 2s, 4s ... out
  to ~1/min), NOT ~1 line/second/qube. A steady per-second stream is the
  regression.

- O2 gateway Connect endpoint + server socket:

      # in sys-whonix
      ls -l /etc/qubes-rpc/sdwdate-gui.Connect          # static symlink (always)
      ls -l /run/user/1000/sdwdate-gui/sdwdate-gui-server.socket  # only when server up

- O3 gateway server log (the tray app; crash vs clean exit):

      # in sys-whonix, as the GUI user
      journalctl --user -f | grep -i sdwdate-gui
      # or run the server in a terminal to see stdout/stderr directly:
      /usr/bin/sdwdate-gui

- O4 connector client + proxy state:

      # in the connector VM
      journalctl -f | grep -i 'sdwdate-gui\|sdwdate'
      systemctl status 'sdwdate-gui-qubes@*'
      ls -l /run/sdwdate-gui-qubes-should-proxy   # proxy-role flag (workstation only)

## Pass criteria (apply to every scenario)

- P1 No dom0 Connect log flood (O1): on a down/disabled gateway the retry rate
  BACKS OFF toward ~1/min; it never holds a sustained per-second stream.
- P2 The gateway server never exits except via the tray `&Exit` item, and when
  it does exit that way O3 shows `Exit requested via the tray menu; quitting.`
  (never a silent SystemExit, never a traceback).
- P3 Every connector that is up and reachable appears in the tray menu within a
  few seconds; every connector that goes down disappears and does not wedge the
  menu or the handshake.
- P4 Connect/reconnect: a fresh connector against an up gateway connects within
  a few seconds; after a gateway comes back up, a waiting connector reconnects
  within the backoff cap (<= ~60s), not instantly and not never.

## Scenario matrix

Two independent dimensions, exercised in combination:

- A. Gateway server state: (A1) server RUNNING vs (A2) server NOT running
  (down, or `disable=true`).
- B. Connector lifecycle timing relative to the server.

| ID  | Gateway server | Connector action                                   | Expect |
|-----|----------------|----------------------------------------------------|--------|
| S1  | A2 not running | connector boots, client starts, no server yet      | P1     |
| S2  | A1 running     | connector already up when server starts            | P1,P3,P4 |
| S3  | A1 running     | connector boots AFTER server is already running    | P1,P3,P4 |
| S4  | A1 running     | connector shuts down while server running          | P1,P3  |
| S5  | A1 running     | connector reboots, reconnects                       | P1,P3,P4 |
| S6  | A1 running     | TWO connectors up; one goes down, other stays       | P1,P3  |
| S7  | A2->A1         | connectors up; start the server late                | P1,P3,P4 |
| S8  | A1->A2         | connectors up; exit the server via &Exit            | P1,P2  |
| S9  | A1 running     | restart the gateway SERVER under live clients       | P1,P3,P4 |
| S10 | A2 (disabled)  | gateway `disable=true`; connectors up               | P1     |

### S1 -- client with no server (the flood regression, server-off arm)

1. Ensure the gateway server is NOT running (O3 shows no process; O2 shows no
   server socket, the static symlink dangling).
2. Boot/keep a connector VM up; confirm its client + proxy start (O4).
3. Watch O1 for 2-3 minutes.
   Expected: the `sdwdate-gui.Connect` attempts SLOW DOWN (1s, 2s, 4s ... capped
   at ~60s), never a sustained per-second stream (P1). This is the backoff doing
   the flood-prevention the old ConnectCheck block used to.

### S2 -- connector already up when the server starts

1. Connector up (S1 state, backed off).
2. Start the gateway server (O3: `/usr/bin/sdwdate-gui`).
3. The connector appears in the tray menu within one backoff interval (P3,P4).
   Watch O1: a connect around the appear, then quiet (P1).

### S3 -- connector boots after the server is running

1. Gateway server running, no connectors.
   Menu shows the disabled "Waiting for sdwdate-gui client..." item.
2. Boot a connector VM.
3. The connector appears in the menu within a few seconds of its client
   starting (P3,P4). O1 quiet (P1).

### S4 -- connector shuts down while the server runs

1. S3 end-state (connector in the menu).
2. `qvm-shutdown <connector>` from dom0.
3. The entry disappears from the menu; the menu stays responsive, other
   entries intact (P3). O1 quiet (P1). O3 no crash (P2).

### S5 -- connector reboot / reconnect

1. S4 end-state.
2. `qvm-start <connector>`; let the client start.
3. The connector reappears and the handshake re-completes promptly (P3,P4).
   No duplicate menu entries. O1 quiet (P1).

### S6 -- two connectors, independent up/down

1. Two connector VMs up, both in the menu.
2. Shut one down; the other stays listed and fully functional (P3).
3. Bring the first back; both listed, no cross-talk, no duplicates (P3).
   O1 quiet throughout (P1).

### S7 -- late server start with connectors already waiting

1. Connectors up, server NOT running (clients backed off, S1).
2. Start the gateway server.
3. Each waiting connector reconnects within its backoff cap (<= ~60s) and
   appears (P3,P4). O1: a connect per connector, then quiet (P1).

### S8 -- clean exit via the tray &Exit item

1. Server running with connectors listed.
2. Open the tray menu, click `&Exit` (also test the `Alt+E` mnemonic -- the
   exact accidental trigger the crash fix addressed).
3. O3 shows exactly `Exit requested via the tray menu; quitting.` and the
   process exits 0 -- no traceback, no silent SystemExit (P2).
4. With the server now down, confirm the connectors back off (P1), not flood.

### S9 -- gateway server restarted under load

1. Server running, connectors listed, handshakes settled.
2. Exit the server (`&Exit`) and restart it (`/usr/bin/sdwdate-gui`). The server
   unlinks and rebinds its socket at the same path; the static Connect symlink
   is unchanged (O2).
3. Live clients reconnect within a backoff interval and the menu re-populates
   (P3,P4). O1: a connect burst around the restart, then quiet (P1).

### S10 -- disabled gateway

1. Set `disable=true` in the gateway config and restart `sdwdate-gui.service`
   (its ExecCondition now skips it: O3 shows no server, O2 no server socket).
2. Keep connectors up.
3. The connectors back off exactly as in S1 (P1): a disabled gateway is
   indistinguishable from a down one and must not flood dom0. Clear `disable`
   and restart to confirm S7-style recovery.

## Button / action coverage (run with at least one connector listed)

For EACH listed connector, open the tray menu and exercise every item. A
Tor-enabled client shows the first two; all clients show the rest; one global
item sits below all connectors.

| Menu item            | Scope        | Expected result                                   |
|----------------------|--------------|---------------------------------------------------|
| Show Tor status      | Tor client   | status message dialog for that VM; no crash       |
| Tor control panel    | Tor client   | opens the Tor control panel in that VM            |
| Show sdwdate status  | every client | sdwdate status message for that VM                |
| Open sdwdate's log   | every client | opens sdwdate's log in that VM                    |
| Restart sdwdate      | every client | sdwdate restarts in that VM; icon reflects it     |
| Stop sdwdate         | every client | sdwdate stops in that VM; icon reflects it        |
| &Exit                | global       | clean server exit (see S8 / P2)                   |

For each: the action fires the RPC into the correct VM only; the menu stays
responsive; O1/O3/O4 show no flood, crash, or stuck process. A connector that
goes down loses its menu entry (S4), so there is no stale down-VM entry to click;
the race to cover is instead firing an action JUST as the VM drops -- shut the
connector down during a "Restart sdwdate" / "Stop sdwdate" RPC and confirm the
server handles the vanishing client gracefully, not a wedge.

## Teardown

1. Exit the gateway server via `&Exit` (not kill) to validate P2 one last time.
2. Restore each connector's normal power state.
3. Confirm O1 is quiet and the static `/etc/qubes-rpc/sdwdate-gui.Connect`
   symlink is present on the gateway (it is shipped, independent of the tray app).

## Resume / automation notes

- Unattended, no qubes: `sdwdate-gui-tests` (unit incl. the bash glue functions
  and reconnect backoff), `sdwdate-gui-tests-fuzz` (wire + glue fuzz), and
  `sdwdate-gui-tests-integration` (headless tray/menu). The reconnect-backoff
  regression (no fixed-rate flood) and the gateway-arg/enabled-check branch
  invariants are proven there; the handshake STATE MACHINE is model-checked by
  `test_handshake_model.py` (the anti-flood "every retry passes through backoff"
  invariant is exhaustive over the reachable state space).
- There is NO headless e2e suite: the new design has no gateway-side maintainer
  or responder to chain without a live qube. The cross-qube round-trip is proven
  only here, operator-driven.
- What stays OPERATOR-DRIVEN (needs a live Qubes host + dom0): the real qvm
  lifecycle (`qvm-start`/`qvm-shutdown`), the dom0 qrexec-policy flood
  observation (O1), the real cross-qube qrexec round-trip through the static
  socket service, and the live tray button actions firing RPC into real client
  VMs. Each step above lists its exact command and O1-O4 observation point so a
  dedicated test session can run it.
