<!--
Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted
-->

# sdwdate-gui live end-to-end test plan (Qubes multi-VM)

## Why this is a document, not a gating suite

The automated lanes verify everything that runs without a real Qubes install:

- `sdwdate-gui-tests` (unit, offscreen) -- client event loop, wire protocol,
  menu/RPC wiring, config parse, the fixed-delay reconnect, the bash glue
  functions (proxy connect-check, proxy-role); 100% python line coverage.
- `sdwdate-gui-tests-fuzz` -- randomized/malformed wire input, no-crash +
  registration invariants.
- `sdwdate-gui-tests-integration` -- the real tray icon on a headless X11
  systray host and a headless Wayland compositor (left/right click opens the
  menu; the Wayland menu opt-out).

What NONE of those can reach: the cross-qube qrexec round-trip through the
`sdwdate-gui.ConnectCheck` + `sdwdate-gui.Connect` socket services, a connector
VM appearing and disappearing on its own schedule, and the menu actions firing
real RPC into a real client VM. That needs live qubes, so it is an
operator-driven plan with exact commands and pass criteria.

These are DISRUPTIVE steps (they stop/restart time sync and power VMs off and
on). Run them on a test session, not while the machine is doing real work.

## The architecture under test

- On the gateway, `sdwdate-gui-qubes-proxy-helper.service` waits for the running
  server's UNIX socket (`/run/user/<uid>/sdwdate-gui/sdwdate-gui-server.socket`,
  the default user's uid) and symlinks it to `/run/qubes-rpc/sdwdate-gui.Connect`.
  The gateway also answers `sdwdate-gui.ConnectCheck`, which BLOCKS gateway-side
  (polling its own `/run/qubes-rpc/sdwdate-gui.Connect` once a second) until that
  endpoint is a live socket, then returns `y`; it returns `q` ("will not become
  available") when the gateway is disabled or is not configured to run the
  server.
- The workstation client connects to its local systemd socket, which
  socket-activates `sdwdate-gui-qubes-proxy`; the proxy execs
  `qrexec-client-vm <gateway> sdwdate-gui.ConnectCheck` and, ONLY on a `y`,
  `qrexec-client-vm <gateway> sdwdate-gui.Connect` to bridge stdio.
- A gateway whose server is merely still starting does NOT flood dom0: the
  single ConnectCheck qrexec call stays open and BLOCKS on the gateway side, so
  the workstation is not making a call per second. On a `q` (disabled /
  non-server gateway, or an unreachable one where the qrexec call fails), the
  proxy drops `/run/sdwdate-gui/qubes-gateway-server-disabled` and the client
  GIVES UP (its next main_loop pass sees the flag and exits). The client's
  `asyncio.sleep(1)` is only a brief fixed pause between a dropped CONNECTED
  session and the next attempt, NOT a capped-exponential backoff and NOT a
  gateway-poll loop.
- `disable=true` on any VM makes `sdwdate-gui.service`'s ExecCondition skip the
  unit, so neither server nor client starts. A disabled gateway answers
  ConnectCheck with `q`, so the workstation gives up rather than retrying.

## Topology and roles

- `sys-whonix` -- the Whonix GATEWAY. Runs the sdwdate-gui SERVER tray app and
  `sdwdate-gui-qubes-proxy-helper.service`, which waits for the server socket and
  symlinks it to `/run/qubes-rpc/sdwdate-gui.Connect`, plus the
  `sdwdate-gui.ConnectCheck` qrexec responder.
- A WORKSTATION connector VM (e.g. `anon-whonix`) -- runs the sdwdate-gui CLIENT
  plus the proxy services (`sdwdate-gui-qubes-proxy` via the socket unit,
  `sdwdate-gui-qubes-proxy-helper`). It reaches the gateway over
  `sdwdate-gui.ConnectCheck` then `sdwdate-gui.Connect`.
- A second connector VM -- to exercise multiple clients and independent up/down
  timing.
- `dom0` -- observation only: the qrexec policy decisions are logged here.

## Observation points (open these first, keep them running)

- O1 dom0 policy log (the bug surface -- ConnectCheck/Connect retry spam):

      # in dom0
      sudo journalctl -f | grep -i 'sdwdate-gui'

  Healthy: at most a handful of `sdwdate-gui.ConnectCheck` / `sdwdate-gui.Connect`
  lines around an actual connect. A server that is merely starting holds ONE
  open ConnectCheck call (blocked gateway-side), not a line per second; a
  disabled gateway answers `q` once and the client gives up. A steady
  per-second stream is the regression.

- O2 gateway Connect endpoint + server socket:

      # in sys-whonix
      systemctl status sdwdate-gui-qubes-proxy-helper.service    # maintains the symlink
      ls -l /run/qubes-rpc/sdwdate-gui.Connect          # symlink -> the server socket
      ## symlink target tracks the running server: /run/user/<uid>/sdwdate-gui/...
      ls -l /run/user/*/sdwdate-gui/sdwdate-gui-server.socket    # only when server up

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

- P1 No dom0 qrexec log flood (O1): a starting gateway holds ONE open blocked
  ConnectCheck call, a disabled gateway answers `q` once and the client gives
  up; neither ever holds a sustained per-second ConnectCheck/Connect stream.
- P2 The gateway server never exits except via the tray `&Exit` item, and when
  it does exit that way O3 shows `Exit requested via the tray menu; quitting.`
  (never a silent SystemExit, never a traceback).
- P3 Every connector that is up and reachable appears in the tray menu within a
  few seconds; every connector that goes down disappears and does not wedge the
  menu or the handshake.
- P4 Connect/reconnect: a fresh connector against an up gateway connects within
  a few seconds; a connector whose ConnectCheck is blocked on a starting gateway
  connects promptly once the server socket appears (the gateway-side block
  releases), not instantly and not never.

## Scenario matrix

Two independent dimensions, exercised in combination:

- A. Gateway server state: (A1) server RUNNING vs (A2) server NOT running.
  Trixie splits A2: a gateway configured to run the server but still starting
  BLOCKS ConnectCheck (client waits), whereas `disable=true` / not-a-server
  answers `q` (client gives up).
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
| S11 | A1 (sysmaint)  | gateway booted in sysmaint mode (GUI as uid 1001)   | P1,P3,P4 |

### S1 -- client with no server yet (the flood regression, server-starting arm)

1. Ensure the gateway server is NOT running but the gateway IS configured to run
   it (`disable=false`, `run_server_in_qubes=true`): O3 shows no process; O2
   shows no server socket and no `/run/qubes-rpc/sdwdate-gui.Connect` yet.
2. Boot/keep a connector VM up; confirm its client + proxy start (O4).
3. Watch O1 for 2-3 minutes.
   Expected: ONE `sdwdate-gui.ConnectCheck` call that stays open, blocked
   gateway-side waiting for the server socket -- never a sustained per-second
   ConnectCheck/Connect stream (P1). The gateway-side block, not a client
   backoff, is the flood-prevention.

### S2 -- connector already up when the server starts

1. Connector up (S1 state, ConnectCheck blocked gateway-side).
2. Start the gateway server (O3: `/usr/bin/sdwdate-gui`).
3. The connector appears in the tray menu promptly once the blocked ConnectCheck
   releases (P3,P4). Watch O1: a connect around the appear, then quiet (P1).

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

1. Connectors up, server NOT running (clients blocked in ConnectCheck, S1).
2. Start the gateway server.
3. Each waiting connector's blocked ConnectCheck releases and it reconnects and
   appears promptly (P3,P4). O1: a connect per connector, then quiet (P1).

### S8 -- clean exit via the tray &Exit item

1. Server running with connectors listed.
2. Open the tray menu, click `&Exit` (also test the `Alt+E` mnemonic -- the
   exact accidental trigger the crash fix addressed).
3. O3 shows exactly `Exit requested via the tray menu; quitting.` and the
   process exits 0 -- no traceback, no silent SystemExit (P2).
4. With the server now down (but the gateway still enabled), confirm each
   connector's ConnectCheck blocks gateway-side waiting for the socket to
   return, not a flood (P1).

### S9 -- gateway server restarted under load

1. Server running, connectors listed, handshakes settled.
2. Exit the server (`&Exit`) and restart it (`/usr/bin/sdwdate-gui`). The server
   unlinks and rebinds its socket at the same path; the proxy-helper re-points
   `/run/qubes-rpc/sdwdate-gui.Connect` at the new socket (O2).
3. Live clients reconnect once the endpoint is back (their fixed-delay retry
   then a releasing ConnectCheck) and the menu re-populates (P3,P4). O1: a
   connect burst around the restart, then quiet (P1).

### S11 -- gateway booted in sysmaint mode

1. Boot the gateway in SYSMAINT mode (the GUI session runs as `sysmaint`,
   uid 1001). Start the server as sysmaint.
2. O2: the proxy-helper points `/run/qubes-rpc/sdwdate-gui.Connect` at the
   ACTUAL running server socket -- `/run/user/1001/sdwdate-gui/...` in a
   sysmaint session, NOT a hardcoded `/run/user/1000/...`.
3. A workstation connects and appears in the sysmaint-session tray (P3,P4);
   O1 quiet (P1). This is the exact case a hardcoded-uid-1000 endpoint would
   silently break.

### S10 -- disabled gateway

1. Set `disable=true` in the gateway config and restart `sdwdate-gui.service`
   (its ExecCondition now skips it: O3 shows no server, O2 no server socket).
2. Keep connectors up.
3. The gateway answers `sdwdate-gui.ConnectCheck` with `q`, so each connector's
   proxy drops `/run/sdwdate-gui/qubes-gateway-server-disabled` and the client
   GIVES UP -- O1 shows one ConnectCheck per connector, then silence, never a
   flood (P1). Clear `disable` and restart the connectors to confirm S7-style
   recovery (give-up is per-run: the flag lives in `/run`, cleared on reboot).

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
3. Confirm O1 is quiet. With the server down, `/run/qubes-rpc/sdwdate-gui.Connect`
   dangles (its target socket is gone); the proxy-helper re-points it when the
   server is next up.

## Resume / automation notes

- Unattended, no qubes: `sdwdate-gui-tests` (unit incl. the bash glue functions
  and the fixed-delay reconnect), `sdwdate-gui-tests-fuzz` (wire + glue fuzz),
  and `sdwdate-gui-tests-integration` (headless tray/menu). The reconnect
  control flow (give-up on the disabled flag, fixed-delay retry otherwise) and
  the gateway-arg/connect-check branch invariants are proven there; the
  handshake STATE MACHINE is model-checked by `test_handshake_model.py` (the
  rate-limited-retry, give-up and liveness invariants are exhaustive over the
  reachable state space).
- There is NO headless e2e suite: the cross-qube ConnectCheck/Connect round-trip
  cannot be chained without a live qube. It is proven only here,
  operator-driven.
- What stays OPERATOR-DRIVEN (needs a live Qubes host + dom0): the real qvm
  lifecycle (`qvm-start`/`qvm-shutdown`), the dom0 qrexec-policy flood
  observation (O1), the real cross-qube qrexec round-trip through the
  ConnectCheck/Connect socket services, and the live tray button actions firing
  RPC into real client VMs. Each step above lists its exact command and O1-O4
  observation point so a dedicated test session can run it.
