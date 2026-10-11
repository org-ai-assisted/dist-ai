<!--
Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted
-->

# sdwdate-gui live end-to-end test plan (Qubes multi-VM)

## Why this is a document, not a gating suite

The automated lanes verify everything that runs without a real Qubes install:

- `sdwdate-gui-tests` (unit, offscreen) -- client event loop, wire protocol,
  menu/RPC wiring, config parse, the ConnectCheck responder; 100% python line
  coverage.
- `sdwdate-gui-tests-fuzz` -- randomized/malformed wire input, no-crash +
  registration invariants.
- `sdwdate-gui-tests-integration` -- the real tray icon on a headless X11
  systray host and a headless Wayland compositor (left/right click opens the
  menu; the Wayland opt-out; the XEmbed-vs-StatusNotifier startup race).

What NONE of those can reach: the cross-qube qrexec handshake, a connector VM
appearing and disappearing on its own schedule, and the menu actions firing
real RPC into a real client VM. That needs live qubes, so it is an
operator-driven plan with exact commands and pass criteria.

These are DISRUPTIVE steps (they stop/restart time sync and power VMs off and
on). Run them on a test session, not while the machine is doing real work.

## Topology and roles

- `sys-whonix` -- the Whonix GATEWAY. Runs the sdwdate-gui SERVER tray app and
  `sdwdate-gui-qubes-connect.service` (maintains `/run/qubes-rpc/sdwdate-gui.Connect`).
- A WORKSTATION connector VM (e.g. `anon-whonix`) -- runs the sdwdate-gui
  CLIENT plus the proxy services (`sdwdate-gui-qubes-proxy` via the socket unit,
  `sdwdate-gui-qubes-proxy-helper`). It reaches the gateway over
  `sdwdate-gui.ConnectCheck` / `sdwdate-gui.Connect`.
- A second connector VM (e.g. `sys-net` when time-sync-proxied, or a second
  workstation) -- to exercise multiple clients and independent up/down timing.
- `dom0` -- observation only: the qrexec policy decisions are logged here.

## Observation points (open these first, keep them running)

- O1 dom0 policy log (the ORIGINAL bug surface -- ConnectCheck spam):

      # in dom0
      sudo journalctl -f | grep -i 'sdwdate-gui'

  Healthy: at most a handful of `sdwdate-gui.Connect` / `.ConnectCheck` lines
  around an actual connect; NOT ~1 line/second/qube. A steady per-second stream
  is the regression.

- O2 gateway connect endpoint + unit:

      # in sys-whonix
      systemctl status sdwdate-gui-qubes-connect.service
      ls -l /run/qubes-rpc/sdwdate-gui.Connect

- O3 gateway server log (the tray app; crash vs clean exit):

      # in sys-whonix, as the GUI user
      journalctl --user -f | grep -i sdwdate-gui
      # or run the server in a terminal to see stdout/stderr directly:
      /usr/bin/sdwdate-gui

- O4 connector client + proxy state:

      # in the connector VM
      journalctl -f | grep -i 'sdwdate-gui\|sdwdate'
      systemctl status 'sdwdate-gui-qubes-proxy*'
      ls -l /run/sdwdate-gui-qubes-should-proxy   # proxy-role flag (workstation only)

## Pass criteria (apply to every scenario)

- P1 No dom0 ConnectCheck/Connect log spam at any point (O1): no sustained
  per-second stream, whether or not the gateway server is running.
- P2 The gateway server never exits except via the tray `&Exit` item, and when
  it does exit that way O3 shows `Exit requested via the tray menu; quitting.`
  (never a silent SystemExit, never a traceback).
- P3 Every connector that is up and reachable appears in the tray menu within a
  few seconds; every connector that goes down disappears and does not wedge the
  menu or the handshake.
- P4 The connect handshake is event-based: a client blocked on ConnectCheck is
  released promptly (sub-second) once the gateway endpoint appears -- no polling
  stream, no multi-second lag.
- P5 No orphaned ConnectCheck responder accumulation on the gateway: a blocked
  responder is bounded and self-clears when the endpoint appears (see the
  honest-docstring note in sdwdate_gui_connect_check).

## Scenario matrix

Two independent dimensions, exercised in combination:

- A. Gateway server state: (A1) server RUNNING vs (A2) server NOT running.
- B. Connector lifecycle timing relative to the server and endpoint.

| ID  | Gateway server | Connector action                                   | Expect |
|-----|----------------|----------------------------------------------------|--------|
| S1  | A2 not running | connector boots, client starts, no server yet      | P1,P4  |
| S2  | A1 running     | connector already up when server starts            | P1,P3  |
| S3  | A1 running     | connector boots AFTER server is already running    | P1,P3,P4 |
| S4  | A1 running     | connector shuts down while server running          | P1,P3  |
| S5  | A1 running     | connector reboots, reconnects                       | P1,P3,P4 |
| S6  | A1 running     | TWO connectors up; one goes down, other stays       | P1,P3  |
| S7  | A2->A1         | connectors up; start the server late                | P1,P3,P4 |
| S8  | A1->A2         | connectors up; exit the server via &Exit            | P1,P2  |
| S9  | A1 running     | gateway connect.service restarted under live clients| P1,P3,P4 |

### S1 -- client with no server (the spam regression, server-off arm)

1. Ensure the gateway server is NOT running (O3 shows no process).
2. Boot/keep a connector VM up; confirm its client + proxy start (O4).
3. Watch O1 for 60 s.
   Expected: no per-second ConnectCheck stream in dom0 (P1). The client's
   ConnectCheck call BLOCKS event-based waiting for the endpoint (P4); it does
   not busy-poll.

### S2 -- connector already up when the server starts

1. Connector up (S1 state).
2. Start the gateway server (O3: `/usr/bin/sdwdate-gui`).
3. Within a few seconds the connector appears in the tray menu (P3).
   Watch O1: a small burst around the connect, then quiet (P1).

### S3 -- connector boots after the server is running

1. Gateway server running, no connectors.
   Menu shows the disabled "Waiting for sdwdate-gui client..." item.
2. Boot a connector VM.
3. The connector appears in the menu within a few seconds of its client
   starting (P3); the handshake completes promptly (P4). O1 quiet (P1).

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

1. Connectors up, server NOT running (clients blocked event-based, S1).
2. Start the gateway server.
3. All waiting connectors appear within a few seconds (P3); each handshake
   fires on the endpoint-appear event, not a poll (P4). O1: one burst, then
   quiet (P1).

### S8 -- clean exit via the tray &Exit item

1. Server running with connectors listed.
2. Open the tray menu, click `&Exit` (also test the `Alt+E` mnemonic -- the
   exact accidental trigger the crash fix addressed).
3. O3 shows exactly `Exit requested via the tray menu; quitting.` and the
   process exits 0 -- no traceback, no silent SystemExit (P2).
4. With the server now down, confirm O1 stays quiet (P1, server-off arm).

### S9 -- gateway endpoint maintainer restarted under load

1. Server running, connectors listed, handshakes settled.
2. `sudo systemctl restart sdwdate-gui-qubes-connect.service` on the gateway.
3. O2: the endpoint is recreated; the service self-heals.
   Live clients re-handshake promptly on the new endpoint (P4); the menu
   re-populates (P3). O1: a burst around the restart, then quiet (P1).

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
responsive; O1/O3/O4 show no spam, crash, or stuck responder. Test "Restart
sdwdate" and "Stop sdwdate" both while that connector is UP and immediately
after it has gone DOWN (the action must fail gracefully, not wedge the server).

## Teardown

1. Exit the gateway server via `&Exit` (not kill) to validate P2 one last time.
2. Restore each connector's normal power state.
3. Confirm O1 is quiet and `sdwdate-gui-qubes-connect.service` is active on the
   gateway (its endpoint is maintained independent of the tray app).

## Resume / automation notes

- The headless tray/menu/SNI portions run unattended:
  `dist-ai-tests-all --integration --component sdwdate-gui --repo-root ~/derivative-maker`
  (installs its own tooling list when missing; skips loud otherwise).
- The cross-VM scenarios above require a live Qubes host and are operator-driven;
  each step lists its exact command and its O1-O4 observation point so a run can
  be scripted from dom0 (`qvm-start`/`qvm-shutdown` for the lifecycle, the
  journ/ls probes for evidence) once a dedicated test session is available.
