#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Explicit-state model check of the Qubes sdwdate-gui connect handshake.

This is a formal (exhaustive) model of the EVENT-BASED design, not a test of
the Python/bash code: it enumerates every reachable state of the protocol and
proves safety/liveness invariants hold for ALL of them, which random fuzzing
cannot. It guards the DESIGN -- if the handshake is changed, update the model
and the proof must still pass.

Correspondence to the implementation:
  * server down/up        -- sdwdate-gui-server: 'up' == its UNIX socket exists.
  * endpoint absent/present -- /run/qubes-rpc/sdwdate-gui.Connect, maintained by
                             sdwdate-gui-qubes-connect.service: it creates the
                             symlink once the server socket exists and removes
                             it once the socket is gone (modelled as the
                             'maintainer' transitions). ONLY a VM configured to
                             run the server (run_server_in_qubes) maintains it.
  * client idle/waiting/connecting/connected/gaveup -- sdwdate-gui-qubes-proxy:
      idle       -> calls sdwdate-gui.ConnectCheck ONCE (no polling).
      waiting    -> the gateway responder BLOCKS on an inotify event and
                    returns 'y' the instant the endpoint is present. A TRANSIENT
                    ConnectCheck failure (qrexec transport) does NOT give up:
                    the proxy exits non-zero and the next socket activation
                    retries (modelled as waiting -> idle).
      connecting -> on 'y' it calls sdwdate-gui.Connect.
      connected  -> the bridge is up.
      gaveup     -> ConnectCheck returned 'q': the gateway has sdwdate-gui
                    disabled, OR this VM does not run the server, so no endpoint
                    will ever appear. The proxy drops the give-up flag and stops.

Two gateway-config dimensions, each constant per run:
  * disabled      -- 'disable=true' in the gateway config.
  * runs_server   -- 'run_server_in_qubes' true (this VM maintains an endpoint).
The responder gives up ('q') iff `disabled or not runs_server`; call that
`gives_up`. Only the operational config (not disabled, runs the server) ever
drives the client past 'waiting'.

Proved over ALL four (disabled, runs_server) configs:
  * SAFETY       -- a gives_up gateway never drives a client to
                    waiting/connecting/connected; connecting->connected only
                    fires while the endpoint is present and the server up.
  * NO DEADLOCK  -- every reachable non-gaveup state has a successor.
  * NO FALSE GIVE-UP -- the operational config never reaches 'gaveup' (a
                    transient failure retries, it does not permanently disable).
  * LIVENESS     -- operational config: 'connected' is reachable from every
                    reachable non-gaveup state (never permanently stuck) and is
                    reachable at all; every gives_up config always reaches
                    'gaveup' (it terminates).
"""

# pylint: disable=invalid-name

import unittest
from collections import deque

## Component state vocabularies.
SERVER = ("down", "up")
ENDPOINT = ("absent", "present")
CLIENT = ("idle", "waiting", "connecting", "connected", "gaveup")

## A protocol state is (server, endpoint, client).
INITIAL = ("down", "absent", "idle")

## The four gateway configs as (disabled, runs_server).
CONFIGS = ((False, False), (False, True), (True, False), (True, True))


def gives_up(disabled, runs_server):
    """The responder returns 'q' (client gives up) iff the gateway is disabled
    or this VM does not run the server -- no endpoint will ever appear."""
    return disabled or not runs_server


def successors(state, disabled, runs_server):
    """All states reachable in one step from `state` under the event-based
    protocol. Environment moves (server, maintainer) are always enabled; client
    moves follow the handshake. Guards here ARE the safety argument."""
    server, endpoint, client = state
    nxt = set()

    ## Environment: the server may start or stop at any time.
    if server == "down":
        nxt.add(("up", endpoint, client))
    else:
        nxt.add(("down", endpoint, client))

    ## Environment: the maintainer tracks the server socket (self-healing), but
    ## ONLY on a VM that runs the server; a non-server VM never gets an endpoint.
    if runs_server and server == "up" and endpoint == "absent":
        nxt.add((server, "present", client))
    if endpoint == "present" and (server == "down" or not runs_server):
        nxt.add((server, "absent", client))

    ## Client handshake.
    if client == "idle":
        ## One ConnectCheck call. Disabled or non-server -> 'q' -> give up;
        ## otherwise the responder blocks until the endpoint appears.
        nxt.add(
            (
                server,
                endpoint,
                "gaveup" if gives_up(disabled, runs_server) else "waiting",
            )
        )
    elif client == "waiting":
        ## The responder returns 'y' only once the endpoint exists.
        if endpoint == "present":
            nxt.add((server, endpoint, "connecting"))
        ## A transient ConnectCheck failure (qrexec transport) must NOT be
        ## turned into a permanent give-up: the proxy exits non-zero and the
        ## next socket activation retries from idle.
        nxt.add((server, endpoint, "idle"))
    elif client == "connecting":
        ## Connect succeeds only while the endpoint is still present and the
        ## server up; otherwise the attempt fails and the client reconnects.
        if endpoint == "present" and server == "up":
            nxt.add((server, endpoint, "connected"))
        else:
            nxt.add((server, endpoint, "idle"))
    elif client == "connected":
        ## A dropped server/endpoint is noticed and triggers a reconnect.
        if server == "down" or endpoint == "absent":
            nxt.add((server, endpoint, "idle"))
    ## gaveup is terminal for the client (environment moves still apply).

    nxt.discard(state)
    return nxt


def reachable_states(disabled, runs_server):
    seen = {INITIAL}
    queue = deque([INITIAL])
    edges = {}
    while queue:
        state = queue.popleft()
        succ = successors(state, disabled, runs_server)
        edges[state] = succ
        for s in succ:
            if s not in seen:
                seen.add(s)
                queue.append(s)
    return seen, edges


def can_reach(edges, targets):
    """Set of states from which any state in `targets` is reachable."""
    reverse = {s: set() for s in edges}
    for src, succ in edges.items():
        for dst in succ:
            reverse.setdefault(dst, set()).add(src)
    good = set(t for t in targets if t in edges)
    queue = deque(good)
    while queue:
        s = queue.popleft()
        for pred in reverse.get(s, ()):
            if pred not in good:
                good.add(pred)
                queue.append(pred)
    return good


class TestHandshakeModel(unittest.TestCase):
    """Exhaustive proof over the reachable state space, all four configs."""

    def test_safety_giveup_never_connects(self) -> None:
        """A gives_up gateway (disabled or non-server) never drives the client
        to waiting/connecting/connected -- it only idles then gives up."""
        for disabled, runs_server in CONFIGS:
            if not gives_up(disabled, runs_server):
                continue
            seen, _ = reachable_states(disabled, runs_server)
            bad = {
                s for s in seen
                if s[2] in ("waiting", "connecting", "connected")
            }
            self.assertEqual(
                bad, set(),
                f"gives_up config disabled={disabled} runs_server="
                f"{runs_server} reached a connecting client state: {bad}",
            )

    def test_no_deadlock(self) -> None:
        """Every reachable non-gaveup state has a successor, all configs."""
        for disabled, runs_server in CONFIGS:
            seen, edges = reachable_states(disabled, runs_server)
            for state in seen:
                if state[2] == "gaveup":
                    continue  ## terminal by design
                self.assertTrue(
                    edges[state],
                    f"deadlock (no successor) at {state}, disabled={disabled} "
                    f"runs_server={runs_server}",
                )

    def test_operational_never_gives_up(self) -> None:
        """
        The operational config (not disabled, runs the server) NEVER reaches
        'gaveup': a transient ConnectCheck failure retries rather than setting
        the permanent give-up/disabled flag. Encodes the C3 correctness fix.
        """
        seen, _ = reachable_states(disabled=False, runs_server=True)
        bad = {s for s in seen if s[2] == "gaveup"}
        self.assertEqual(
            bad, set(),
            f"operational gateway wrongly reached 'gaveup': {bad}",
        )

    def test_liveness_operational_can_connect(self) -> None:
        """Operational config: 'connected' reachable from every non-gaveup
        state, and reachable at all."""
        seen, edges = reachable_states(disabled=False, runs_server=True)
        good = can_reach(edges, [s for s in seen if s[2] == "connected"])
        stuck = seen - good
        self.assertEqual(
            stuck, set(),
            f"client can never reach 'connected' from: {stuck}",
        )
        self.assertTrue(any(s[2] == "connected" for s in seen))

    def test_liveness_giveup_always_terminates(self) -> None:
        """Every gives_up config always reaches 'gaveup' (it terminates)."""
        for disabled, runs_server in CONFIGS:
            if not gives_up(disabled, runs_server):
                continue
            seen, edges = reachable_states(disabled, runs_server)
            good = can_reach(edges, [s for s in seen if s[2] == "gaveup"])
            stuck = seen - good
            self.assertEqual(
                stuck, set(),
                f"gives_up config disabled={disabled} runs_server="
                f"{runs_server} can never reach 'gaveup' from: {stuck}",
            )


if __name__ == "__main__":
    unittest.main()
