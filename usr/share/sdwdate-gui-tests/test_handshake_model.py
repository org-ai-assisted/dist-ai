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
                             'maintainer' transitions).
  * client idle/waiting/connecting/connected/gaveup -- sdwdate-gui-qubes-proxy:
      idle       -> calls sdwdate-gui.ConnectCheck ONCE (no polling).
      waiting    -> the gateway responder BLOCKS on an inotify event and
                    returns 'y' the instant the endpoint is present.
      connecting -> on 'y' it calls sdwdate-gui.Connect.
      connected  -> the bridge is up.
      gaveup     -> ConnectCheck returned 'q' (sdwdate-gui disabled); the proxy
                    drops the give-up flag and stops.
  * disabled -- the gateway 'disable=true' config; constant per run.

Proved for disabled in {False, True}:
  * SAFETY       -- the connecting->connected step only fires while the endpoint
                    is present (by construction); and a disabled gateway never
                    drives a client to waiting/connecting/connected.
  * NO DEADLOCK  -- every reachable state has a successor (gaveup aside).
  * LIVENESS     -- 'connected' is reachable from every reachable non-gaveup
                    state (disabled=False): the client is never permanently
                    stuck; and 'gaveup' is reachable (disabled=True): it always
                    terminates.
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


def successors(state, disabled):
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

    ## Environment: the maintainer tracks the server socket (self-healing).
    if server == "up" and endpoint == "absent":
        nxt.add((server, "present", client))
    if server == "down" and endpoint == "present":
        nxt.add((server, "absent", client))

    ## Client handshake.
    if client == "idle":
        ## One ConnectCheck call. Disabled -> 'q' -> give up; else block.
        nxt.add((server, endpoint, "gaveup" if disabled else "waiting"))
    elif client == "waiting":
        ## The responder returns 'y' only once the endpoint exists. No 'n', no
        ## poll: the client simply waits for the event.
        if endpoint == "present":
            nxt.add((server, endpoint, "connecting"))
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


def reachable_states(disabled):
    seen = {INITIAL}
    queue = deque([INITIAL])
    edges = {}
    while queue:
        state = queue.popleft()
        succ = successors(state, disabled)
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
    """Exhaustive proof over the reachable state space."""

    def test_safety_disabled_never_connects(self) -> None:
        seen, _ = reachable_states(disabled=True)
        ## A disabled gateway drives the client only to idle or gaveup.
        bad = {s for s in seen if s[2] in ("waiting", "connecting", "connected")}
        self.assertEqual(
            bad, set(),
            f"disabled gateway reached a connecting client state: {bad}",
        )

    def test_no_deadlock(self) -> None:
        for disabled in (False, True):
            seen, edges = reachable_states(disabled)
            for state in seen:
                if state[2] == "gaveup":
                    continue  ## terminal by design
                self.assertTrue(
                    edges[state],
                    f"deadlock (no successor) at {state}, disabled={disabled}",
                )

    def test_liveness_client_can_always_connect(self) -> None:
        seen, edges = reachable_states(disabled=False)
        good = can_reach(edges, [s for s in seen if s[2] == "connected"])
        stuck = seen - good
        self.assertEqual(
            stuck, set(),
            f"client can never reach 'connected' from: {stuck}",
        )
        ## And 'connected' is actually reachable at all.
        self.assertTrue(any(s[2] == "connected" for s in seen))

    def test_liveness_disabled_always_terminates(self) -> None:
        seen, edges = reachable_states(disabled=True)
        good = can_reach(edges, [s for s in seen if s[2] == "gaveup"])
        stuck = seen - good
        self.assertEqual(
            stuck, set(),
            f"disabled client can never reach 'gaveup' from: {stuck}",
        )


if __name__ == "__main__":
    unittest.main()
