#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Explicit-state model check of the Qubes sdwdate-gui connect handshake.

This is a formal (exhaustive) model of the socket-service design, not a test of
the Python/bash code: it enumerates every reachable state of the protocol and
proves safety/liveness invariants hold for ALL of them, which random fuzzing
cannot. It guards the DESIGN -- if the handshake is changed, update the model
and the proof must still pass.

Correspondence to the implementation:
  * server down/up -- sdwdate-gui-server on the gateway: 'up' == its UNIX socket
                    exists. The gateway Connect endpoint is a STATIC qrexec
                    socket-service symlink to that socket, so there is no
                    maintainer and no readiness responder to model.
  * client idle/connecting/connected/backoff -- the workstation client +
      sdwdate-gui-qubes-proxy:
      idle       -> the client connects to its local systemd socket, which
                    socket-activates the proxy; the proxy calls
                    sdwdate-gui.Connect over qrexec (modelled as 'connecting').
      connecting -> on an up server the qrexec socket service bridges
                    ('connected'); on a down/disabled gateway the call fails
                    fast (qrexec exit 125), so the session drops ('backoff').
      connected  -> the bridge is up until the server drops.
      backoff    -> the client sleeps a capped-exponential delay before
                    retrying (idle). There is NO give-up state: a disabled
                    gateway is indistinguishable from a down one, and both are
                    retried, rate-limited by the backoff.

One gateway-reachability dimension, constant per run:
  * reachable=True  -- an operational gateway (not disabled, runs the server):
                       its socket may come up and down.
  * reachable=False -- a disabled / non-server gateway: its socket NEVER comes
                       up, so 'connected' is unreachable; the client retries
                       forever (via backoff), never gives up.

Proved over both configs:
  * SAFETY         -- a client only BECOMES 'connected' from an up server; the
                      unreachable config never reaches 'connected'.
  * ANTI-FLOOD     -- every retry passes through 'backoff': 'idle' is only ever
                      re-entered from 'backoff', never directly from a failed
                      'connecting' or a dropped 'connected'. This is what keeps
                      a down/disabled gateway from being polled in a tight loop
                      and flooding dom0's qrexec-policy log.
  * NO DEADLOCK    -- every reachable state has a successor.
  * LIVENESS       -- reachable config: 'connected' is reachable from every
                      reachable state (never permanently stuck) and reachable at
                      all. unreachable config: 'idle' (a fresh attempt) is
                      reachable from every state -- the client never gives up.
"""

# pylint: disable=invalid-name

import unittest
from collections import deque

## Component state vocabularies.
SERVER = ("down", "up")
CLIENT = ("idle", "connecting", "connected", "backoff")

## A protocol state is (server, client).
INITIAL = ("down", "idle")

## The gateway-reachability configs.
CONFIGS = (True, False)


def successors(state, reachable):
    """All states reachable in one step from `state`. The environment move (the
    server starting/stopping) is enabled only for a reachable gateway; the
    client moves follow the reconnect loop. Guards here ARE the safety
    argument."""
    server, client = state
    nxt = set()

    ## Environment: an operational gateway's server may start or stop at any
    ## time; a disabled / non-server gateway's server never comes up.
    if reachable:
        nxt.add(("up" if server == "down" else "down", client))

    ## Client reconnect loop. No give-up: a down and a disabled gateway are
    ## indistinguishable and both are retried.
    if client == "idle":
        ## Local socket activation -> proxy calls sdwdate-gui.Connect.
        nxt.add((server, "connecting"))
    elif client == "connecting":
        if server == "up":
            nxt.add((server, "connected"))
        else:
            ## No server socket -> qrexec Connect fails fast -> rate-limited
            ## retry, never a direct re-attempt.
            nxt.add((server, "backoff"))
    elif client == "backoff":
        ## After the capped-exponential sleep, retry from idle.
        nxt.add((server, "idle"))
    elif client == "connected":
        ## A dropped server is noticed and reconnected THROUGH the backoff path.
        if server == "down":
            nxt.add((server, "backoff"))

    nxt.discard(state)
    return nxt


def reachable_states(reachable):
    seen = {INITIAL}
    queue = deque([INITIAL])
    edges = {}
    while queue:
        state = queue.popleft()
        succ = successors(state, reachable)
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


def fair_successors(state, reachable):
    """The FAIR transitions out of `state`: all client progress moves plus the
    environment bringing the server UP (down -> up). The environment DROPPING
    the server (up -> down) is adversarial and NOT assumed fair, so it is
    excluded -- a fair scheduler need not ever drop a running server, but under
    strong fairness it must eventually bring a down server up and must
    eventually take an enabled client-progress step."""
    server, _client = state
    adversarial = ("down", state[1]) if server == "up" else None
    return {s for s in successors(state, reachable) if s != adversarial}


def _strongly_connected_components(graph):
    """Tarjan's SCCs of `graph` (a dict node -> set of successor nodes)."""
    index = {}
    low = {}
    on_stack = {}
    stack = []
    counter = [0]
    result = []

    def strongconnect(node):
        index[node] = counter[0]
        low[node] = counter[0]
        counter[0] += 1
        stack.append(node)
        on_stack[node] = True
        for succ in graph[node]:
            if succ not in index:
                strongconnect(succ)
                low[node] = min(low[node], low[succ])
            elif on_stack.get(succ):
                low[node] = min(low[node], index[succ])
        if low[node] == index[node]:
            component = []
            while True:
                member = stack.pop()
                on_stack[member] = False
                component.append(member)
                if member == node:
                    break
            result.append(frozenset(component))

    for node in graph:
        if node not in index:
            strongconnect(node)
    return result


class TestHandshakeModel(unittest.TestCase):
    """Exhaustive proof over the reachable state space, both configs."""

    def test_safety_connected_only_from_up_server(self) -> None:
        """A client only BECOMES 'connected' from an up server, and the
        unreachable config never reaches 'connected' at all."""
        for reachable in CONFIGS:
            seen, edges = reachable_states(reachable)
            for src, succ in edges.items():
                for dst in succ:
                    if dst[1] == "connected" and src[1] != "connected":
                        self.assertEqual(
                            dst[0], "up",
                            f"became 'connected' from a down server: "
                            f"{src} -> {dst} (reachable={reachable})",
                        )
            if not reachable:
                self.assertEqual(
                    {s for s in seen if s[1] == "connected"}, set(),
                    "unreachable gateway reached a 'connected' client",
                )

    def test_anti_flood_retry_passes_through_backoff(self) -> None:
        """'idle' is only ever re-entered from 'backoff' -- every retry is
        rate-limited, so a down/disabled gateway is never polled in a tight
        loop that would flood dom0's qrexec-policy log."""
        for reachable in CONFIGS:
            _seen, edges = reachable_states(reachable)
            for src, succ in edges.items():
                for dst in succ:
                    if dst[1] == "idle" and src[1] != "idle":
                        self.assertEqual(
                            src[1], "backoff",
                            f"retry re-entered 'idle' without backing off: "
                            f"{src} -> {dst} (reachable={reachable})",
                        )

    def test_no_deadlock(self) -> None:
        """Every reachable state has a successor, both configs."""
        for reachable in CONFIGS:
            seen, edges = reachable_states(reachable)
            for state in seen:
                self.assertTrue(
                    edges[state],
                    f"deadlock (no successor) at {state}, "
                    f"reachable={reachable}",
                )

    def test_liveness_reachable_can_connect(self) -> None:
        """Reachable config: 'connected' reachable from every state, and
        reachable at all."""
        seen, edges = reachable_states(reachable=True)
        good = can_reach(edges, [s for s in seen if s[1] == "connected"])
        stuck = seen - good
        self.assertEqual(
            stuck, set(),
            f"client can never reach 'connected' from: {stuck}",
        )
        self.assertTrue(any(s[1] == "connected" for s in seen))

    def test_unreachable_never_gives_up(self) -> None:
        """Unreachable config: 'idle' (a fresh attempt) reachable from every
        state -- the client retries forever and never gives up."""
        seen, edges = reachable_states(reachable=False)
        good = can_reach(edges, [s for s in seen if s[1] == "idle"])
        stuck = seen - good
        self.assertEqual(
            stuck, set(),
            f"client gets stuck (cannot retry) from: {stuck}",
        )


class TestStrongFairnessLiveness(unittest.TestCase):
    """
    EVENTUAL CONNECTION under strong fairness -- stronger than the reachability
    liveness above (which only shows a path to 'connected' exists).

    Assume STRONG FAIRNESS on the fair transitions (the environment bringing the
    server up, and every client progress step) but NOT on the adversarial
    server-drop. Then every fair run reaches 'connected': there is no "fair
    trap" -- no cycle of non-'connected' states closed under fair transitions.
    A fair scheduler cannot sit in such a cycle, because every one of its SCCs
    has a fair transition leaving it toward 'connected', which strong fairness
    forces to be taken. Proven exhaustively over the reachable state space.
    """

    @staticmethod
    def _fair_traps(reachable):
        """Non-'connected' SCCs with a cycle, closed under fair transitions."""
        seen, _edges = reachable_states(reachable)
        fgraph = {s: fair_successors(s, reachable) for s in seen}
        traps = []
        for scc in _strongly_connected_components(fgraph):
            ## A single node with no fair self-loop is not a cycle (successors
            ## never include the node itself), so only multi-node SCCs cycle.
            if len(scc) < 2:
                continue
            if any(state[1] == "connected" for state in scc):
                continue
            ## Closed == no fair transition leaves the SCC (toward 'connected'
            ## or elsewhere). An escaping fair transition is continuously
            ## enabled on a recurring state, so strong fairness forces the exit.
            closed = all(
                succ in scc for state in scc for succ in fgraph[state]
            )
            if closed:
                traps.append(scc)
        return traps

    def test_no_fair_cycle_avoids_connected(self) -> None:
        """Reachable config: every fair run reaches 'connected'."""
        self.assertEqual(
            self._fair_traps(reachable=True), [],
            "a fair cycle avoids 'connected' (eventual connection broken)",
        )
        seen, _ = reachable_states(reachable=True)
        self.assertTrue(any(s[1] == "connected" for s in seen))

    def test_trap_detector_catches_a_synthetic_fair_trap(self) -> None:
        """
        Canary: the trap detector must FLAG a closed non-'connected' fair cycle,
        or 'no traps' above would be vacuous. A hand-built two-state cycle with
        no exit is a trap.
        """
        trap_graph = {
            ("up", "idle"): {("up", "backoff")},
            ("up", "backoff"): {("up", "idle")},
        }
        sccs = _strongly_connected_components(trap_graph)
        cyclic = [scc for scc in sccs if len(scc) >= 2]
        self.assertEqual(len(cyclic), 1, "SCC finder missed the 2-cycle")
        scc = cyclic[0]
        closed = all(
            succ in scc for state in scc for succ in trap_graph[state]
        )
        self.assertTrue(
            closed and not any(s[1] == "connected" for s in scc),
            "the detector would not have flagged a real fair trap",
        )


## --------------------------------------------------------------------------
## Concurrent client admission (the single-client handshake model above cannot
## express it). Mirrors SdwdateTrayIcon.accept_client: a unique-named client is
## admitted only below MAX_CLIENTS, the next is kicked, and a duplicate name is
## always kicked. MAX_CLIENTS is drift-guarded against the server constant.
## --------------------------------------------------------------------------
MAX_CLIENTS = 64


def admit(count, unique_name):
    """The admitted count after one newcomer: admitted (count+1) only if its
    name is unique AND there is capacity; otherwise kicked (count unchanged)."""
    if unique_name and count < MAX_CLIENTS:
        return count + 1
    return count


def admitted_count_successors(count):
    nxt = set()
    nxt.add(admit(count, True))  # a unique-named newcomer
    nxt.add(admit(count, False))  # a duplicate-named newcomer (kicked)
    if count > 0:
        nxt.add(count - 1)  # a client disconnects
    nxt.discard(count)
    return nxt


def admitted_reachable():
    seen = {0}
    queue = deque([0])
    while queue:
        count = queue.popleft()
        for nextcount in admitted_count_successors(count):
            if nextcount not in seen:
                seen.add(nextcount)
                queue.append(nextcount)
    return seen


class TestClientAdmissionModel(unittest.TestCase):
    """The server admits at most MAX_CLIENTS; duplicates are always kicked."""

    def test_capacity_is_a_hard_bound(self) -> None:
        seen = admitted_reachable()
        self.assertEqual(max(seen), MAX_CLIENTS)
        self.assertEqual(
            {n for n in seen if n > MAX_CLIENTS}, set(),
            "admitted count exceeded MAX_CLIENTS",
        )

    def test_newcomer_admitted_below_cap_kicked_at_cap(self) -> None:
        for count in range(MAX_CLIENTS):
            self.assertEqual(admit(count, True), count + 1)
        ## At capacity a unique newcomer is kicked (count unchanged).
        self.assertEqual(admit(MAX_CLIENTS, True), MAX_CLIENTS)

    def test_duplicate_name_never_admitted(self) -> None:
        for count in range(MAX_CLIENTS + 1):
            self.assertEqual(
                admit(count, False), count,
                "a duplicate-named client was admitted",
            )

    def test_max_clients_matches_server(self) -> None:
        """Drift guard: the model's MAX_CLIENTS equals the server constant."""
        try:
            from sdwdate_gui import (  # pylint: disable=import-outside-toplevel
                sdwdate_gui_server,
            )
        except (ModuleNotFoundError, ImportError) as exc:  # pragma: no cover
            raise unittest.SkipTest(
                "sdwdate_gui_server not importable (PyQt5 absent)"
            ) from exc
        self.assertEqual(MAX_CLIENTS, sdwdate_gui_server.MAX_CLIENTS)


if __name__ == "__main__":
    unittest.main()
