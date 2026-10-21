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
                    exists. sdwdate-gui-qubes-proxy-helper symlinks that running
                    socket to the gateway's /run/qubes-rpc/sdwdate-gui.Connect
                    qrexec endpoint.
  * client idle/connecting/connected/retry/gaveup -- the workstation client +
      sdwdate-gui-qubes-proxy:
      idle       -> the client connects to its local systemd socket, which
                    socket-activates the proxy; the proxy calls
                    sdwdate-gui.ConnectCheck over qrexec (modelled as
                    'connecting').
      connecting -> ConnectCheck BLOCKS on the gateway while an operational
                    server is still starting, then returns 'y' and the proxy
                    bridges sdwdate-gui.Connect ('connected'). On a disabled /
                    non-server gateway it returns 'q' ("will not become
                    available"), so the proxy drops the
                    qubes-gateway-server-disabled flag and the client exits
                    ('gaveup'). The client does NOT poll qrexec in a loop: the
                    gateway side blocks, so a down/disabled gateway cannot be
                    hammered into dom0's qrexec-policy log.
      connected  -> the bridge is up until the server drops.
      retry      -> a dropped CONNECTED session pauses a FIXED reconnect delay
                    (asyncio.sleep in main_loop) before retrying (idle). This
                    is the only reconnect path; it rate-limits the drop/retry
                    cycle but is NOT a capped-exponential backoff.
      gaveup     -> the client process exits (terminal): the disabled flag is
                    set, so the next main_loop pass breaks out.

One gateway-reachability dimension, constant per run:
  * reachable=True  -- an operational gateway (not disabled, runs the server):
                       ConnectCheck answers, blocking until the server socket is
                       up, so the client always eventually connects and NEVER
                       gives up; the server may come up and down (restart).
  * reachable=False -- a disabled / non-server / unreachable gateway:
                       ConnectCheck returns 'q' (or the qrexec call fails), so
                       'connected' is unreachable and the client gives up
                       instead of retrying.

Proved over both configs:
  * SAFETY         -- a client only BECOMES 'connected' from an up server; the
                      unreachable config never reaches 'connected'.
  * RATE-LIMITED   -- every reconnect passes through 'retry': 'idle' is only
                      re-entered from 'retry', never directly from a dropped
                      'connected'. The client pauses a fixed delay between a
                      drop and the next attempt rather than reconnecting in a
                      tight loop.
  * GIVE-UP        -- the unreachable config REACHES 'gaveup' (a disabled
                      gateway is given up on, not retried forever); the
                      reachable config never reaches 'gaveup' (an operational
                      gateway is always waited out).
  * NO DEADLOCK    -- every reachable NON-terminal state has a successor
                      ('gaveup' is terminal by design: the client has exited).
  * LIVENESS       -- reachable config: 'connected' is reachable from every
                      reachable state (never permanently stuck) and reachable at
                      all. unreachable config: 'gaveup' is reachable from every
                      state -- the client always eventually gives up.
"""

# pylint: disable=invalid-name

import unittest
from collections import deque

## Component state vocabularies.
SERVER = ("down", "up")
CLIENT = ("idle", "connecting", "connected", "retry", "gaveup")

## A protocol state is (server, client).
INITIAL = ("down", "idle")

## 'gaveup' models the client process having exited; it is terminal and has no
## successor, so the no-deadlock proof exempts it.
TERMINAL = "gaveup"

## The gateway-reachability configs.
CONFIGS = (True, False)


def successors(state, reachable):
    """All states reachable in one step from `state`. The environment move (the
    server starting/stopping) is enabled only for a reachable gateway; the
    client moves follow the connect loop. Guards here ARE the safety
    argument."""
    server, client = state
    nxt = set()

    ## Environment: an operational gateway's server may start or stop at any
    ## time; a disabled / non-server / unreachable gateway's server never comes
    ## up.
    if reachable:
        nxt.add(("up" if server == "down" else "down", client))

    ## Client connect loop.
    if client == "idle":
        ## Local socket activation -> proxy calls sdwdate-gui.ConnectCheck.
        nxt.add((server, "connecting"))
    elif client == "connecting":
        if reachable:
            ## ConnectCheck blocks until the server socket is up, then bridges.
            ## While the server is down the client simply waits (no client move;
            ## only the environment bringing the server up makes progress).
            if server == "up":
                nxt.add((server, "connected"))
        else:
            ## ConnectCheck returns 'q' (or the qrexec call fails): the gateway
            ## will never serve, so the disabled flag is dropped and the client
            ## exits. No tight retry loop.
            nxt.add((server, "gaveup"))
    elif client == "connected":
        ## A dropped server is noticed and reconnected THROUGH the fixed retry
        ## delay.
        if server == "down":
            nxt.add((server, "retry"))
    elif client == "retry":
        ## After the fixed reconnect delay, retry from idle.
        nxt.add((server, "idle"))
    ## 'gaveup' is terminal: the client process has exited, no successor.

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
    reverse: dict[tuple[str, str], set[tuple[str, str]]] = {
        s: set() for s in edges
    }
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

    def test_rate_limited_retry_passes_through_delay(self) -> None:
        """'idle' is only ever re-entered from 'retry' -- every reconnect is
        preceded by the fixed delay, so a dropped session is not reconnected in
        a tight loop."""
        for reachable in CONFIGS:
            _seen, edges = reachable_states(reachable)
            for src, succ in edges.items():
                for dst in succ:
                    if dst[1] == "idle" and src[1] != "idle":
                        self.assertEqual(
                            src[1], "retry",
                            f"retry re-entered 'idle' without the delay: "
                            f"{src} -> {dst} (reachable={reachable})",
                        )

    def test_give_up_only_on_unreachable_gateway(self) -> None:
        """The unreachable config reaches 'gaveup' (a disabled gateway is given
        up on); the reachable config never does (an operational gateway is
        waited out)."""
        seen_unreachable, _ = reachable_states(reachable=False)
        self.assertTrue(
            any(s[1] == TERMINAL for s in seen_unreachable),
            "unreachable gateway never reached 'gaveup' (no give-up)",
        )
        seen_reachable, _ = reachable_states(reachable=True)
        self.assertEqual(
            {s for s in seen_reachable if s[1] == TERMINAL}, set(),
            "reachable gateway wrongly gave up",
        )

    def test_no_deadlock(self) -> None:
        """Every reachable NON-terminal state has a successor, both configs;
        'gaveup' is terminal by design."""
        for reachable in CONFIGS:
            seen, edges = reachable_states(reachable)
            for state in seen:
                if state[1] == TERMINAL:
                    self.assertEqual(
                        edges[state], set(),
                        f"terminal 'gaveup' has a successor at {state}",
                    )
                    continue
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

    def test_unreachable_always_gives_up(self) -> None:
        """Unreachable config: 'gaveup' reachable from every state -- the client
        always eventually gives up on a disabled gateway rather than retrying
        forever."""
        seen, edges = reachable_states(reachable=False)
        good = can_reach(edges, [s for s in seen if s[1] == TERMINAL])
        stuck = seen - good
        self.assertEqual(
            stuck, set(),
            f"client can never reach 'gaveup' from: {stuck}",
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
            ("up", "idle"): {("up", "retry")},
            ("up", "retry"): {("up", "idle")},
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
