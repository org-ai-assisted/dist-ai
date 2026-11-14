#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Daemon-level END-TO-END tests for kloak's privilege-separated Wayland adapter.

Unlike the kloak-tests harness suite (which drives pure functions and forked
fragments of src/kloak*.c), this lane runs the REAL daemon pair -- the libinput
proxy /usr/bin/kloak that fork+execve's the sandboxed Wayland adapter kloakwl --
against a REAL wlroots compositor, exercising the whole wiring the unit tests
cannot: the CTP pipe handshake, the in-process sandbox (user namespace,
pivot_root, capability + uid drop), the Wayland connect, and the degraded-mode
fallback.

Built from the kloak source (KLOAK_REPO) so the test tracks the source, not a
possibly-stale installed package. bindir is pointed at the build tree, so the
proxy execs the freshly built kloakwl and nothing under /usr/bin is touched.

Two paths are covered:

  * connected + privsep (test_1): a headless labwc (wlroots) with a uinput
    keyboard on its seat gives kloakwl the globals + seat keyboard it needs.
    kloak must come up WITHOUT entering degraded mode, the kloakwl child must
    drop to the unprivileged kloakwl uid (the privsep guarantee), and injecting
    a keystroke must not crash it.
  * connect-failure degraded (test_2): pointed at a nonexistent Wayland display,
    the shipped daemon degrades instead of aborting -- the kloakwl child reports
    CTP_PACKET_WAYLAND_LOST and exit(0)s, and the parent stays up WITHOUT grabbing
    the devices, awaiting the escape combo (the Whonix/kloak#35 fallback, with the
    coupled #34 dead-child-pipe spin avoided by dropping the child fd from the poll
    set). Injecting the escape combo then exits it cleanly. The daemon-level
    complement to the kloakwl/kloak harness regressions.
  * connect-failure fatal opt-in (test_2b): with KLOAK_EXIT_ON_WL_CONNECT_FAILURE=1
    the same connect failure is turned back into a non-zero fatal exit.

Plus the random-delay lanes -- kloak's reason to exist -- each injecting real input
through the grabbed device and measuring, at a focused wev client, TWO delays per
event:

  * the scheduled delay: the released event's `time` field (kloak's scheduled
    release, CLOCK_MONOTONIC ms) minus the injection time -- asserts the schedule
    is bounded by -d max_delay and that it VARIES (randomised jitter).
  * the real delay: wall-clock elapsed between injecting and the released line
    appearing at the client -- asserts the event is actually WITHHELD that long
    and never arrives appreciably before its scheduled time. A regression that
    flushes the queue immediately while still stamping a future `sched_time`
    keeps a perfect scheduled delay but a near-zero real delay, so the scheduled
    delay alone cannot catch it.

  * keyboard keys (test_3), mouse button clicks (test_4), mouse motion (test_5),
    and scroll wheel (test_6) -- the input classes kloak delays, all on the one
    release scheduler. test_3/test_4 also assert each press is matched by a
    RELEASE at the client (no stuck keys/buttons), and test_4 that the button
    code survives the proxy.

DESTRUCTIVE + root-only: builds in the source tree, creates the kloakwl system
user if absent, drives uinput, and runs a compositor. Authorized skip (euid !=
0, no /dev/uinput, or labwc/python3-evdev/the kloak source absent), so a plain
unit-CI container reports the lane SKIP, never a false pass or a hard failure.
"""

import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from typing import Any

KLOAKWL_USER = 'kloakwl'


def _repo():
    return os.path.abspath(os.environ.get('KLOAK_REPO', '').strip() or '/')


def _sh(*cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def _kloakwl_procs_owned_by_user():
    ## pids of running 'kloakwl' processes whose owner is the kloakwl user --
    ## i.e. the sandbox child AFTER it dropped privileges.
    out = _sh('ps', '-eo', 'user:32,comm').stdout.splitlines()
    return [line for line in out
            if line.split()[:1] == [KLOAKWL_USER]
            and line.rsplit(None, 1)[-1] == KLOAKWL_USER]


def _kloakwl_pids():
    ## PIDs of the kloakwl-owned 'kloakwl' privsep children. Returned as a set so
    ## a before/after delta can tell a NEWLY dropped child from one left running
    ## by an earlier test (a global presence check would false-positive on those).
    out = _sh('ps', '-eo', 'pid=,user:32=,comm=').stdout.splitlines()
    pids = set()
    for line in out:
        parts = line.split()
        if (len(parts) >= 3 and parts[1] == KLOAKWL_USER
                and parts[-1] == KLOAKWL_USER):
            pids.add(parts[0])
    return pids


class KloakDaemonE2E(unittest.TestCase):
    _created_user = False
    _compositor = None
    _uinput = None
    _work = None
    ## Set in setUpClass (a classmethod), so declare here for the type checker:
    ## the evdev module and the virtual-mouse UInput the delay tests drive.
    _uinput_mouse: Any = None
    _evdev: Any = None
    kloak_bin: str
    runtime_dir: str
    wayland_display: str

    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            ## style-ok: allow-skip: e2e drives the real privsep sandbox + uinput, needs root
            raise unittest.SkipTest('needs root')
        src = os.path.join(_repo(), 'src', 'kloak.c.in')
        if not os.path.exists(src):
            ## style-ok: allow-skip: kloak source absent (not a --component run)
            raise unittest.SkipTest('kloak.c.in not found -- set KLOAK_REPO')
        if not os.path.exists('/dev/uinput'):
            ## style-ok: allow-skip: no /dev/uinput -- cannot give the seat a keyboard
            raise unittest.SkipTest('/dev/uinput absent')
        for tool in ('make', 'labwc', 'unshare'):
            if shutil.which(tool) is None:
                ## style-ok: allow-skip: e2e compositor/build dependency absent in the unit-CI env
                raise unittest.SkipTest('%s not installed (e2e dependency)' % tool)
        try:
            import evdev  # noqa: F401
        except ImportError:
            ## style-ok: allow-skip: python3-evdev is an e2e-lane uinput dependency
            raise unittest.SkipTest('python3-evdev not installed (e2e dependency)')

        repo = _repo()
        ## Build in place (no copy), with the proxy's compiled-in kloakwl path
        ## pointed at the build tree so nothing under /usr/bin is touched.
        cls.addClassCleanup(lambda: _sh('make', '-C', repo, 'clean'))
        build = _sh('make', '-C', repo, 'bindir=%s' % repo)
        assert build.returncode == 0, 'kloak build failed:\n%s' % build.stderr[-2000:]
        cls.kloak_bin = os.path.join(repo, 'kloak')

        if _sh('id', KLOAKWL_USER).returncode != 0:
            add = _sh('useradd', '--system', '--no-create-home',
                      '--shell', '/usr/sbin/nologin', KLOAKWL_USER)
            assert add.returncode == 0, 'useradd kloakwl failed:\n%s' % add.stderr
            cls._created_user = True
            cls.addClassCleanup(cls._remove_user)

        cls._work = tempfile.mkdtemp(prefix='kloak-e2e-')
        cls.addClassCleanup(lambda: shutil.rmtree(cls._work, ignore_errors=True))
        cls.runtime_dir = os.path.join(cls._work, 'xdg')
        os.makedirs(cls.runtime_dir)
        os.chmod(cls.runtime_dir, 0o700)

        cls._start_uinput_keyboard()
        cls._start_uinput_pointer()
        cls._start_compositor()

    @classmethod
    def _remove_user(cls):
        if cls._created_user:
            _sh('userdel', KLOAKWL_USER)

    @classmethod
    def _start_uinput_keyboard(cls):
        ## Create the virtual keyboard BEFORE the compositor so libinput
        ## enumerates it and the seat advertises a keyboard capability (which
        ## kloakwl requires). The UInput object keeps the device alive.
        import evdev
        from evdev import UInput, ecodes
        keys = [ecodes.KEY_A, ecodes.KEY_ESC,
                ecodes.KEY_LEFTSHIFT, ecodes.KEY_RIGHTSHIFT]
        cls._uinput = UInput({ecodes.EV_KEY: keys}, name='kloak-e2e-kbd')
        cls._evdev = evdev
        cls.addClassCleanup(cls._uinput.close)
        time.sleep(1)

    @classmethod
    def _start_uinput_pointer(cls):
        ## A virtual MOUSE (relative motion + buttons + wheel) alongside the
        ## keyboard, created before the compositor so libinput enumerates it and
        ## the seat advertises a pointer capability. kloak grabs it and drives the
        ## compositor only through its own delayed virtual pointer, so what a
        ## focused client sees is kloak's output, not the raw device.
        from evdev import UInput, ecodes
        cap = {
            ecodes.EV_REL: [ecodes.REL_X, ecodes.REL_Y, ecodes.REL_WHEEL],
            ecodes.EV_KEY: [ecodes.BTN_LEFT, ecodes.BTN_RIGHT],
        }
        cls._uinput_mouse = UInput(cap, name='kloak-e2e-mouse')
        cls.addClassCleanup(cls._uinput_mouse.close)
        time.sleep(1)

    @classmethod
    def _start_compositor(cls):
        env = dict(os.environ)
        env.update({
            'XDG_RUNTIME_DIR': cls.runtime_dir,
            ## wlroots: software render, headless output, plus the libinput
            ## backend so the uinput keyboard reaches the seat.
            'WLR_BACKENDS': 'libinput,headless',
            'WLR_RENDERER': 'pixman',
            'WLR_HEADLESS_OUTPUTS': '1',
            ## libseat builtin opens /dev/input + /dev/dri directly as root; a
            ## headless container has no seatd/logind/VT.
            'LIBSEAT_BACKEND': 'builtin',
        })
        ## unshare --net isolates the abstract X11 socket so labwc's Xwayland
        ## cannot clash with another compositor already in this machine.
        log = open(os.path.join(cls._work, 'labwc.log'), 'wb')
        cls._compositor_log = log
        ## _stop_compositor closes the log (and terminates the compositor if it
        ## started); register it before Popen so a raising Popen cannot leak the
        ## fd. cls._compositor stays None until assigned, which _stop_compositor
        ## tolerates.
        cls.addClassCleanup(cls._stop_compositor)
        cls._compositor = subprocess.Popen(
            ['unshare', '--net', 'labwc'], env=env,
            stdout=log, stderr=subprocess.STDOUT)

        cls.wayland_display = ''
        for _ in range(30):
            if cls._compositor.poll() is not None:
                break
            socks = [name for name in os.listdir(cls.runtime_dir)
                     if name.startswith('wayland-') and not name.endswith('.lock')]
            if socks:
                cls.wayland_display = sorted(socks)[0]
                break
            time.sleep(1)
        if not cls.wayland_display:
            with open(os.path.join(cls._work, 'labwc.log'),
                      encoding='utf-8', errors='replace') as handle:
                tail = handle.read()[-2000:]
            raise unittest.SkipTest(
                ## style-ok: allow-skip: headless wlroots could not start here (no DRM/seat)
                'labwc did not expose a Wayland socket:\n%s' % tail)

    @classmethod
    def _stop_compositor(cls):
        if cls._compositor and cls._compositor.poll() is None:
            cls._compositor.terminate()
            try:
                cls._compositor.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls._compositor.kill()
        if getattr(cls, '_compositor_log', None):
            cls._compositor_log.close()

    def _run_kloak(self, runtime_dir, wayland_display, max_delay=0,
                   extra_env=None):
        """Start kloak with its own log; return (Popen, log_path). max_delay is
        kloak's -d (ms); 0 means no jitter (the fast connected/degraded checks),
        a positive value is used by the delay-measurement test. extra_env merges
        additional environment variables (e.g. KLOAK_EXIT_ON_WL_CONNECT_FAILURE)."""
        env = dict(os.environ)
        env['XDG_RUNTIME_DIR'] = runtime_dir
        env['WAYLAND_DISPLAY'] = wayland_display
        if extra_env:
            env.update(extra_env)
        log_path = os.path.join(self._work, 'kloak-%s.log' % wayland_display)
        log = open(log_path, 'wb')
        ## Register the close the instant the fd is acquired, so a raising Popen
        ## cannot leak it.
        self.addCleanup(log.close)
        proc = subprocess.Popen(
            [self.kloak_bin, '-d', str(max_delay)], env=env,
            stdout=log, stderr=subprocess.STDOUT)
        self.addCleanup(self._kill, proc)
        return proc, log_path

    @staticmethod
    def _kill(proc):
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    @staticmethod
    def _read(path):
        with open(path, encoding='utf-8', errors='replace') as handle:
            return handle.read()

    def _start_wev(self):
        ## A focused Wayland client (wev) that logs every seat event with its
        ## `time`. Returns its log path; the process is cleaned up automatically.
        wev = shutil.which('wev')
        if wev is None:
            ## style-ok: allow-skip: wev is an e2e-lane dependency for observing output
            raise unittest.SkipTest('wev not installed (e2e dependency)')
        wev_log_path = os.path.join(
            self._work, 'wev-%s.log' % os.urandom(4).hex())
        wev_log = open(wev_log_path, 'wb')
        self.addCleanup(wev_log.close)
        env = dict(os.environ)
        env['XDG_RUNTIME_DIR'] = self.runtime_dir
        env['WAYLAND_DISPLAY'] = self.wayland_display
        ## stdbuf -oL: wev block-buffers stdout to a file, so without this the
        ## focus/event lines never reach the log until wev exits. Line-buffer it
        ## so focus and events are observable live.
        wev_proc = subprocess.Popen(
            ['stdbuf', '-oL', '-eL', wev], env=env, stdout=wev_log,
            stderr=subprocess.STDOUT)
        self.addCleanup(self._kill, wev_proc)
        return wev_log_path

    def _wait_for_focus(self, wev_log_path, iface, timeout=10):
        ## Wait until wev logs an <iface> 'enter' (keyboard or pointer focus) on a
        ## single line, so an injected event is actually delivered to it. Matching
        ## iface AND 'enter' on the SAME line avoids a false hit from the seat
        ## capability announcement (which names wl_pointer before any enter).
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for line in self._read(wev_log_path).splitlines():
                if iface in line and 'enter' in line:
                    return True
            time.sleep(0.2)
        return False

    @staticmethod
    def _pointer_focus_state(log):
        ## The last wl_pointer enter/leave in the log == current focus. Overshooting
        ## the surface walks the cursor back off (enter THEN leave), so a bare
        ## "an enter appeared" is not enough -- the LAST focus event must be enter.
        state = None
        for line in log.splitlines():
            if 'wl_pointer' not in line:
                continue
            if 'enter' in line:
                state = 'enter'
            elif 'leave' in line:
                state = 'leave'
        return state

    def _establish_pointer_focus(self, wev_log_path, timeout=20):
        ## kloak's virtual cursor starts at (0, 0); walk it to roughly the middle
        ## of the default 640x480 wev surface and STOP. Overshooting would carry
        ## it back off the surface (wl_pointer leave), so move a bounded total
        ## (~300, ~230) rather than nudging until an enter is seen, then wait for
        ## the kloak-delayed moves to flush and focus to settle on enter.
        ecodes = self._evdev.ecodes
        for _ in range(10):
            self._uinput_mouse.write(ecodes.EV_REL, ecodes.REL_X, 30)
            self._uinput_mouse.write(ecodes.EV_REL, ecodes.REL_Y, 23)
            self._uinput_mouse.syn()
            time.sleep(0.03)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._pointer_focus_state(self._read(wev_log_path)) == 'enter':
                return True
            time.sleep(0.3)
        return False

    def _count_releases(self, wev_log_path, is_release_line):
        ## The `time` stamp of every released line matching is_release_line, in
        ## log order. is_release_line(line) returns the uint32 ms stamp for a
        ## measured release event (e.g. a wl_keyboard press of our key), else None.
        return [stamp for stamp in
                (is_release_line(line)
                 for line in self._read(wev_log_path).splitlines())
                if stamp is not None]

    def _measure_delays(self, wev_log_path, inject_one, is_release_line, num,
                        max_delay):
        """Inject num events one at a time and, for EACH, capture both:

          * stamp delay = the released event's `time` field (kloak's scheduled
            release, CLOCK_MONOTONIC ms) minus the injection time. Proves the
            SCHEDULE is bounded and random.
          * real delay  = wall-clock (CLOCK_MONOTONIC) elapsed between injecting
            the event and its released line first appearing at the wev client.
            Proves the event is actually WITHHELD that long -- a regression that
            flushes the queue immediately while still stamping a future
            `sched_time` keeps a perfect stamp delay but a near-zero real delay,
            so the stamp delay ALONE cannot see it.

        Injects the next event only after the current one has arrived, so the
        spacing exceeds the applied delay and the per-event prev_release clamp
        never saturates the random range. Returns (stamp_delays_ms,
        real_delays_ms), both length num."""
        stamp_delays = []
        real_delays = []
        ## Baseline past any already-released events (e.g. focus-establishing
        ## motions), so the first measured arrival is our first injected event.
        seen = len(self._count_releases(wev_log_path, is_release_line))
        for _ in range(num):
            inj_mono = time.monotonic()
            inj_stamp = int(
                time.clock_gettime(time.CLOCK_MONOTONIC) * 1000) & 0xffffffff
            inject_one()
            deadline = inj_mono + (max_delay + 2000) / 1000.0
            arrival_mono = None
            rel_stamp = None
            while time.monotonic() < deadline:
                stamps = self._count_releases(wev_log_path, is_release_line)
                if len(stamps) > seen:
                    arrival_mono = time.monotonic()
                    rel_stamp = stamps[seen]
                    seen = len(stamps)
                    break
                time.sleep(0.004)
            if rel_stamp is None:
                self.fail(
                    'a released event never reached the client within %d ms '
                    '(released %d of %d so far):\nwev:\n%s'
                    % (max_delay + 2000, len(stamp_delays), num,
                       self._read(wev_log_path)))
            stamp_delays.append((rel_stamp - inj_stamp) & 0xffffffff)
            real_delays.append((arrival_mono - inj_mono) * 1000.0)
        return stamp_delays, real_delays

    def _assert_delays(self, stamp_delays, real_delays, max_delay, what):
        ## Shared assertions for the three delay lanes.
        ## stamp bound + spread: the SCHEDULE is bounded by max_delay and random.
        tol = 80
        for delay in stamp_delays:
            self.assertLessEqual(
                delay, max_delay + tol,
                'released %s scheduled delay %d ms exceeds max_delay %d (+%d '
                'tol); delays=%r' % (what, delay, max_delay, tol, stamp_delays))
        self.assertGreater(
            max(stamp_delays) - min(stamp_delays), max_delay // 4,
            '%s scheduled delays show no spread (jitter not randomised): %r'
            % (what, stamp_delays))
        ## Real-time enforcement (Whonix/kloak anti-deanon guarantee): the event
        ## must not arrive at the client appreciably EARLIER than its scheduled
        ## release. real >= stamp structurally on correct code (arrival fires
        ## only once current_time >= sched_time); early_tol only absorbs
        ## measurement slack. A queue flushed immediately (real ~ constant small
        ## latency while stamp is a large random delay) fails this -- the gap the
        ## stamp-only check cannot catch.
        early_tol = 60
        for stamp, real in zip(stamp_delays, real_delays):
            self.assertGreaterEqual(
                real, stamp - early_tol,
                '%s arrived %.0f ms after injection but was scheduled for %d ms '
                '-- released EARLY, the random delay is not actually enforced '
                '(flushed immediately?): real=%r stamp=%r'
                % (what, real, stamp, real_delays, stamp_delays))
        ## And it must not sit in the queue far longer than scheduled.
        real_tol = 400
        for real in real_delays:
            self.assertLessEqual(
                real, max_delay + real_tol,
                '%s real release latency %.0f ms exceeds max_delay %d (+%d tol) '
                '-- event withheld too long: %r'
                % (what, real, max_delay, real_tol, real_delays))

    def test_1_connected_privsep(self):
        proc, log_path = self._run_kloak(self.runtime_dir, self.wayland_display)
        time.sleep(4)
        self.assertIsNone(proc.poll(),
                          'kloak exited against a live compositor:\n%s'
                          % self._read(log_path))
        log = self._read(log_path)
        for marker in ('Could not connect', 'await escape key combo',
                       'FATAL', 'aborted'):
            self.assertNotIn(marker, log,
                             'kloak degraded/aborted on the connected path '
                             '(%r):\n%s' % (marker, log))
        ## The sandbox child must have dropped to the unprivileged kloakwl uid.
        self.assertTrue(
            _kloakwl_procs_owned_by_user(),
            'no kloakwl process owned by the kloakwl user (privsep drop failed)')

        ## Inject a keystroke through the grabbed virtual keyboard; the daemon
        ## must process + forward it without crashing.
        ecodes = self._evdev.ecodes
        self._uinput.write(ecodes.EV_KEY, ecodes.KEY_A, 1)
        self._uinput.write(ecodes.EV_KEY, ecodes.KEY_A, 0)
        self._uinput.syn()
        time.sleep(1)
        self.assertIsNone(proc.poll(),
                          'kloak crashed processing an injected key:\n%s'
                          % self._read(log_path))

    def test_2_connect_failure_degraded(self):
        ## A private empty runtime dir so <dir>/<display> names no socket and the
        ## Wayland connect fails deterministically. The shipped daemon degrades:
        ## the kloakwl child reports CTP_PACKET_WAYLAND_LOST and exit(0)s, and the
        ## parent stays up WITHOUT grabbing the devices, awaiting the escape combo
        ## (Whonix/kloak#35; the coupled #34 dead-child-pipe spin is avoided by
        ## dropping the child fd from the poll set). Injecting the escape combo
        ## (KEY_RIGHTSHIFT + KEY_ESC, the DEFAULT_ESC_KEY_STR) then exits it clean.
        runtime_dir = os.path.join(self._work, 'degraded-xdg')
        os.makedirs(runtime_dir, exist_ok=True)
        os.chmod(runtime_dir, 0o700)
        proc, log_path = self._run_kloak(runtime_dir, 'kloak-nonexistent-wl')

        ## It must stay up (degraded), not abort or spin.
        time.sleep(4)
        self.assertIsNone(
            proc.poll(),
            'kloak exited on a failed Wayland connect instead of degrading:\n%s'
            % self._read(log_path))
        log = self._read(log_path)
        self.assertIn('await escape key combo', log,
                      'kloak did not log the degraded-mode warning:\n%s' % log)
        self.assertNotIn('FATAL', log,
                         'kloak aborted on the degraded path:\n%s' % log)

        ## The escape combo must bring the degraded daemon down cleanly (exit 0).
        ecodes = self._evdev.ecodes
        for key in (ecodes.KEY_RIGHTSHIFT, ecodes.KEY_ESC):
            self._uinput.write(ecodes.EV_KEY, key, 1)
        self._uinput.syn()
        time.sleep(0.2)
        for key in (ecodes.KEY_ESC, ecodes.KEY_RIGHTSHIFT):
            self._uinput.write(ecodes.EV_KEY, key, 0)
        self._uinput.syn()
        try:
            rc = proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            self.fail('degraded kloak did not exit on the escape combo:\n%s'
                      % self._read(log_path))
        self.assertEqual(
            rc, 0,
            'degraded kloak should exit 0 on the escape combo:\n%s'
            % self._read(log_path))
        self.assertIn('Escape combo pressed', self._read(log_path))

    def test_2b_connect_failure_fatal_optin(self):
        ## KLOAK_EXIT_ON_WL_CONNECT_FAILURE=1 turns the degraded fallback back
        ## into a non-zero fatal exit on a failed Wayland connect.
        runtime_dir = os.path.join(self._work, 'fatal-xdg')
        os.makedirs(runtime_dir, exist_ok=True)
        os.chmod(runtime_dir, 0o700)
        proc, log_path = self._run_kloak(
            runtime_dir, 'kloak-nonexistent-wl',
            extra_env={'KLOAK_EXIT_ON_WL_CONNECT_FAILURE': '1'})
        try:
            rc = proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            self.fail('kloak did not exit with the fatal opt-in set '
                      '(expected a fatal exit, not a hang):\n%s'
                      % self._read(log_path))
        self.assertNotEqual(
            rc, 0,
            'kloak should exit non-zero with '
            'KLOAK_EXIT_ON_WL_CONNECT_FAILURE=1:\n%s' % self._read(log_path))
        self.assertIn('Could not connect to Wayland compositor',
                      self._read(log_path),
                      'kloak did not log the connect failure')

    def test_3_keyboard_delay_measured(self):
        """End-to-end proof of kloak's reason to exist: inject real keystrokes
        through the grabbed keyboard and verify each reaches a focused client
        after a RANDOM delay bounded by max_delay, measured on the real
        device -> kloak -> compositor -> client path. The released wl_keyboard
        event's `time` (kloak's scheduled release time, CLOCK_MONOTONIC ms)
        minus the injection time is the applied delay."""
        max_delay = 200
        ecodes = self._evdev.ecodes
        key_a = ecodes.KEY_A
        ## wl_keyboard.key reports the XKB keycode, which is the evdev code + 8
        ## (the fixed historical X11 offset), so KEY_A (30) arrives as 38.
        wl_keycode = key_a + 8

        wev_log_path = self._start_wev()
        ## Wait for wev to receive keyboard focus, so an injected key is actually
        ## delivered to it.
        if not self._wait_for_focus(wev_log_path, 'wl_keyboard'):
            self.fail('wev never got keyboard focus:\n%s'
                      % self._read(wev_log_path))

        ## kloak grabs the keyboard and re-injects each key after a random delay.
        proc, log_path = self._run_kloak(
            self.runtime_dir, self.wayland_display, max_delay=max_delay)
        time.sleep(2)
        self.assertIsNone(proc.poll(),
                          'kloak exited before the delay test:\n%s'
                          % self._read(log_path))

        ## wev prints `time` with %d on a uint32_t, so a value >= 0x80000000
        ## (~24.9d monotonic uptime) can print negative; accept an optional minus
        ## and mask to 32 bits so the stamp matches kloak's uint32 ms domain.
        def _kb_stamp(line, want_state):
            if 'wl_keyboard' not in line:
                return None
            match = re.search(r'time: (-?\d+); key: (\d+); state: (\d+)', line)
            if (match is not None and int(match.group(2)) == wl_keycode
                    and int(match.group(3)) == want_state):
                return int(match.group(1)) & 0xffffffff
            return None

        def inject_key():
            self._uinput.write(ecodes.EV_KEY, key_a, 1)
            self._uinput.write(ecodes.EV_KEY, key_a, 0)
            self._uinput.syn()

        num_keys = 15
        stamp_delays, real_delays = self._measure_delays(
            wev_log_path, inject_key, lambda line: _kb_stamp(line, 1),
            num_keys, max_delay)
        self._assert_delays(stamp_delays, real_delays, max_delay, 'key press')

        ## Every press must be matched by a RELEASE at the client -- a daemon
        ## that dropped key-ups would leave keys stuck down. Drain the last
        ## scheduled releases first.
        time.sleep((max_delay + 500) / 1000.0)
        releases = self._count_releases(
            wev_log_path, lambda line: _kb_stamp(line, 0))
        self.assertGreaterEqual(
            len(releases), num_keys,
            'expected >= %d key releases (state 0) at the client, got %d -- '
            'releases dropped, keys would stick down:\nwev:\n%s'
            % (num_keys, len(releases), self._read(wev_log_path)))

    def test_4_pointer_click_delay_measured(self):
        """Same proof as test_3, for mouse CLICKS: inject real BTN_LEFT clicks
        through the grabbed mouse and verify each wl_pointer button event reaches
        a focused client after a RANDOM delay bounded by max_delay. The child
        schedules clicks on the same release scheduler as keys, so the button
        event's `time` (its scheduled release, CLOCK_MONOTONIC ms) minus the
        injection time is the applied delay."""
        max_delay = 200
        ecodes = self._evdev.ecodes
        wev_log_path = self._start_wev()
        ## Keyboard focus confirms wev is up and the seat is live before kloak
        ## grabs the devices.
        if not self._wait_for_focus(wev_log_path, 'wl_keyboard'):
            self.fail('wev never got keyboard focus:\n%s'
                      % self._read(wev_log_path))

        proc, log_path = self._run_kloak(
            self.runtime_dir, self.wayland_display, max_delay=max_delay)
        time.sleep(2)
        self.assertIsNone(proc.poll(),
                          'kloak exited before the click test:\n%s'
                          % self._read(log_path))

        ## Move the (grabbed, kloak-driven) cursor onto the wev surface so button
        ## events are delivered there.
        if not self._establish_pointer_focus(wev_log_path):
            self.fail('wev never got pointer focus (cursor did not reach the '
                      'surface):\nwev:\n%s\nkloak:\n%s'
                      % (self._read(wev_log_path), self._read(log_path)))
        ## Drain every delayed focus-establishing motion (each <= max_delay) so
        ## the measurement baseline is stable before the clicks.
        time.sleep((max_delay + 500) / 1000.0)

        ## BTN_LEFT reaches wl_pointer as button code 272. Requiring the code in
        ## the matcher also proves the button value survives the proxy (M4): a
        ## wrong code would miscount and fail.
        wl_btn_left = 272

        def _btn_stamp(line, want_state):
            if 'wl_pointer' not in line or 'button' not in line:
                return None
            t_match = re.search(r'time:\s*(-?\d+)', line)
            b_match = re.search(r'button:\s*(\d+)', line)
            s_match = re.search(r'state:\s*(\d+)', line)
            if (t_match is not None and b_match is not None
                    and s_match is not None
                    and int(b_match.group(1)) == wl_btn_left
                    and int(s_match.group(1)) == want_state):
                return int(t_match.group(1)) & 0xffffffff
            return None

        def inject_click():
            ## Press and release in SEPARATE syn frames (a zero-duration click in
            ## one frame can be dropped).
            self._uinput_mouse.write(ecodes.EV_KEY, ecodes.BTN_LEFT, 1)
            self._uinput_mouse.syn()
            time.sleep(0.02)
            self._uinput_mouse.write(ecodes.EV_KEY, ecodes.BTN_LEFT, 0)
            self._uinput_mouse.syn()

        num_clicks = 12
        stamp_delays, real_delays = self._measure_delays(
            wev_log_path, inject_click, lambda line: _btn_stamp(line, 1),
            num_clicks, max_delay)
        self._assert_delays(stamp_delays, real_delays, max_delay, 'button press')

        ## Every press must be matched by a button RELEASE (state 0) at the
        ## client -- a dropped button-up would leave the button stuck down (E2).
        time.sleep((max_delay + 500) / 1000.0)
        releases = self._count_releases(
            wev_log_path, lambda line: _btn_stamp(line, 0))
        self.assertGreaterEqual(
            len(releases), num_clicks,
            'expected >= %d button releases (state 0) at the client, got %d -- '
            'releases dropped, button would stick down:\nwev:\n%s'
            % (num_clicks, len(releases), self._read(wev_log_path)))

    def test_5_pointer_motion_delay_measured(self):
        """Same proof as test_3, for mouse MOTION: inject real relative moves
        through the grabbed mouse and verify each wl_pointer motion event reaches
        a focused client after a RANDOM delay bounded by max_delay. Each injected
        move changes the integer cursor position, so the child emits exactly one
        delayed motion_absolute per move; its `time` minus the injection time is
        the applied delay."""
        max_delay = 200
        ecodes = self._evdev.ecodes
        wev_log_path = self._start_wev()
        if not self._wait_for_focus(wev_log_path, 'wl_keyboard'):
            self.fail('wev never got keyboard focus:\n%s'
                      % self._read(wev_log_path))

        proc, log_path = self._run_kloak(
            self.runtime_dir, self.wayland_display, max_delay=max_delay)
        time.sleep(2)
        self.assertIsNone(proc.poll(),
                          'kloak exited before the motion test:\n%s'
                          % self._read(log_path))

        if not self._establish_pointer_focus(wev_log_path):
            self.fail('wev never got pointer focus (cursor did not reach the '
                      'surface):\nwev:\n%s\nkloak:\n%s'
                      % (self._read(wev_log_path), self._read(log_path)))
        ## Stabilise the baseline past the delayed focus-establishing motions.
        time.sleep((max_delay + 500) / 1000.0)

        def _motion_stamp(line):
            if 'wl_pointer' not in line or 'motion' not in line:
                return None
            t_match = re.search(r'time:\s*(-?\d+)', line)
            if t_match is not None:
                return int(t_match.group(1)) & 0xffffffff
            return None

        ## Alternate the move direction so the cursor oscillates in place and
        ## stays over the surface (no drift off-screen). One integer-position
        ## change per move -> exactly one delayed motion at the client.
        move_idx = [0]

        def inject_move():
            dx = 15 if move_idx[0] % 2 == 0 else -15
            move_idx[0] += 1
            self._uinput_mouse.write(ecodes.EV_REL, ecodes.REL_X, dx)
            self._uinput_mouse.syn()

        num_moves = 15
        stamp_delays, real_delays = self._measure_delays(
            wev_log_path, inject_move, _motion_stamp, num_moves, max_delay)
        self._assert_delays(stamp_delays, real_delays, max_delay, 'motion')

    def _spawn_compositor(self, outputs='1'):
        """Start a PRIVATE labwc instance in its own runtime dir, so a test can
        kill it (disconnect) or give it a different output count without
        disturbing the shared class fixture. Returns (proc, runtime_dir,
        wayland_display); cleanup is registered. Mirrors _start_compositor."""
        rdir = tempfile.mkdtemp(prefix='kloak-e2e-priv-', dir=self._work)
        os.chmod(rdir, 0o700)
        env = dict(os.environ)
        env.update({
            'XDG_RUNTIME_DIR': rdir,
            'WLR_BACKENDS': 'libinput,headless',
            'WLR_RENDERER': 'pixman',
            'WLR_HEADLESS_OUTPUTS': outputs,
            'LIBSEAT_BACKEND': 'builtin',
        })
        log = open(os.path.join(rdir, 'labwc.log'), 'wb')
        self.addCleanup(log.close)
        proc = subprocess.Popen(
            ['unshare', '--net', 'labwc'], env=env, stdout=log,
            stderr=subprocess.STDOUT)
        self.addCleanup(self._kill, proc)
        display = ''
        for _ in range(30):
            if proc.poll() is not None:
                break
            socks = [name for name in os.listdir(rdir)
                     if name.startswith('wayland-') and not name.endswith('.lock')]
            if socks:
                display = sorted(socks)[0]
                break
            time.sleep(1)
        if not display:
            with open(os.path.join(rdir, 'labwc.log'),
                      encoding='utf-8', errors='replace') as handle:
                tail = handle.read()[-2000:]
            ## style-ok: allow-skip: headless wlroots could not start here (no DRM/seat)
            raise unittest.SkipTest(
                'private labwc did not expose a Wayland socket:\n%s' % tail)
        return proc, rdir, display

    def test_7_mid_session_disconnect_exit0(self):
        """kloak must exit 0 PROMPTLY when the compositor disconnects mid-session
        -- the POLLHUP 'Peer disconnected, exiting' path -- not spin or keep the
        input devices grabbed (which would deadlock the seat). Uses a PRIVATE
        compositor so killing it leaves the shared fixture intact."""
        comp, rdir, display = self._spawn_compositor()
        proc, log_path = self._run_kloak(rdir, display)
        time.sleep(4)
        self.assertIsNone(
            proc.poll(),
            'kloak did not stay up against the private compositor:\n%s'
            % self._read(log_path))

        ## Drop the compositor; kloak's poll sees POLLHUP and must exit cleanly.
        comp.terminate()
        try:
            rc = proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            self.fail('kloak did not exit after the compositor disconnected '
                      '(spin / stuck device grab?):\n%s' % self._read(log_path))
        self.assertEqual(
            rc, 0,
            'kloak should exit 0 on compositor disconnect, got %d:\n%s'
            % (rc, self._read(log_path)))

    def test_8_multi_screen_connects(self):
        """kloak must handle a real MULTI-OUTPUT compositor: recalc_global_space
        runs over 2 outputs, not the shared fixture's 1. Either it comes up
        connected (layout accepted) and processes input, or it aborts cleanly on
        a gapped/invalid layout -- but it must never crash with a signal or hang
        degraded-silently."""
        comp, rdir, display = self._spawn_compositor(outputs='2')
        proc, log_path = self._run_kloak(rdir, display)
        time.sleep(4)
        rc = proc.poll()
        log = self._read(log_path)
        if rc is None:
            ## Up: must be the connected path (not degraded), and injecting input
            ## over the 2-output global space must not crash it.
            self.assertNotIn(
                'await escape key combo', log,
                'kloak degraded against a 2-output compositor:\n%s' % log)
            ecodes = self._evdev.ecodes
            self._uinput.write(ecodes.EV_KEY, ecodes.KEY_A, 1)
            self._uinput.write(ecodes.EV_KEY, ecodes.KEY_A, 0)
            self._uinput.syn()
            time.sleep(1)
            self.assertIsNone(
                proc.poll(),
                'kloak crashed processing input with 2 outputs:\n%s'
                % self._read(log_path))
        else:
            ## Exited: acceptable only as a clean abort (rc >= 0), never a crash
            ## signal (negative rc from Popen).
            self.assertGreaterEqual(
                rc, 0,
                'kloak crashed (signal %d) on a 2-output layout:\n%s'
                % (-rc, log))

    def test_6_pointer_scroll_delay_measured(self):
        """Same proof as test_3, for SCROLL: inject real wheel ticks through the
        grabbed mouse and verify each wl_pointer axis event reaches a focused
        client after a RANDOM delay bounded by max_delay, measured in real
        wall-clock time. Scroll rides the same release scheduler as keys/clicks/
        motion, so an immediate flush would be caught here too."""
        max_delay = 200
        ecodes = self._evdev.ecodes
        wev_log_path = self._start_wev()
        if not self._wait_for_focus(wev_log_path, 'wl_keyboard'):
            self.fail('wev never got keyboard focus:\n%s'
                      % self._read(wev_log_path))

        proc, log_path = self._run_kloak(
            self.runtime_dir, self.wayland_display, max_delay=max_delay)
        time.sleep(2)
        self.assertIsNone(proc.poll(),
                          'kloak exited before the scroll test:\n%s'
                          % self._read(log_path))

        ## Axis events are delivered to the focused pointer surface, so the
        ## cursor must be over the wev surface first.
        if not self._establish_pointer_focus(wev_log_path):
            self.fail('wev never got pointer focus (cursor did not reach the '
                      'surface):\nwev:\n%s\nkloak:\n%s'
                      % (self._read(wev_log_path), self._read(log_path)))
        time.sleep((max_delay + 500) / 1000.0)

        ## The continuous wl_pointer.axis event carries `time:`; axis_discrete /
        ## axis_source / frame do not, so a `time:`-bearing axis line is exactly
        ## one released scroll tick.
        def _axis_stamp(line):
            if 'wl_pointer' not in line or 'axis' not in line:
                return None
            t_match = re.search(r'time:\s*(-?\d+)', line)
            if t_match is not None:
                return int(t_match.group(1)) & 0xffffffff
            return None

        ## Alternate wheel direction so the accumulator does not drift; one tick
        ## per injection -> one released axis event.
        scroll_idx = [0]

        def inject_scroll():
            direction = 1 if scroll_idx[0] % 2 == 0 else -1
            scroll_idx[0] += 1
            self._uinput_mouse.write(ecodes.EV_REL, ecodes.REL_WHEEL, direction)
            self._uinput_mouse.syn()

        num_scrolls = 12
        stamp_delays, real_delays = self._measure_delays(
            wev_log_path, inject_scroll, _axis_stamp, num_scrolls, max_delay)
        self._assert_delays(stamp_delays, real_delays, max_delay, 'scroll')


    def test_9_device_hotplug_grabbed(self):
        """A device appearing AFTER kloak started must be grabbed via the inotify
        hotplug path and its input delayed to the client; removing it must not
        crash kloak. Exercises the runtime attach/detach the startup scan can't."""
        from evdev import UInput, ecodes
        max_delay = 150
        wev_log_path = self._start_wev()
        if not self._wait_for_focus(wev_log_path, 'wl_keyboard'):
            self.fail('wev never got keyboard focus:\n%s'
                      % self._read(wev_log_path))
        proc, log_path = self._run_kloak(
            self.runtime_dir, self.wayland_display, max_delay=max_delay)
        time.sleep(2)
        self.assertIsNone(proc.poll(),
                          'kloak exited before the hotplug test:\n%s'
                          % self._read(log_path))

        ## Hot-add a SECOND keyboard while kloak is already running + grabbing.
        hot = UInput({ecodes.EV_KEY: [ecodes.KEY_B]}, name='kloak-e2e-hotplug')
        self.addCleanup(hot.close)
        time.sleep(2)   ## inotify IN_CREATE + grab settle

        ## Inject through the NEW device; if kloak grabbed it the key reaches the
        ## client (delayed). KEY_B (48) -> wl_keyboard keycode 56 (evdev + 8).
        before = len(self._read(wev_log_path))
        for _ in range(3):
            hot.write(ecodes.EV_KEY, ecodes.KEY_B, 1)
            hot.write(ecodes.EV_KEY, ecodes.KEY_B, 0)
            hot.syn()
            time.sleep((max_delay + 120) / 1000.0)
        time.sleep((max_delay + 300) / 1000.0)

        got = [line for line in self._read(wev_log_path)[before:].splitlines()
               if 'wl_keyboard' in line and 'key: 56' in line]
        self.assertTrue(
            got,
            'the hot-plugged device was not grabbed -- its key never reached the '
            'client:\nwev:\n%s\nkloak:\n%s'
            % (self._read(wev_log_path), self._read(log_path)))

        ## Removing the device must not crash kloak.
        hot.close()
        time.sleep(2)
        self.assertIsNone(proc.poll(),
                          'kloak crashed on device removal:\n%s'
                          % self._read(log_path))

    def test_seccomp_filter_runtime(self):
        """kloak must start under its SHIPPED SystemCallFilter without tripping a
        SIGSYS -- the arm64 group-based-filter regression manifests only under the
        real filter, which the direct-spawn tests bypass. Launch it as a TRANSIENT
        SERVICE (systemd-run, not --scope: a scope rejects SystemCallFilter since
        it manages an externally-forked process) with the filter parsed from the
        shipped unit, so systemd applies the exec sandbox exactly as the real unit
        does and the properties never drift. Honest: passes only if the privsep
        uid drop COMPLETES under the filter (a kloakwl-owned process, as in
        test_1) with no SIGSYS; skips only if the environment cannot run the
        transient service; fails on SIGSYS or a privsep drop that never happens."""
        systemd_run = shutil.which('systemd-run')
        if systemd_run is None:
            ## style-ok: allow-skip: systemd-run absent -- cannot apply the shipped filter
            self.skipTest('systemd-run not installed (seccomp-filter lane)')
        unit = os.path.join(_repo(), 'usr', 'lib', 'systemd', 'system',
                            'kloak.service')
        if not os.path.exists(unit):
            ## style-ok: allow-skip: shipped unit absent in this checkout
            self.skipTest('kloak.service not found')

        props = []
        for raw in self._read(unit).splitlines():
            line = raw.strip()
            if line.startswith('#'):
                continue
            for key in ('SystemCallFilter=', 'SystemCallArchitectures=',
                        'RestrictNamespaces=', 'NoNewPrivileges='):
                if line.startswith(key):
                    props.extend(['-p', line])
        self.assertTrue(
            any(p.startswith('SystemCallFilter=') for p in props),
            'no SystemCallFilter parsed from the shipped unit %s' % unit)

        log_path = os.path.join(self._work, 'kloak-seccomp.log')
        log = open(log_path, 'wb')
        self.addCleanup(log.close)
        ## Connect to the SHARED compositor (NOT a nonexistent display): only on
        ## the connected path does the privsep child run the full sandbox + uid
        ## drop, which is where the arm64 group-filter SIGSYS regression bit. The
        ## degraded path bails before the uid drop and would not exercise it.
        ## Baseline the kloakwl children left running by earlier tests, so only a
        ## NEW one -- this run's privsep drop -- counts.
        before = _kloakwl_pids()
        cmd = [systemd_run, '--pipe', '--quiet', '--collect'] + props + [
            '--', 'env', 'XDG_RUNTIME_DIR=%s' % self.runtime_dir,
            'WAYLAND_DISPLAY=%s' % self.wayland_display, self.kloak_bin, '-d', '0']
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
        self.addCleanup(self._kill, proc)

        ## A NEW kloakwl-owned process appears ONLY if the whole fork + sandbox +
        ## setuid path ran under the filter without a blocked syscall -- the
        ## positive proof the filter covers kloak's real privsep path.
        dropped = False
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if _kloakwl_pids() - before:
                dropped = True
                break
            time.sleep(0.3)
        out = self._read(log_path)
        self.assertNotIn(
            'Bad system call', out,
            'kloak hit SIGSYS under its shipped SystemCallFilter:\n%s' % out)
        if not dropped:
            ## No new privsep child dropped. Skip ONLY if systemd-run itself could
            ## not run the transient service (e.g. no system bus) -- a skip that
            ## swallowed a real filter break would hide the very regression this
            ## guards. A child SIGSYS kills the forked child silently (the parent
            ## survives, so proc's rc never shows -31), so "kloak ran but never
            ## dropped" is a FAILURE, not a skip.
            launch_failed = any(
                marker in out for marker in (
                    'Failed to connect to bus',
                    'Failed to start transient',
                    'Failed to allocate',
                    'Interactive authentication required'))
            if launch_failed:
                ## style-ok: allow-skip: cannot run a systemd transient service in this environment
                self.skipTest('systemd-run could not run the service under the '
                              'filter:\n%s' % out[-800:])
            self.fail(
                'kloak did not complete the privsep uid drop under its shipped '
                'SystemCallFilter -- a needed syscall is blocked (SIGSYS in the '
                'sandbox child; the arm64 group-filter regression):\n%s' % out)


if __name__ == '__main__':
    unittest.main()
