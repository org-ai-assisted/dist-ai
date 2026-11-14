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
through the grabbed device and measuring, at a focused wev client, that the released
event arrives after a RANDOM delay bounded by -d max_delay (the released event's
`time` is kloak's scheduled release, CLOCK_MONOTONIC ms; delay = that minus the
injection time), asserting both the bound and that the delays VARY:

  * keyboard keys (test_3), mouse button clicks (test_4), and mouse motion (test_5)
    -- the three input classes kloak delays, all on the one release scheduler.

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


class KloakDaemonE2E(unittest.TestCase):
    _created_user = False
    _compositor = None
    _uinput = None
    _work = None
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

        ## Inject N key presses spaced >= max_delay apart, so the per-event
        ## prev_release clamp does not saturate the delay to max_delay -- we want
        ## to observe the full random spread.
        num_keys = 15
        inject_ms = []
        for _ in range(num_keys):
            stamp = int(time.clock_gettime(time.CLOCK_MONOTONIC) * 1000)
            self._uinput.write(ecodes.EV_KEY, key_a, 1)
            self._uinput.write(ecodes.EV_KEY, key_a, 0)
            self._uinput.syn()
            inject_ms.append(stamp & 0xffffffff)
            time.sleep((max_delay + 60) / 1000.0)
        time.sleep((max_delay + 300) / 1000.0)

        ## Collect the client-observed press events (state 1) for key_a.
        presses = []
        for line in self._read(wev_log_path).splitlines():
            if 'wl_keyboard' not in line:
                continue
            ## wev prints `time` with %d on a uint32_t, so a value >= 0x80000000
            ## (~24.9d monotonic uptime) can print negative; accept an optional minus
            ## and mask to 32 bits (matches the inject_ms masking) so the press is not
            ## dropped, failing the count assertion.
            match = re.search(r'time: (-?\d+); key: (\d+); state: (\d+)', line)
            if (match is not None and int(match.group(2)) == wl_keycode
                    and int(match.group(3)) == 1):
                presses.append(int(match.group(1)) & 0xffffffff)

        self.assertEqual(
            len(presses), num_keys,
            'expected %d key presses at the client, got %d:\nwev:\n%s\nkloak:\n%s'
            % (num_keys, len(presses), self._read(wev_log_path),
               self._read(log_path)))

        ## Applied delay = released time - injection time (uint32 ms), bounded by
        ## max_delay plus a small processing-latency tolerance; and it must VARY.
        tol = 80
        delays = []
        for inj, rel in zip(inject_ms, presses):
            delay = (rel - inj) & 0xffffffff
            self.assertLessEqual(
                delay, max_delay + tol,
                'released delay %d ms exceeds max_delay %d (+%d tol); delays=%r'
                % (delay, max_delay, tol, delays))
            delays.append(delay)
        self.assertGreater(
            max(delays) - min(delays), max_delay // 4,
            'released delays show no spread (jitter not randomised): %r' % delays)

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
        ## only the measured clicks appear past this offset.
        time.sleep((max_delay + 500) / 1000.0)
        offset = len(self._read(wev_log_path))

        ## Inject clicks spaced >= max_delay apart so the prev_release clamp does
        ## not saturate the delay -- we want the full random spread.
        num_clicks = 12
        inject_ms = []
        for _ in range(num_clicks):
            stamp = int(time.clock_gettime(time.CLOCK_MONOTONIC) * 1000)
            ## Press and release in SEPARATE syn frames (a zero-duration click in
            ## one frame can be dropped). Measure the press.
            self._uinput_mouse.write(ecodes.EV_KEY, ecodes.BTN_LEFT, 1)
            self._uinput_mouse.syn()
            time.sleep(0.02)
            self._uinput_mouse.write(ecodes.EV_KEY, ecodes.BTN_LEFT, 0)
            self._uinput_mouse.syn()
            inject_ms.append(stamp & 0xffffffff)
            time.sleep((max_delay + 60) / 1000.0)
        time.sleep((max_delay + 300) / 1000.0)

        ## Client-observed button PRESS events (state 1), parsed from the new tail.
        presses = []
        for line in self._read(wev_log_path)[offset:].splitlines():
            if 'wl_pointer' not in line or 'button' not in line:
                continue
            t_match = re.search(r'time:\s*(-?\d+)', line)
            s_match = re.search(r'state:\s*(\d+)', line)
            if (t_match is not None and s_match is not None
                    and int(s_match.group(1)) == 1):
                presses.append(int(t_match.group(1)) & 0xffffffff)

        self.assertEqual(
            len(presses), num_clicks,
            'expected %d button presses at the client, got %d:\nwev:\n%s\n'
            'kloak:\n%s' % (num_clicks, len(presses),
                            self._read(wev_log_path), self._read(log_path)))

        tol = 80
        delays = []
        for inj, rel in zip(inject_ms, presses):
            delay = (rel - inj) & 0xffffffff
            self.assertLessEqual(
                delay, max_delay + tol,
                'released click delay %d ms exceeds max_delay %d (+%d tol); '
                'delays=%r' % (delay, max_delay, tol, delays))
            delays.append(delay)
        self.assertGreater(
            max(delays) - min(delays), max_delay // 4,
            'click delays show no spread (jitter not randomised): %r' % delays)

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
        time.sleep((max_delay + 500) / 1000.0)
        offset = len(self._read(wev_log_path))

        ## Alternate the move direction so the cursor oscillates in place and
        ## stays over the surface (no drift off-screen), each move spaced
        ## >= max_delay apart for the full random spread.
        num_moves = 15
        inject_ms = []
        for i in range(num_moves):
            dx = 15 if i % 2 == 0 else -15
            stamp = int(time.clock_gettime(time.CLOCK_MONOTONIC) * 1000)
            self._uinput_mouse.write(ecodes.EV_REL, ecodes.REL_X, dx)
            self._uinput_mouse.syn()
            inject_ms.append(stamp & 0xffffffff)
            time.sleep((max_delay + 60) / 1000.0)
        time.sleep((max_delay + 300) / 1000.0)

        ## Client-observed motion events, parsed from the new tail.
        motions = []
        for line in self._read(wev_log_path)[offset:].splitlines():
            if 'wl_pointer' not in line or 'motion' not in line:
                continue
            t_match = re.search(r'time:\s*(-?\d+)', line)
            if t_match is not None:
                motions.append(int(t_match.group(1)) & 0xffffffff)

        self.assertEqual(
            len(motions), num_moves,
            'expected %d motion events at the client, got %d:\nwev:\n%s\n'
            'kloak:\n%s' % (num_moves, len(motions),
                            self._read(wev_log_path), self._read(log_path)))

        tol = 80
        delays = []
        for inj, rel in zip(inject_ms, motions):
            delay = (rel - inj) & 0xffffffff
            self.assertLessEqual(
                delay, max_delay + tol,
                'released motion delay %d ms exceeds max_delay %d (+%d tol); '
                'delays=%r' % (delay, max_delay, tol, delays))
            delays.append(delay)
        self.assertGreater(
            max(delays) - min(delays), max_delay // 4,
            'motion delays show no spread (jitter not randomised): %r' % delays)


if __name__ == '__main__':
    unittest.main()
