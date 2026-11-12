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
  * degraded (test_2): pointed at a nonexistent Wayland display, kloak must
    honor degraded mode -- stay up awaiting the escape combo -- and NOT spin the
    parent at 100% CPU on the dead child pipe (Whonix/kloak#35 + the coupled
    #34). The daemon-level complement to the kloakwl/kloak harness regressions.

DESTRUCTIVE + root-only: builds in the source tree, creates the kloakwl system
user if absent, drives uinput, and runs a compositor. Authorized skip (euid !=
0, no /dev/uinput, or labwc/python3-evdev/the kloak source absent), so a plain
unit-CI container reports the lane SKIP, never a false pass or a hard failure.
"""

import os
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


def _proc_cpu_ticks(pid):
    ## utime (field 14) + stime (field 15) from /proc/<pid>/stat, in clock
    ## ticks. The comm field can contain spaces/parens, so split after the
    ## trailing ')'.
    with open('/proc/%d/stat' % pid, encoding='utf-8') as handle:
        fields = handle.read().rpartition(')')[2].split()
    ## after the ')' the first field is state, so utime/stime are indices 11/12
    return int(fields[11]) + int(fields[12])


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
        src = os.path.join(_repo(), 'src', 'kloak.c')
        if not os.path.exists(src):
            ## style-ok: allow-skip: kloak source absent (not a --component run)
            raise unittest.SkipTest('kloak.c not found -- set KLOAK_REPO')
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
        cls._compositor = subprocess.Popen(
            ['unshare', '--net', 'labwc'], env=env,
            stdout=log, stderr=subprocess.STDOUT)
        cls.addClassCleanup(cls._stop_compositor)

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

    def _run_kloak(self, runtime_dir, wayland_display):
        """Start kloak with its own log; return (Popen, log_path)."""
        env = dict(os.environ)
        env['XDG_RUNTIME_DIR'] = runtime_dir
        env['WAYLAND_DISPLAY'] = wayland_display
        log_path = os.path.join(self._work, 'kloak-%s.log' % wayland_display)
        log = open(log_path, 'wb')
        proc = subprocess.Popen(
            [self.kloak_bin, '-d', '0'], env=env,
            stdout=log, stderr=subprocess.STDOUT)
        self.addCleanup(log.close)
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

    def test_2_degraded_mode(self):
        ## A private empty runtime dir so <dir>/<display> names no socket and the
        ## Wayland connect fails deterministically.
        runtime_dir = os.path.join(self._work, 'degraded-xdg')
        os.makedirs(runtime_dir, exist_ok=True)
        os.chmod(runtime_dir, 0o700)
        proc, log_path = self._run_kloak(runtime_dir, 'kloak-nonexistent-wl')
        time.sleep(2)
        self.assertIsNone(proc.poll(),
                          'kloak exited instead of entering degraded mode '
                          '(the old #35 abort):\n%s' % self._read(log_path))
        before = _proc_cpu_ticks(proc.pid)
        time.sleep(3)
        after = _proc_cpu_ticks(proc.pid)
        self.assertIsNone(proc.poll(), 'kloak exited during the degraded idle')
        ## A dead-pipe busy-loop (the coupled #34) burns ~100% CPU (~300 ticks
        ## over 3s at 100 Hz); a correctly blocked poll burns almost none.
        self.assertLess(after - before, 50,
                        'kloak is busy-looping in degraded mode (#34): %d CPU '
                        'ticks over 3s' % (after - before))
        self.assertIn('await escape key combo', self._read(log_path),
                      'kloak did not log the degraded-mode message')


if __name__ == '__main__':
    unittest.main()
