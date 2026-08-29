#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Tests for secure-terminal's pure, Qt-free support modules: the single-instance
## IPC framing (ipc), session persistence (session) and drop-in settings
## (settings). These exercise the happy paths AND the defensive error branches
## (unreachable/unreadable paths, short or malformed frames) that the GUI relies on
## to never crash. No Qt is imported, so this runs headless with only python3.

import os
import fcntl
import sys
import json
import glob
import socket
import struct
import tempfile
import threading

try:
    from secure_terminal import ipc, session, settings
except Exception as exc:  # fail closed: a required dependency must not silently skip
    sys.stderr.write('secure-terminal-tests: FAIL missing dependency: '
                     '%s\n' % exc)
    sys.exit(1)

_failures = 0


def ok(cond, msg):
    global _failures
    if cond:
        print('ok   %s' % msg)
    else:
        _failures += 1
        print('FAIL: %s' % msg)


def eq(got, want, msg):
    ok(got == want, '%s (got %r, want %r)' % (msg, got, want))


# ============================ ipc =============================================

# --- Framer: a partial frame yields None until the payload is complete ---------
_fr = ipc.Framer()
ok(_fr.feed(b'\x00') is None, 'Framer: fewer than 4 header bytes -> None')
_fr_p = ipc.Framer()
ok(_fr_p.feed(struct.pack('<I', 100) + b'partial') is None,
   'Framer: header present but payload incomplete -> None')

_fr2 = ipc.Framer()
_payload = b'{"x":1}'
ok(_fr2.feed(ipc.frame(_payload)) == _payload,
   'Framer: a complete frame returns the exact payload')

_fr3 = ipc.Framer()
_raised = False
try:
    _fr3.feed(struct.pack('<I', ipc._MAX_REQUEST + 1) + b'..')
except ValueError:
    _raised = True
ok(_raised, 'Framer: an over-long frame raises ValueError')


# --- ensure_socket_dir chmods the dir owner-only; a chmod failure is swallowed -
_run_dir = tempfile.mkdtemp()
os.environ['XDG_RUNTIME_DIR'] = _run_dir
_made = ipc.ensure_socket_dir()
ok(os.path.isdir(_made) and (os.stat(_made).st_mode & 0o777) == 0o700,
   'ensure_socket_dir: creates an owner-only (0700) directory')

_orig_chmod = os.chmod
def _boom_chmod(*_a, **_k):
    raise OSError('chmod denied')
os.chmod = _boom_chmod
try:
    ipc.ensure_socket_dir()             # pre-existing dir + failing chmod
    ok(True, 'ensure_socket_dir: a failed chmod is swallowed, not raised')
finally:
    os.chmod = _orig_chmod


# --- send_request talks to a real same-UID server over the framed protocol -----
def _serve_once(path, responder):
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)

    def run():
        try:
            conn, _ = srv.accept()
            try:
                responder(conn)
            finally:
                conn.close()
        except OSError:
            pass                # the client may have hung up; the thread just ends
        finally:
            srv.close()

    thread = threading.Thread(target=run)
    thread.daemon = True
    thread.start()
    return thread


def _read_frame(conn):
    head = b''
    while len(head) < 4:
        chunk = conn.recv(4 - len(head))
        if not chunk:
            return b''
        head += chunk
    (length,) = struct.unpack('<I', head)
    body = b''
    while len(body) < length:
        chunk = conn.recv(length - len(body))
        if not chunk:
            break
        body += chunk
    return body


_sock_path = ipc.socket_path('default')

# happy path: the server echoes a valid framed verdict
def _valid(conn):
    _read_frame(conn)
    conn.sendall(ipc.frame(json.dumps({'verdict': 'allow'}).encode('utf-8')))
_t = _serve_once(_sock_path, _valid)
_reply = ipc.send_request('default', {'op': 'ping'})
_t.join(timeout=2)
os.unlink(_sock_path)
eq(_reply, {'verdict': 'allow'}, 'send_request: returns the parsed reply dict')

# no server reachable -> None
eq(ipc.send_request('default', {'op': 'ping'}), None,
   'send_request: no server listening -> None')

# server accepts then closes with nothing -> empty read is a FAILED exchange -> None
# (a bound primary whose Qt loop is not yet serving does exactly this)
def _empty(conn):
    _read_frame(conn)
_t = _serve_once(_sock_path, _empty)
_reply = ipc.send_request('default', {'op': 'ping'})
_t.join(timeout=2)
os.unlink(_sock_path)
eq(_reply, None, 'send_request: a server that sends nothing -> None (empty reply)')

# server replies with a zero-length frame -> treated as empty -> None
def _zerolen(conn):
    _read_frame(conn)
    conn.sendall(struct.pack('<I', 0))
_t = _serve_once(_sock_path, _zerolen)
_reply = ipc.send_request('default', {'op': 'ping'})
_t.join(timeout=2)
os.unlink(_sock_path)
eq(_reply, None, 'send_request: a zero-length reply frame -> None')

# server promises a long payload but sends fewer bytes then closes -> None
def _short(conn):
    _read_frame(conn)
    conn.sendall(struct.pack('<I', 100) + b'only-ten!!')
_t = _serve_once(_sock_path, _short)
_reply = ipc.send_request('default', {'op': 'ping'})
_t.join(timeout=2)
os.unlink(_sock_path)
eq(_reply, None,
   'send_request: a truncated payload -> None (incomplete frame dropped)')

# server replies with a valid frame carrying non-JSON -> ValueError -> None
def _badjson(conn):
    _read_frame(conn)
    conn.sendall(ipc.frame(b'not json at all'))
_t = _serve_once(_sock_path, _badjson)
_reply = ipc.send_request('default', {'op': 'ping'})
_t.join(timeout=2)
os.unlink(_sock_path)
eq(_reply, None, 'send_request: a non-JSON reply -> None (exchange failed)')


# ============================ session ========================================

_state_root = tempfile.mkdtemp()
os.environ['XDG_STATE_HOME'] = _state_root

# a round-trip: save then load restores the tabs and their scrollback
session.save([{'name': 'one', 'text': 'hello\nworld'},
              {'name': 'two', 'text': 'second'}])
_loaded = session.load()
eq([t.get('name') for t in _loaded], ['one', 'two'],
   'session: save/load restores the tab order and names')
eq(_loaded[0].get('text'), 'hello\nworld',
   'session: a tab scrollback is restored from its own log file')

# a tab's working directory round-trips through the index (so restore can cd back)
session.save([{'name': 'w', 'cwd': '/known/work/dir', 'text': ''}])
eq(session.load()[0].get('cwd'), '/known/work/dir',
   'session: a tab cwd is saved and restored in the index')
session.save([{'name': 'one', 'text': 'hello\nworld'},
              {'name': 'two', 'text': 'second'}])   # restore the two-tab fixture

# shrinking the session drops the stale log of the removed tab
session.save([{'name': 'only', 'text': 'x'}])
ok(not os.path.exists(os.path.join(session._state_dir(), 'tab-1.log')),
   'session: a shrunk session removes the now-stale tab log')

# cap_text keeps only the most recent lines
eq(session.cap_text('a\nb\nc\nd', 2), 'c\nd', 'session: cap_text keeps the tail')

# a non-dict index entry is skipped; a dict entry whose log is missing loads empty
session._write_atomic(session.session_path(),
                      json.dumps({'tabs': [123, {'name': 'nolog'}]}))
_stale_log = os.path.join(session._state_dir(), 'tab-1.log')
if os.path.exists(_stale_log):
    os.remove(_stale_log)               # position 1 (nolog) must have no log
_loaded = session.load()
eq([t.get('name') for t in _loaded], ['nolog'],
   'session: a non-dict index entry is skipped')
eq(_loaded[0].get('text'), '',
   'session: a dict entry with no log file restores an empty scrollback')

# a corrupt session.json -> empty session, never raises
session._write_atomic(session.session_path(), 'this is not json')
eq(session.load(), [], 'session: a corrupt index loads as an empty session')

# a well-formed object whose 'tabs' is not a list -> empty session
session._write_atomic(session.session_path(), json.dumps({'tabs': 'nope'}))
eq(session.load(), [], "session: a non-list 'tabs' value loads as empty")

# window geometry blob round-trips; anything not a non-empty string -> None (#77)
session.save([{'name': 'a', 'text': ''}], 'QkxPQg==')
eq(session.load_window(), 'QkxPQg==', 'session: the window geometry blob round-trips')
session.save([{'name': 'a', 'text': ''}])                 # no window arg
eq(session.load_window(), None, 'session: no saved window -> None')
session.save([{'name': 'a', 'text': ''}], '')             # empty string ignored
eq(session.load_window(), None, 'session: an empty window blob is not saved')
session.save([{'name': 'a', 'text': ''}], 123)            # non-str ignored
eq(session.load_window(), None, 'session: a non-string window value is not saved')
session._write_atomic(session.session_path(), 'not json')
eq(session.load_window(), None, 'session: load_window on corrupt json -> None')
session._write_atomic(session.session_path(), json.dumps(['a', 'list']))
eq(session.load_window(), None, 'session: load_window on a non-dict payload -> None')
session._write_atomic(session.session_path(), json.dumps({'tabs': [], 'window': 9}))
eq(session.load_window(), None, 'session: a non-string saved window loads as None')

# active-tab index round-trips; out-of-range / non-int / corrupt -> None (#88)
session.save([{'name': 'a', 'text': ''}, {'name': 'b', 'text': ''}], active=1)
eq(session.load_active(), 1, 'session: the active-tab index round-trips')
session.save([{'name': 'a', 'text': ''}], active=5)         # out of range -> dropped
eq(session.load_active(), None, 'session: an out-of-range active index is not saved')
session.save([{'name': 'a', 'text': ''}])                   # no active arg
eq(session.load_active(), None, 'session: no saved active -> None')
session._write_atomic(session.session_path(), 'not json')
eq(session.load_active(), None, 'session: load_active on corrupt json -> None')
session._write_atomic(session.session_path(), json.dumps(['x']))
eq(session.load_active(), None, 'session: load_active on a non-dict payload -> None')
session._write_atomic(session.session_path(), json.dumps({'tabs': [], 'active': -1}))
eq(session.load_active(), None, 'session: a negative saved active loads as None')

# clear removes the index and logs; a second clear on nothing is a no-op
session.clear()
ok(not os.path.exists(session.session_path()),
   'session: clear removes the saved index')
session.clear()
ok(True, 'session: clear on an already-empty state does not raise')

# _log_indices on a missing state dir -> [] (listdir OSError swallowed)
os.environ['XDG_STATE_HOME'] = os.path.join(_state_root, 'does', 'not', 'exist')
eq(session._log_indices(), [],
   'session: an unreadable state dir yields no log indices')

# save when the state dir cannot be created (its parent is a file) -> swallowed
_blocker = os.path.join(_state_root, 'blocker')
with open(_blocker, 'w', encoding='utf-8') as _h:
    _h.write('x')
os.environ['XDG_STATE_HOME'] = os.path.join(_blocker, 'sub')
session.save([{'name': 'a', 'text': 'a'}])
ok(True, 'session: save is best-effort when its directory cannot be created')
os.environ['XDG_STATE_HOME'] = _state_root


# ============================ settings =======================================

_cfg_root = tempfile.mkdtemp()
os.environ['XDG_CONFIG_HOME'] = _cfg_root

# the search path and the write-target aliases
ok(settings.config_dirs()[-1].endswith('secure-terminal.d'),
   'settings: config_dirs ends with the user drop-in directory')
eq(settings.config_path(), settings.user_config_file(),
   'settings: config_path is an alias for user_config_file')

# save then load round-trips a user value; a locked key is NOT written out
settings.save({'font_size': '12', 'theme': 'dark', 'remote_control': 'on'},
              locked=('remote_control',))
_cfg = settings.load()
eq(_cfg.get('font_size'), '12', 'settings: a saved user value is loaded back')
ok('remote_control' not in _cfg,
   'settings: a locked key is not persisted to the user file')
ok(not _cfg.is_locked('font_size'),
   'settings: an unlocked key reports is_locked False')

# ---- set_user_key / update_user honor an admin lock -------------------------
# The lock path is exercised by monkeypatching _system_dirs in-process (the
# suite-wide convention, cf. test_widget.py); production keeps these dirs fixed to
# the root-writable privileged folders, so a lock can be neither set nor bypassed
# without root. set_user_key/update_user are the Finding-1/2 writers; test_widget
# already covers load()/save-locked/violations/UI.
_lk_sys = tempfile.mkdtemp(prefix='st-sys-')
_lk_usr = tempfile.mkdtemp(prefix='st-usr-')
_orig_sysd, _orig_usrd = settings._system_dirs, settings._user_config_dir
settings._system_dirs = lambda: [_lk_sys]
settings._user_config_dir = lambda: _lk_usr
try:
    with open(os.path.join(_lk_sys, '10_admin.conf'), 'w', encoding='utf-8') as _h:
        _h.write('lock=clip_warn_any\nclip_warn_any=true\n')

    def _user_file_keys():
        _d = {}
        settings._parse_into(settings.user_config_file(), _d)
        return _d

    # set_user_key never writes the admin-locked key to the (dead) user file
    settings.set_user_key('clip_warn_any', 'false')
    ok('clip_warn_any' not in _user_file_keys(),
       'settings: set_user_key drops an admin-locked key')
    settings.set_user_key('theme', 'mono')
    eq(_user_file_keys().get('theme'), 'mono',
       'settings: set_user_key persists a non-locked key')
    eq(settings.load().get('clip_warn_any'), 'true',
       'settings: the admin lock value still wins after set_user_key')

    # update_user drops the locked key but PRESERVES a key an earlier writer set
    # here that is `theme`, from the set_user_key above; the tray-set clip_warn_any
    # is locked so it drops, so the clip_warn_any-specific no-clobber contract is
    # the integration test in test_mainwin. This covers the generic merge property.
    settings.update_user({'clip_warn_any': 'false', 'font_size': '20'})
    _uf = _user_file_keys()
    ok('clip_warn_any' not in _uf, 'settings: update_user drops an admin-locked key')
    eq(_uf.get('font_size'), '20', 'settings: update_user persists a non-locked key')
    eq(_uf.get('theme'), 'mono',
       'settings: update_user preserves a key another writer set (no clobber)')
finally:
    settings._system_dirs, settings._user_config_dir = _orig_sysd, _orig_usrd

# ---- a non-UTF-8 user file is defensive: never raises AND never clobbered ---
_bad_usr = tempfile.mkdtemp(prefix='st-badutf-')
_orig_bud = settings._user_config_dir
settings._user_config_dir = lambda: _bad_usr
try:
    _bad_bytes = b'theme=dark\nzoom=150\nclip_warn_any=\xff\n'
    with open(os.path.join(_bad_usr, '50_user.conf'), 'wb') as _bh:
        _bh.write(_bad_bytes)
    settings.load()                       # a non-UTF-8 drop-in must not raise
    settings.set_user_key('theme', 'light')   # unreadable base -> SKIP, not clobber
    settings.update_user({'zoom': '2'})       # unreadable base -> SKIP, not clobber
    with open(os.path.join(_bad_usr, '50_user.conf'), 'rb') as _rb:
        ok(_rb.read() == _bad_bytes,
           'settings: a non-UTF-8 user file is left untouched, not clobbered (no data loss)')
finally:
    settings._user_config_dir = _orig_bud

# ---- the user-file write lock serializes the two writers (flock) ------------
_lockd = tempfile.mkdtemp(prefix='st-lock-')
_orig_lud = settings._user_config_dir
settings._user_config_dir = lambda: _lockd
try:
    _held = settings._user_write_lock()
    ok(_held is not None, 'settings: _user_write_lock acquires an exclusive lock')
    _probe = os.open(settings.user_config_file() + '.lock', os.O_CREAT | os.O_RDWR, 0o600)
    _blocked = False
    try:
        fcntl.flock(_probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        _blocked = True
    ok(_blocked, 'settings: a held write lock blocks a second writer')
    os.close(_held)                                       # release
    fcntl.flock(_probe, fcntl.LOCK_EX | fcntl.LOCK_NB)    # succeeds now, no raise
    os.close(_probe)
    ok(True, 'settings: the write lock is re-acquirable once released')
finally:
    settings._user_config_dir = _orig_lud

# ---- the write lock is best-effort: None when its dir cannot be created -----
_nolockp = os.path.join(tempfile.mkdtemp(prefix='st-nolock-'), 'afile')
with open(_nolockp, 'w', encoding='utf-8') as _nf:
    _nf.write('x')
_orig_nud = settings._user_config_dir
settings._user_config_dir = lambda: os.path.join(_nolockp, 'sub')   # parent is a file
try:
    ok(settings._user_write_lock() is None,
       'settings: _user_write_lock yields None when the lock dir is unavailable')
    settings.set_user_key('theme', 'x')   # tolerates a missing lock (handle-None path)
    settings.update_user({'zoom': '3'})
    ok(True, 'settings: set_user_key/update_user tolerate a missing write lock')
finally:
    settings._user_config_dir = _orig_nud

# ---- a failed flock closes the fd and yields None (no descriptor leak) ------
_flockd = tempfile.mkdtemp(prefix='st-flockfail-')
_orig_flud = settings._user_config_dir
_orig_flock = settings.fcntl.flock
settings._user_config_dir = lambda: _flockd
def _boom_flock(*_a):
    raise OSError('flock unsupported')
settings.fcntl.flock = _boom_flock
try:
    ok(settings._user_write_lock() is None,
       'settings: _user_write_lock returns None when flock fails')
    _fd0 = len(os.listdir('/proc/self/fd'))
    for _ in range(20):
        settings._user_write_lock()       # each opens the sidecar then flock fails
    _fd1 = len(os.listdir('/proc/self/fd'))
    ok(_fd1 <= _fd0 + 2, 'settings: a failed flock leaks no fd (%d -> %d)' % (_fd0, _fd1))
    settings.set_user_key('theme', 'x')   # still writes, best-effort (unserialized)
    eq(settings.load().get('theme'), 'x',
       'settings: a write still proceeds when the lock is unavailable')
finally:
    settings.fcntl.flock = _orig_flock
    settings._user_config_dir = _orig_flud

# ---- set_user_key AND update_user actually ACQUIRE the write lock -----------
_acqd = tempfile.mkdtemp(prefix='st-acq-')
_orig_aud = settings._user_config_dir
_orig_uwl = settings._user_write_lock
_lock_calls = []
def _spy_lock():
    _lock_calls.append(1)
    return _orig_uwl()
settings._user_config_dir = lambda: _acqd
settings._user_write_lock = _spy_lock
try:
    settings.set_user_key('theme', 'a')
    settings.update_user({'zoom': '5'})
    ok(len(_lock_calls) >= 2,
       'settings: set_user_key and update_user each acquire the write lock')
finally:
    settings._user_write_lock = _orig_uwl
    settings._user_config_dir = _orig_aud

# ---- update_user honors an EXPLICIT locked= (the window's startup snapshot) --
# so a key locked at launch is dropped even when load() no longer locks it: an
# admin who removes a lock while the GUI is open cannot have the stale value pinned.
_es = tempfile.mkdtemp(prefix='st-esys-')
_eu = tempfile.mkdtemp(prefix='st-euser-')
_o_es, _o_eu = settings._system_dirs, settings._user_config_dir
settings._system_dirs = lambda: [_es]           # no active admin lock here
settings._user_config_dir = lambda: _eu
try:
    settings.update_user({'theme': 'dark', 'osc_clipboard_read_always': 'true'},
                         locked=frozenset({'osc_clipboard_read_always'}))
    _w = {}
    settings._parse_into(settings.user_config_file(), _w)
    ok('osc_clipboard_read_always' not in _w and _w.get('theme') == 'dark',
       'settings: update_user drops a key named in explicit locked=, keeps the rest')
    settings.update_user({'shade': 'x'}, locked=None)   # None must not raise
    _wn = {}
    settings._parse_into(settings.user_config_file(), _wn)
    ok(_wn.get('shade') == 'x',
       'settings: update_user(locked=None) does not raise and writes (never raises)')
    # UNION, not "choose one": a key locked by the CURRENT system config is dropped
    # even when a NON-EMPTY, DIFFERENT locked= is passed. A broken impl that uses one
    # set OR the other (never both) writes the system-locked key -- caught only here.
    with open(os.path.join(_es, '10_admin.conf'), 'w', encoding='utf-8') as _ah:
        _ah.write('lock=osc_clipboard_read_always\n')
    settings.update_user({'osc_clipboard_read_always': 'true'},
                         locked=frozenset({'theme'}))     # different key in the passed set
    _wu = {}
    settings._parse_into(settings.user_config_file(), _wu)
    ok('osc_clipboard_read_always' not in _wu,
       'settings: update_user unions current+startup locks (system lock honored with a non-empty locked=)')
finally:
    settings._system_dirs, settings._user_config_dir = _o_es, _o_eu

# _parse_into on an unreadable path is swallowed (returns without touching out)
_out = {}
settings._parse_into(os.path.join(_cfg_root, 'no', 'such.conf'), _out)
eq(_out, {}, 'settings: parsing a missing drop-in is a no-op')

# a drop-in that decodes PART-WAY then fails does not partially apply (atomic)
_atomicf = os.path.join(_cfg_root, 'atomic.conf')
with open(_atomicf, 'wb') as _af:
    _af.write(b'a=1\n' * 4000)         # >8 KiB of valid lines (spans read buffers)
    _af.write(b'b=\xff\n')             # a bad byte only AFTER the first buffer
_aout = {'keep': 'yes'}
settings._parse_into(_atomicf, _aout)
eq(_aout, {'keep': 'yes'},
   'settings: a drop-in failing to decode partway does not partially apply')

# _load_dir swallows a glob error (defensive; glob almost never raises)
_orig_glob = glob.glob
def _boom_glob(*_a, **_k):
    raise OSError('glob failed')
glob.glob = _boom_glob
try:
    eq(settings._load_dir(_cfg_root), {},
       'settings: a glob failure yields an empty layer, not a crash')
finally:
    glob.glob = _orig_glob

# save when the config dir cannot be created (parent is a file) -> swallowed
_cfg_blocker = os.path.join(_cfg_root, 'file-not-dir')
with open(_cfg_blocker, 'w', encoding='utf-8') as _h:
    _h.write('x')
os.environ['XDG_CONFIG_HOME'] = os.path.join(_cfg_blocker, 'sub')
settings.save({'k': 'v'})
ok(True, 'settings: save is best-effort when its directory cannot be created')
os.environ['XDG_CONFIG_HOME'] = _cfg_root


# ============================ ipc.Framer ======================================

# a reused Framer advances to the next frame (buf trimmed, not re-returning frame 1)
_p37fr = ipc.Framer()
ok(_p37fr.feed(struct.pack('<I', 3) + b'abc') == b'abc', 'Framer: the first frame is returned')
ok(_p37fr.feed(struct.pack('<I', 2) + b'xy') == b'xy',
   'Framer: a reused Framer advances to the next frame (buf trimmed, not re-returning frame 1)')


print('secure-terminal-tests(modules): all passed' if not _failures else
      'secure-terminal-tests(modules): %d failed' % _failures)
sys.exit(1 if _failures else 0)
