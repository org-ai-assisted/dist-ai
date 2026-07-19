#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Tests for secure-terminal's pure, Qt-free support modules: the single-instance
## IPC framing (ipc), session persistence (session), drop-in settings (settings)
## and the command-hook protocol (hook). These exercise the happy paths AND the
## defensive error branches (unreachable/unreadable paths, short or malformed
## frames, a hostile hook) that the GUI relies on to never crash. No Qt is
## imported, so this runs headless with only python3.

import os
import sys
import json
import glob
import socket
import struct
import tempfile
import threading

try:
    from secure_terminal import ipc, session, settings, hook
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
            pass
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

# server accepts then closes with nothing -> empty reply parsed as {}
def _empty(conn):
    _read_frame(conn)
_t = _serve_once(_sock_path, _empty)
_reply = ipc.send_request('default', {'op': 'ping'})
_t.join(timeout=2)
os.unlink(_sock_path)
eq(_reply, {}, 'send_request: a server that sends nothing -> {} (empty reply)')

# server replies with a zero-length frame -> treated as empty -> {}
def _zerolen(conn):
    _read_frame(conn)
    conn.sendall(struct.pack('<I', 0))
_t = _serve_once(_sock_path, _zerolen)
_reply = ipc.send_request('default', {'op': 'ping'})
_t.join(timeout=2)
os.unlink(_sock_path)
eq(_reply, {}, 'send_request: a zero-length reply frame -> {}')

# server promises a long payload but sends fewer bytes then closes -> {}
def _short(conn):
    _read_frame(conn)
    conn.sendall(struct.pack('<I', 100) + b'only-ten!!')
_t = _serve_once(_sock_path, _short)
_reply = ipc.send_request('default', {'op': 'ping'})
_t.join(timeout=2)
os.unlink(_sock_path)
eq(_reply, {}, 'send_request: a truncated payload -> {} (incomplete frame dropped)')

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

# _parse_into on an unreadable path is swallowed (returns without touching out)
_out = {}
settings._parse_into(os.path.join(_cfg_root, 'no', 'such.conf'), _out)
eq(_out, {}, 'settings: parsing a missing drop-in is a no-op')

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


# ============================ hook ===========================================

# a handler returning a verdict outside the allowed set -> contained error reply
_bad = hook.evaluate(['sh', '-c', 'echo \'{"verdict":"totally-bogus"}\''],
                     'ls', on_error='allow')
eq(_bad.get('verdict'), 'allow',
   'hook: an invalid verdict falls back to the on_error verdict')
ok(_bad.get('error') and 'invalid verdict' in _bad.get('message', ''),
   'hook: an invalid verdict is reported as a contained error')

# a well-formed allow verdict passes through, sanitized
_good = hook.evaluate(['sh', '-c', 'echo \'{"verdict":"allow"}\''], 'ls')
eq(_good.get('verdict'), 'allow', 'hook: a valid allow verdict passes through')


print('secure-terminal-tests(modules): all passed' if not _failures else
      'secure-terminal-tests(modules): %d failed' % _failures)
sys.exit(1 if _failures else 0)
