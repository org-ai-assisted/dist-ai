# tor-control-panel / anon-connection-wizard -- open-issue tracker

Current state of the bugs and hardening items from the Whonix forum thread
["Tor controller GUI (tor-control-panel)"](https://forums.whonix.org/t/tor-controller-gui-tor-control-panel/5444)
(arraybolt3's review, post #161, + adrelanos/troubadour) and later findings.

## Fixed and shipped

- **All confirmed review bugs** (custom-bridge data loss, wizard Cancel crash,
  duplicate network toggle, char-set bridge strip, cookie-auth dialog never
  shown, log-view regex crash, dropped proxy) -- each has a fail-before /
  pass-after regression here.
- **All robustness items** -- per-transport `ClientTransportPlugin`, guarded
  bootstrap `terminate()`, QThread GC lifetime, untrusted input sanitized before
  display, `DisableNetwork` directive-match, live cancel/back restore, IPv6
  proxy/bridge validation, absent-torrc handling.
- **Plain Debian / Kicksecure** -- distro-aware `/etc/tor/torrc.d` (Debian
  AppArmor forbids `/usr/local`), `tor-config-sane`, no redundant `ControlSocket`,
  `debian-tor` group prompt, privilege chain (leaprun/pkexec/sudo), package split.
- **Proxy bootstrap tags** -- `conn_proxy` / `ap_conn_proxy` / ... mapped, so a
  proxied connection no longer shows "Unknown Bootstrap TAG".
- **Enable-network hang** -- the privileged call now runs off the GUI thread
  (`CommandThread`), so Enable network no longer blocks/freezes the window.
- **Later security/robustness findings** -- symlink root-file disclosure in the
  torrc write path, NEWNYM fd leak, `valid_ip` crash on an over-long host (fuzz),
  a `TorBootstrap()` missing-arg bug (CodeQL).

## Still open

- **ACW layout drift** (post #161 bug 3): unchecking "I need bridges..." after a
  custom-bridges round-trip can leave the checkbox mid-window. Purely visual; a
  QGridLayout stretch issue that needs the running GUI to see and confirm a fix
  (cannot be reproduced or verified headlessly). May already be incidentally
  resolved by the layout cleanup -- unverified.
- **`tor_status.py` rewrite** around Enable-network edge cases is troubadour's
  ongoing upstream workstream.
