# dm-image-boot-tests: serial-console debug harness

Fast-iteration tooling for developing/debugging the boot checks that
`dm-image-test` runs, WITHOUT rebooting on every change.

## The channel

`dm-qemu --test-console` boots the guest with
`systemd.debug_shell=<ttyS> systemd.mask=serial-getty@<ttyS>.service`, so a
login-free ROOT bash is bound straight to the serial line. That sidesteps the
image's interactive user zsh, whose line editor (ZLE, auto-suggest, bracketed
paste) corrupts programmatically-sent input (mangles `"$?"`, swallows queued
`exec`). Drive this plain root bash instead -- the same reason `dm-image-test`
uses it in CI.

## Why boot once, poke many

Under pure-TCG (no KVM) a full boot is minutes. `dmserial.py` boots the image
ONCE with the serial on a UNIX socket and leaves qemu running; each `poke`
opens a fresh connection to that persistent debug-shell, so you iterate on
command/parse logic in seconds.

```
dmserial.py boot  /path/to/Kicksecure-*.qcow2         # or a .iso
dmserial.py poke  'systemctl is-system-running --wait' # boot barrier
dmserial.py poke  'getent passwd sysmaint || echo NO-SYSMAINT'
dmserial.py poke  "su - user -c 'systemcheck --cli --leak-tests --verbose'"
dmserial.py raw                                        # dump current console
dmserial.py kill                                       # stop qemu
```

- dm-qemu is resolved from `$DM_QEMU`, else the sibling `../dm-qemu` in this
  suite, else `PATH`.
- State (socket, pidfile, boot log, recorded image path) lives under
  `$DMSERIAL_WORK`, else `${XDG_RUNTIME_DIR:-/tmp}/dmserial`.
- Select the sysmaint session (GUI/lxqt flavors only -- CLI ships no
  `user-sysmaint-split`) by passing the boot-role cmdline as the boot extra:
  `dmserial.py boot IMG "boot-role=sysmaint systemd.unit=sysmaint-boot.target"`.

## Example probe

A probe waits for the root shell, crosses the boot barrier, then runs checks --
the pattern `dm-image-test` productionizes. Read output between a split token so
only the shell's real OUTPUT matches, never the command echo:

```python
import dmserial, time, re
s = dmserial.connect()

def run(cmd, wait=10):
    s.sendall(b"\r"); time.sleep(0.4); dmserial.drain(s, 1)
    beg, end = "B7X7", "E7X7"
    s.sendall(("printf '%s\\n'; %s; printf '%s%%s\\n' \"$?\"\r" % (beg, cmd, end)).encode())
    out = dmserial.drain(s, wait).replace("\r", "")
    m = re.search(re.escape(beg) + r"\n(.*?)" + re.escape(end) + r"(-?\d+)", out, re.S)
    return (m.group(2), m.group(1).strip()) if m else ("NO-RC", out[-200:])

# probe for the root shell, then run a check
print(run("systemctl is-system-running --wait", wait=400))
print(run("su - user -c 'systemcheck --cli --leak-tests --verbose'", wait=400))
```

This is DEV tooling, not a gated test: it is not registered in
`dist-ai-tests-all`. The productionized path is `dm-image-boot-tests`.
