# secure-terminal fingerprint probe

Reproducible active-fingerprint comparison behind the compatibility page's
Fingerprintability section. It sends the standard terminal identification/query
escapes to each terminal and records what it ANSWERS -- a terminal that answers
leaks that datum to any program, including a remote host over ssh.

    secure-terminal-fingerprint [--out aggregate.json] [--st-repo DIR]

- `probe.py` -- run INSIDE a terminal; sends each query to `/dev/tty`, reads the
  reply within a timeout, writes a JSON report. Used for the real emulators.
- `probe-secure-terminal.py` -- probes secure-terminal headlessly by driving a
  SecureTerminal widget: a child shell emits each query as output and the app's
  reply (if any) is captured off the pty. Covers CLI and TUI mode.
- `secure-terminal-fingerprint` -- runner: probes the real emulators
  (xterm/st/urxvt) under a nested Xvfb, probes secure-terminal, prints a
  comparison table and writes the aggregate JSON.

Needs Xvfb + the emulators; installs nothing. Result: a typical terminal answers
~10/13 queries (name, version, feature set, exact theme colours); secure-terminal
answers 0/13 in both modes -- it strips every escape and never writes a reply.

The three CSI-`t` / pixel queries can vary by build; the table on the site is a
captured snapshot, regenerate it with this tool.

## Bracketed-paste-bypass probe (sibling tool)

`secure-terminal-paste-fingerprint` measures a different class: whether a terminal's
bracketed-paste guard can be escaped by a pasted payload that hides a FORGED end
marker (`CSI 201~`) -- the pasted-command smuggling class (CVE-2021-31701 and kin).

    secure-terminal-paste-fingerprint [--out JSON] [--st-repo DIR]

- `paste_probe_lib.py` -- shared PAYLOAD (`BEFORE CSI201~ AFTER`) + `verdict()`
  (strips complete 200~..201~ regions; if AFTER survives outside one, the guard was
  bypassed). `test-paste-verdict.py` pins this pure logic.
- `probe-paste.py` -- runs INSIDE a terminal: enables bracketed paste, signals ready,
  captures the pasted byte stream, writes the verdict.
- `paste-driver.py` -- runs INSIDE the nested Xvfb: owns the PRIMARY + CLIPBOARD
  selections with the payload, launches the terminal running the probe, and
  middle-clicks to paste (a pointer event; the bare Xvfb has no WM, so keyboard focus
  is unset and Shift+Insert would go nowhere).
- runner -- drives xterm + st under Xvfb and measures secure-terminal headlessly
  through its real `sanitize_paste()`.

Needs Xvfb + xdotool + xclip (or xsel) + the emulators. Measured verdicts:
xterm `guard-held` (sanitises the forged marker), st `bypass` (forged marker escapes),
secure-terminal `guard-held` (paste sanitised to ASCII, so the ESC-based marker cannot
survive). urxvt is omitted: it does not act on synthetic paste events under a headless
Xvfb, so it cannot be driven here without lying about the result.
