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
