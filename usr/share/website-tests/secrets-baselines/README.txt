Secrets-scan baselines
======================

check_secrets.py scans every built site tree with gitleaks (see
usr/share/website-tests/check_secrets.py, wired into usr/bin/website-tests).

A static site's bytes are public, so any key/token/credential in the built
tree is an irreversible leak: the default (no baseline file) accepts nothing,
and every gitleaks finding FAILS the gate. That is correct -- fix the leak.

This directory holds the per-site accepted-false-positive files:

    secrets-baseline-<site>.txt

where <site> is the site root's directory basename (the same keying the other
webcheck lanes use). A file is created ONLY when a reviewed gitleaks hit is a
genuine false positive (e.g. an example/placeholder token in documentation).
Each accepted entry carries a one-line comment saying WHY it is not a real
secret.

The directory is tracked (via this README) so the --baseline-dir path always
exists; an absent per-site file simply means "no accepted false positives for
that site".
