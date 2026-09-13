#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.
## AI-Assisted

"""Shared constants + verdict logic for the bracketed-paste-bypass probe.

Importable (underscore name) by probe-paste.py, paste-driver.py and the runner,
so the payload and the verdict are defined in exactly one place."""

import re

BEG = b'\x1b[200~'                       # bracketed-paste BEGIN a terminal emits
END = b'\x1b[201~'                       # bracketed-paste END (also the FORGED one)
SENTINEL_BEFORE = b'STPASTE-BEFORE'
SENTINEL_AFTER = b'STPASTE-AFTER-ESCAPED'

# Placed on the PRIMARY selection by the driver. The middle bytes are a forged END
# marker: a safe terminal must not let it close its own 200~..201~ wrapper early.
PAYLOAD = SENTINEL_BEFORE + END + SENTINEL_AFTER


_REGION = re.compile(re.escape(BEG) + b'.*?' + re.escape(END), re.DOTALL)


def verdict(raw):
    """Classify the captured pty byte stream.

    The test: does the sentinel that follows the FORGED end marker land OUTSIDE the
    terminal's own bracketed-paste region? Strip every complete 200~..201~ region
    (non-greedy) and look at what remains:

    no-bracketed-paste : no 200~ wrapper at all (paste delivered as raw keystrokes)
    bypass             : AFTER survives in the unbracketed remainder (guard escaped)
    guard-held         : AFTER appears only inside a bracketed region
    inconclusive       : the paste never arrived, or an unexpected shape

    Stripping regions (not counting markers) stays correct even if the harness
    were to deliver the paste more than once."""
    has_after = SENTINEL_AFTER in raw
    has_before = SENTINEL_BEFORE in raw
    if not has_before and not has_after:
        return 'inconclusive'
    if BEG not in raw:
        return 'no-bracketed-paste'
    leftover = _REGION.sub(b'', raw)
    if SENTINEL_AFTER in leftover:
        return 'bypass'
    if has_after:
        return 'guard-held'
    return 'inconclusive'
