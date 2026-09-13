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
    terminal's own bracketed-paste region? Work from the FIRST 200~ (pre-paste noise
    is ignored), strip every COMPLETE 200~..201~ region (non-greedy), and look at
    what remains:

    no-bracketed-paste : no 200~ wrapper at all (paste delivered as raw keystrokes)
    inconclusive       : no sentinel arrived; OR an unclosed 200~ remains after
                         stripping (the closing 201~ was not captured -- an
                         incomplete read, NOT proof the guard was escaped)
    bypass             : AFTER survives in the remainder of a CLOSED region (escaped)
    guard-held         : AFTER stayed inside a bracketed region

    Anchoring to the first 200~ and rejecting a dangling opener avoids two false
    'bypass' verdicts: AFTER sitting before an intact unforged wrapper, and a
    truncated capture of a safe terminal whose trailing 201~ has not yet arrived.
    Stripping complete regions (not counting markers) stays correct even under an
    accidental double paste."""
    has_after = SENTINEL_AFTER in raw
    has_before = SENTINEL_BEFORE in raw
    if not has_before and not has_after:
        return 'inconclusive'
    if BEG not in raw:
        return 'no-bracketed-paste'
    tail = raw[raw.index(BEG):]              # ignore any bytes before the first opener
    leftover = _REGION.sub(b'', tail)        # remove every complete 200~..201~ region
    if BEG in leftover:
        return 'inconclusive'                # an unclosed opener remains -> incomplete
    if SENTINEL_AFTER in leftover:
        return 'bypass'                      # AFTER escaped a closed region
    if has_after:
        return 'guard-held'                  # AFTER stayed inside a region
    return 'inconclusive'
