#!/usr/bin/python3
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Emit the site's HOMEPAGE hero board: one realistic "verify before you trust"
session that LOOKS trustworthy on a traditional terminal yet is laced with several
still-applicable display deceptions. It is cat'd on both sides of the homepage
before/after slider: a traditional emulator renders it innocent, secure-terminal
(SHOW mode) shows the same bytes AND flags every trap.

Same bytes, two stories. The deceptions, each a documented terminal display-deception
class -- NOT a cat/escape RCE (modern terminals mitigate those):

  1. HOMOGLYPH   a Cyrillic U+0430 stands in for Latin 'a' in "example.com", so a
                 domain glyph reads clean while the bytes are a different, attacker-
                 registrable IDN. Same code point as the corpus homoglyph PoC. Used on
                 several lines (mirror URL, contact address) so more of them are revealed
                 as the slider sweeps right.
  2. BIDI        a Trojan-Source right-to-left override (U+202E, closed by U+202C)
                 reorders a RENDERED filename vs its bytes, so an ".exe" shows ".pdf".
  3. ZERO-WIDTH  a U+200B hidden inside an identifier: invisible on a normal terminal,
                 boxed by secure-terminal.
  4. OSC 0 TITLE a silent title-set escape rewrites the window/tab title -- trusted UI
                 chrome -- to a domain the program chose ("example.com").
  5. OSC 52      a silent clipboard-write escape overwrites the clipboard; the planted
                 text here is an INERT shell comment (see below).

This is a PAGE-FACING display demo (no canary token), so -- like the notify / zerowidth
/ art / gradient / unicode generators in this dir -- it is produced here rather than
reproduced from the corpus, while reusing the corpus's canonical code points.

Display-only, nothing executed: it prints text plus two OSC escapes (title-set,
clipboard-set) -- no cursor addressing, alt-screen, clear or charset shift. On a
terminal that honours them the title and clipboard do change: `reset` (or
`printf '\033]0;\007'`) restores the title, and the clipboard is overwritten with an
INERT, comment-only marker -- harmless even if the user later pastes it into a shell.
Meant for an isolated demo / capture session.

The hostile bytes live only in the emitted stream; this source stays plain ASCII by
writing every non-ASCII / control byte as a \\u or \\x escape.

    hero-board.py            # writes the board to stdout
"""

import base64
import sys

# --- attack primitives, each a documented display-deception class -------------------
A = '\u0430'     # U+0430 CYRILLIC SMALL LETTER A -- look-alike for Latin 'a'
RLO = '\u202e'   # U+202E RIGHT-TO-LEFT OVERRIDE
PDF = '\u202c'   # U+202C POP DIRECTIONAL FORMATTING (closes the override)
ZWSP = '\u200b'  # U+200B ZERO WIDTH SPACE

# Homoglyph domains: the glyphs read "example.com" but the Cyrillic 'a' makes them a
# different, attacker-registrable IDN.
EX = 'ex' + A + 'mple.com'

# BIDI attachment: logical bytes end ".exe"; the override renders the tail reversed to
# a trusted ".pdf".
BIDI_FILE = 'q3-report.' + RLO + 'fdp.exe' + PDF

# ZERO-WIDTH identifier: "administrator" with a hidden U+200B -- reads clean, boxed by
# secure-terminal.
ZW_ID = 'admin' + ZWSP + 'istrator'

# OSC 0: silently set the window/tab title from program output (trusted chrome). The demo
# title names the injection itself, so the spoof is legible on the page; secure-terminal
# ignores it and keeps its own honest title.
OSC0_TITLE = '\x1b]0;gnome-terminal (window title injected)\x07'

# OSC 52: silently overwrite the clipboard. The planted text is an INERT shell comment
# (leading '#'): it demonstrates the silent overwrite yet runs NOTHING if pasted.
_CLIP_MARKER = '# secure-terminal hero demo: an OSC 52 escape silently set your clipboard'
OSC52_CLIP = '\x1b]52;c;%s\x07' % base64.b64encode(
    _CLIP_MARKER.encode('utf-8')).decode('ascii')


def board():
    # A believable "verify this release before you run it" session. Every visible line reads
    # as an ordinary, trustworthy step; the deception rides in the primitives. The lines are
    # WIDE and each trap sits at a different horizontal position -- left, centre-left, centre-
    # right, right -- so they fill the frame (no dead space) and the before/after slider
    # reveals them one by one as its divider sweeps left to right. Kept compact vertically.
    # The two silent OSC escapes ride out after the final line.
    lines = [
        'acme-cli 3.2  --  pre-deploy verification (release v3.2.0, signed + reproducible)',
        '',
        # trap 1 (homoglyph) sits far LEFT: the URL leads the line.
        'https://' + EX + '/acme/install.sh   -- fetching from the official signed mirror',
        '  ok -- TLS certificate valid, checksum matches the signed manifest',
        # trap 2 (bidi) sits CENTRE-LEFT.
        'release attachment q3-report.' + RLO + 'fdp.exe' + PDF + ' scanned -- reported document-only, safe',
        '  ok -- no active content, macros disabled',
        # trap 3 (zero-width) sits CENTRE.
        'deploy account (reviewed, least privilege): ' + ZW_ID + '@corp.internal   -- CHG-4821 approved',
        '  ok -- least-privilege confirmed, audit trail attached',
        # trap 4 (homoglyph) sits far RIGHT: the address ends the line.
        'maintainer signature good; support + security escalation contact is ops@' + EX,
        '  ok -- good signature, fingerprint matches the pinned keyring',
        '',
        'All preflight checks passed -- the release is verified and you are ready to deploy.',
    ]
    return '\n'.join(lines) + OSC0_TITLE + OSC52_CLIP + '\n'


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv:
        sys.stderr.write('usage: hero-board.py  (writes the hero board to stdout)\n')
        return 2
    sys.stdout.buffer.write(board().encode('utf-8'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
