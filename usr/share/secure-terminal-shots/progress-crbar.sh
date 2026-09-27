#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Deterministic coloured carriage-return progress bar, emitted to stdout. Fixed step count, no
## clock, no rate -- so its bytes are byte-stable. Uses \r (return to column 0) + \033[K
## (erase-to-end-of-line) + SGR colour, and a final line SHORTER than the bar, so a terminal's
## line-editing modes render it DISTINCTLY (full erases cleanly; read-safe keeps the CR but drops
## the erase, leaving the wider bar's tail; append-only stacks every frame). Single source of the
## terminal-safe-corpus demos/progress-crbar-safe-to-cat.txt bytes (see that repo's check-drift).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

steps=20
width=24
for (( i=1; i<=steps; i++ )); do
   filled=$(( i * width / steps ))
   bar=''
   for (( c=0; c<filled; c++ )); do bar+='#'; done
   for (( c=filled; c<width; c++ )); do bar+=' '; done
   printf '\r\033[K\033[36mFetching \033[32m[%s]\033[0m %3d%%' "${bar}" "$(( i * 100 / steps ))"
done
printf '\r\033[K\033[32mFetch complete.\033[0m\n'
