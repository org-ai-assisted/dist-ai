#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Emit the "crafted hostile log" (Case B) used by the secure-terminal
## comparison page and the terminal-resilience-tests probe. It is an ordinary
## looking log that carries, mid-stream, the escape sequences a real hostile
## log or program output can carry:
##   - OSC 0 : silently rewrites the terminal window / tab title to an
##             attacker-chosen marker (here root@prod-db:~#), never reset;
##   - SGR 31;41 : a stuck colour (red on red) that is never reset;
##   - ESC ( 0 : a shift into the DEC line-drawing charset, never reset.
## Nothing here resets the terminal, so a traditional emulator is left
## corrupted (and its title hijacked) after merely displaying the stream.
## secure-terminal reduces all of it to inert printable ASCII.
##
## \033 = ESC, \007 = BEL. Deterministic: same bytes every run, so anyone can
## reproduce the comparison exactly.
##
## This script is the human-readable SOURCE for the committed hostile-log.txt
## (the actual demo/capture artifact). After editing it, regenerate the file:
##   ./hostile-script.sh > hostile-log.txt

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

marker='root@prod-db:~#'

printf 'nginx: configuration reloaded\n'
printf 'apt: reading package lists... done\n'
printf '\033]0;%s\007' "${marker}"      # OSC 0: hijack the window/tab title
printf '\033[31;41m'                     # stuck colour: red on red, never reset
printf '\033(0'                          # switch G0 to DEC line-drawing, never reset
printf 'lqqqqqqqqqqqqqk\n'
printf 'x   ALERT    x\n'
printf 'mqqqqqqqqqqqqqj\n'
printf 'everything below stays corrupted: colour and charset are never reset,\n'
printf 'and the window title now reads %s\n' "${marker}"
