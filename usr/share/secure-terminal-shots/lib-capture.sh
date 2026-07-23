#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: no-strict -- sourced-only fragment; a top-level strict-mode block
## would leak set -o errexit/nounset into the consumer (both already set it).

## Shared hostile-DATA contract for the secure-terminal comparison capture tools:
## comparison-capture.sh (pure X11, ImageMagick import) and wayland-capture.sh
## (native Wayland, grim). Sourced, never executed -- defines functions only.
##
## Deliberately kept HERE, in dist-ai, next to its two consumers rather than
## reusing dist-ai-config's headless-capture backends: the sandbox that runs these
## tools has NEITHER repo installed (code reaches it only by the whole tree being
## copied in), so the comparison subsystem must travel self-contained. The two
## capture pipelines above are genuinely different (host-X + import + frame-extents
## crop vs namespace + Xvfb + grim + black-trim), so only the DATA contract below
## -- which is the same for both -- is shared, to keep the cases from drifting.

## THREAT MODEL: a terminal cannot protect you from running hostile CODE, only from
## DISPLAYING hostile DATA. Every case DISPLAYS data and NEVER runs a script.
##   crafted   -- cat hostile.log   (OSC-0 title hijack + stuck colour + DEC
##                line-drawing shift, none reset)
##   homoglyph -- cat homoglyph.log (an install one-liner whose domain carries a
##                Cyrillic look-alike, U+0430 for Latin a)
##   random    -- head -c N /dev/random (genuine random garble)
## crafted + homoglyph read the deterministic logs from make-*-log.sh.

## /dev/random (not urandom): equivalent once seeded on a modern kernel, and
## Kicksecure prefers it. https://www.kicksecure.com/wiki/Dev/Entropy
## Sized so the returned prompt stays visible below the garble.
shots_random_bytes=1200
shots_random_source='/dev/random'

shots_payload_cmd() {  ## $1=case -> the command string the terminal displays
   case "$1" in
      crafted)
         printf 'cat hostile.log'
         ;;
      homoglyph)
         printf 'cat homoglyph.log'
         ;;
      random)
         printf 'head -c %s %s' "${shots_random_bytes}" "${shots_random_source}"
         ;;
   esac
}

shots_generate_logs() {  ## $1=generators-dir $2=dest-dir -> hostile.log + homoglyph.log
   local gen_dir="$1" dest="$2"
   "${gen_dir}/make-hostile-log.sh"   > "${dest}/hostile.log"
   "${gen_dir}/make-homoglyph-log.sh" > "${dest}/homoglyph.log"
}
