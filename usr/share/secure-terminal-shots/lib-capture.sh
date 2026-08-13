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
## reusing private-ai-config's headless-capture backends: the sandbox that runs these
## tools has NEITHER repo installed (code reaches it only by the whole tree being
## copied in), so the comparison subsystem must travel self-contained. The two
## capture pipelines above are genuinely different (host-X + import + frame-extents
## crop vs namespace + Xvfb + grim + black-trim), so only the DATA contract below
## -- which is the same for both -- is shared, to keep the cases from drifting.

## THREAT MODEL: a terminal cannot protect you from running hostile CODE, only from
## DISPLAYING hostile DATA. Every case DISPLAYS data and NEVER runs a script.
##   crafted   -- cat crafted.payload   (OSC-0 title hijack + stuck colour + DEC
##                line-drawing shift, none reset)
##   homoglyph -- cat homoglyph.payload (a domain carrying a Cyrillic look-alike,
##                U+0430 for Latin a)
##   bidi      -- cat bidi.payload      (Trojan-Source bidi-override controls that
##                reorder the rendered line vs its logical bytes)
##   zerowidth -- cat zerowidth.payload (a zero-width byte hidden inside a word --
##                invisible on a normal terminal, boxed by secure-terminal)
##   altscreen -- cat altscreen.payload (an unrestored alternate-screen switch that
##                leaves a traditional terminal stuck full-screen)
##   tui-showcase -- cat tui-showcase.payload (a safe display-only board exercising
##                every text-attack class at once; a full-screen "what you see vs what
##                is there" table)
##   notify    -- cat notify.payload    (an OSC-9 desktop-notification from log output)
##   random    -- head -c N /dev/random (genuine random garble)
##
## SINGLE SOURCE OF TRUTH: the attack payloads come from the terminal-poc-corpus
## (canary-forked, hex-encoded, harness-verified), reproduced by its tools/reproduce.py
## -- NOT hand-written here. The inline exceptions are the page-facing display demos that
## carry NO canary detection token: `notify` (friendly-wording OSC-9 demo), `zerowidth`
## (a self-describing hidden zero-width byte) and `random` (genuine kernel garble).

## /dev/random (not urandom): equivalent once seeded on a modern kernel, and
## Kicksecure prefers it. https://www.kicksecure.com/wiki/Dev/Entropy
## Sized so the returned prompt stays visible below the garble.
shots_random_bytes=1200
shots_random_source='/dev/random'

## image-optimize (lossless PNG->webp) is a bundled dist-ai tool at usr/bin/image-optimize,
## a FIXED location relative to THIS file (usr/share/secure-terminal-shots/lib-capture.sh) in
## both the installed tree and a source checkout. Resolve it by that path: a DIRECT
## comparison-capture.sh / wayland-capture.sh run has no wrapper to prime PATH, so a bare
## name would resolve only when usr/bin happens to be on PATH -- and fail AFTER the whole
## capture. BASH_SOURCE[0] is the absolute path both entry points source us by.
shots_image_optimize="$(dirname -- "${BASH_SOURCE[0]}")/../../bin/image-optimize"

## Fail BEFORE an expensive capture if that bundled optimizer is missing, never after it.
shots_require_image_optimize() {
   [ -x "${shots_image_optimize}" ] && return 0
   printf '%s\n' "shots: bundled image-optimize not found/executable at ${shots_image_optimize} -- the dist-ai checkout is incomplete; refusing to run the capture only to fail at the end" >&2
   return 1
}

## Resolve the terminal-poc-corpus checkout (CORPUS_REPO, a default under
## private-sources, or a script-relative fallback). Echoes the path, or returns 1.
shots_resolve_corpus() {  ## $1=script-relative fallback dir
   local cand
   for cand in "${CORPUS_REPO:-}" "${HOME}/private-sources/terminal-poc-corpus" "$1"; do
      [ -n "${cand}" ] || continue
      if [ -f "${cand}/tools/reproduce.py" ]; then
         printf '%s' "${cand}"
         return 0
      fi
   done
   return 1
}

## case -> corpus PoC id (empty for the inline cases notify / random).
shots_corpus_id() {  ## $1=case
   case "$1" in
      crafted)
         printf '%s' 'crafted-hostile-log'
         ;;
      homoglyph)
         printf '%s' 'homoglyph-domain-install-2021'
         ;;
      bidi)
         printf '%s' 'trojan-source-bidi-2021'
         ;;
      altscreen)
         printf '%s' 'alt-screen-hijack'
         ;;
      tui-showcase)
         printf '%s' 'tui-showcase'
         ;;
      clipboard)
         printf '%s' 'osc52-clipboard-write'
         ;;
   esac
}

## The benign canary the osc52-clipboard-write PoC writes to the clipboard; the
## clipboard-verdict lane reads it back to decide honored-vs-refused. Kept next to
## shots_corpus_id so the lane and the corpus id cannot drift.
shots_clipboard_token='POC-CORPUS-CANARY-FIRED'

shots_payload_cmd() {  ## $1=case -> the command string the terminal displays
   case "$1" in
      crafted)
         printf '%s' 'cat crafted.payload'
         ;;
      homoglyph)
         printf '%s' 'cat homoglyph.payload'
         ;;
      bidi)
         printf '%s' 'cat bidi.payload'
         ;;
      zerowidth)
         printf '%s' 'cat zerowidth.payload'
         ;;
      altscreen)
         printf '%s' 'cat altscreen.payload'
         ;;
      tui-showcase)
         printf '%s' 'cat tui-showcase.payload'
         ;;
      clipboard)
         printf '%s' 'cat clipboard.payload'
         ;;
      notify)
         printf '%s' 'cat notify.payload'
         ;;
      random)
         printf '%s' "head -c ${shots_random_bytes} ${shots_random_source}"
         ;;
   esac
}

## Reproduce the corpus-backed payloads into the dest dir. Two DISTINCT failures:
## 77 (a legitimate SKIP) ONLY when the terminal-poc-corpus is absent; any other
## non-zero is a real generation failure (reproduce.py / write) that a caller must
## NOT convert to a skip -- otherwise a broken payload is reported as green.
shots_generate_logs() {  ## $1=script-relative fallback dir $2=dest-dir
   local fallback dest corpus rp c id notify zerowidth

   fallback="$1"
   dest="$2"
   if ! corpus="$(shots_resolve_corpus "${fallback}/../../../../terminal-poc-corpus")"; then
      printf '%s\n' 'lib-capture: terminal-poc-corpus not found (set CORPUS_REPO)' >&2
      return 77
   fi
   rp="${corpus}/tools/reproduce.py"
   ## the corpus-backed cases: reproduce.py writes the exact hex-decoded payload bytes.
   ## Explicit '|| return 1' -- a caller runs this with '|| exit "$?"', and the '||'
   ## suppresses errexit inside the function, so a failed reproduce.py must be surfaced
   ## by hand (as a NON-77 code, distinct from the missing-corpus skip) or the capture
   ## would proceed with a missing payload.
   for c in crafted homoglyph bidi altscreen tui-showcase; do
      id="$(shots_corpus_id "${c}")"
      POC_CORPUS_IN_SANDBOX=1 python3 "${rp}" "${id}" --out "${dest}/${c}.payload" || return 1
   done
   ## notify: a page-facing friendly desktop-notification demo -- clearly-safe wording,
   ## no session/reauth framing. Not a corpus detection payload (which carries the
   ## canary token); kept inline deliberately. $'...' gives the real escape bytes.
   notify=$'build log: packaging step 3 of 5\n\033]9;Safe demonstration only: secure-terminal terminal-attack comparison test. No action needed.\007post-install: done\n'
   printf '%s' "${notify}" > "${dest}/notify.payload" || return 1
   ## zerowidth: a page-facing display demo of an invisible byte -- a single U+200B
   ## (zero-width space, UTF-8 e2 80 8b) hidden inside 'administrator'. On a normal
   ## terminal the word reads clean; secure-terminal boxes the hidden byte. Self-describing
   ## so the shot needs no external caption. No canary token, so kept inline like notify.
   ## Written as raw \x byte escapes, NOT \u200b: bash's \u encodes to the CURRENT locale,
   ## so under LC_ALL=C $'\u200b' yields the literal text "\u200b" and the demo would carry
   ## no zero-width byte at all. \x is locale-independent.
   zerowidth=$'A hidden zero-width byte sits inside this word: admin\xe2\x80\x8bistrator -- invisible on a normal terminal, boxed by secure-terminal.\n'
   printf '%s' "${zerowidth}" > "${dest}/zerowidth.payload" || return 1
}

shots_optimize_to_webp() {  ## $@=produced PNG shots -> convert each to webp in place
   ## Match the site's webp image references: a freshly captured PNG is losslessly
   ## converted to <name>.webp (the PNG removed) via image-optimize, so a regenerated shot
   ## lands optimized rather than being caught later by the pre-commit image gate.
   ## image-optimize is a REQUIRED, BUNDLED dist-ai sibling (${shots_image_optimize}); no
   ## fallback -- an absent one is a broken checkout, and this fails loudly.
   local shot
   for shot in "$@"; do
      [ -f "${shot}" ] || continue
      "${shots_image_optimize}" --webp --quiet -- "${shot}" >/dev/null
   done
}
