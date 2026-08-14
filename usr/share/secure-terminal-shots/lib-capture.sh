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
##   random    -- cat random.payload    (a fixed pseudo-random garble field, deterministic)
##
## SINGLE SOURCE OF TRUTH: the attack payloads come from the terminal-poc-corpus
## (canary-forked, hex-encoded, harness-verified), reproduced by its tools/reproduce.py
## -- NOT hand-written here. The inline exceptions are the page-facing display demos that
## carry NO canary detection token: `notify` (friendly-wording OSC-9 demo), `zerowidth`
## (a self-describing hidden zero-width byte) and `random` (a fixed pseudo-random field).

## DETERMINISTIC pseudo-random garble field, sized so the returned prompt stays visible
## below it. A live /dev/random would churn the shot on every run (never byte-identical);
## a FIXED-seed generator makes regeneration a no-op when nothing else changed. Generated
## by python3's seeded Mersenne-Twister (specified + stable across versions/platforms). ESC
## (0x1b) bytes are dropped so no escape sequence that happens to fall in the garble can
## hijack the terminal (alt-screen / clear / OSC title) -- the field renders as pure garble
## every run, and the exact bytes are irrelevant to the demonstration.
shots_random_bytes=1200
shots_random_seed=0

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
      escape)
         printf '%s' 'charset-shift-deception'
         ;;
      contrast)
         printf '%s' 'stuck-colour-contrast'
         ;;
      title)
         printf '%s' 'title-set-hijack'
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
      escape)
         printf '%s' 'cat escape.payload'
         ;;
      contrast)
         printf '%s' 'cat contrast.payload'
         ;;
      title)
         printf '%s' 'cat title.payload'
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
         printf '%s' 'cat random.payload'
         ;;
      art)
         printf '%s' 'cat art.payload'
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
   for c in crafted escape contrast title homoglyph bidi altscreen tui-showcase; do
      id="$(shots_corpus_id "${c}")"
      POC_CORPUS_IN_SANDBOX=1 python3 "${rp}" "${id}" --out "${dest}/${c}.payload" || return 1
   done
   ## Strip the human-facing "read me first" safety preamble from the tui-showcase SHOT
   ## payload ONLY (the corpus file keeps it for raw downloads). The header only ever lingers
   ## in secure-terminal's CLI shot (normal terminals hide it via the alt-screen switch),
   ## wasting vertical space and skewing the ST-vs-others compare. The sibling script slices
   ## to the first ESC and hard-fails if none is found; ${fallback} is the shots dir it lives in.
   "${fallback}/strip-tui-showcase-header.py" "${dest}/tui-showcase.payload" || return 1
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
   ## random: a DETERMINISTIC pseudo-random garble field (shots_random_seed / _bytes). A live
   ## /dev/random churned the shot every run; a fixed-seed generator gives byte-identical output
   ## so regeneration is a no-op when nothing changed. Drawn from python3's seeded Mersenne-
   ## Twister (stable across versions/platforms); 2x bytes are drawn and ESC (0x1b) filtered out
   ## so a stray escape sequence in the garble can never hijack the terminal (alt-screen / clear /
   ## OSC title), then sliced to the exact size. Not a corpus detection payload (no canary token)
   ## -- an inline page-facing demo like notify / zerowidth.
   python3 -c 'import random,sys
n=int(sys.argv[1]); r=random.Random(int(sys.argv[2]))
buf=bytes(x for x in (r.getrandbits(8) for _ in range(n*2)) if x!=0x1b)[:n]
sys.stdout.buffer.write(buf)' "${shots_random_bytes}" "${shots_random_seed}" > "${dest}/random.payload" || return 1
   ## art: a display-only truecolor terminal-art scene (a sunset beach + rolling green hills).
   ## SAFE to cat -- the generator emits ONLY SGR truecolour, the half-block glyph, newlines and
   ## a trailing reset (no cursor moves, no clear, no OSC), so it repaints nothing and leaves the
   ## scrollback clean. A page-facing capability demo: secure-terminal renders full 24-bit colour
   ## in every mode. Deterministic (pure function of position), so regeneration is a no-op.
   "${fallback}/truecolor-art.py" > "${dest}/art.payload" || return 1
}

## Install secure-terminal's icon into a session icon theme at ${1}=XDG_DATA_HOME, so labwc
## (which resolves a window's title-bar icon by app-id through the icon theme, not
## _NET_WM_ICON) shows the real logo. A no-op when ST_REPO / the svg is absent. Extracted so
## the --jobs orchestrator can build it ONCE and share it, instead of every lane re-rasterising
## the eight sizes concurrently (which spiked memory).
## True when a captured shot is (near) a single flat colour -- a blank/black grab, which
## happens when the window is screenshotted before its content finished rendering (more
## likely under the parallel --jobs load, where CPU contention slows the render past the
## fixed settle). The caller waits and re-grabs. Uses ImageMagick's own standard-deviation
## metric (0 = perfectly flat) so no extra tool is pulled in.
shots_shot_is_blank() {  ## $1=png
   local flat
   [ -s "$1" ] || return 0
   flat="$(convert "$1" -colorspace Gray -format '%[fx:standard_deviation<0.012?1:0]' info: 2>/dev/null || printf '0')"
   [ "${flat}" = '1' ]
}

shots_install_icon_theme() {  ## $1 = XDG_DATA_HOME target dir
   local data_home th st_icon sz
   data_home="$1"
   st_icon="${ST_REPO:-}/usr/share/icons/hicolor/scalable/apps/secure-terminal.svg"
   if [ -z "${ST_REPO:-}" ] || [ ! -f "${st_icon}" ]; then
      return 0
   fi
   th="${data_home}/icons/hicolor"
   mkdir --parents -- "${th}/scalable/apps"
   cp -- "${st_icon}" "${th}/scalable/apps/secure-terminal.svg"
   for sz in 16 22 24 32 48 64 128 256; do
      mkdir --parents -- "${th}/${sz}x${sz}/apps"
      convert -background none -resize "${sz}x${sz}" "${st_icon}" \
         "${th}/${sz}x${sz}/apps/secure-terminal.png" 2>/dev/null || true
   done
   gtk-update-icon-cache -f "${th}" 2>/dev/null || true
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

## ---- reliable process-group reaping + per-capture deadline ------------------------
##
## THE REAPING MODEL. Every terminal / GUI a capture starts is launched in its OWN session
## (setsid), and that session's PGID is recorded, so teardown takes down the WHOLE tree with a
## single `kill -- -PGID`. This is the ONLY reliable reaper for the secure-terminal GUI, which
## runs as `python3 .../usr/bin/secure-terminal`: its process NAME is `python3`, so the old
## `pkill -x secure-terminal` never matched it, and a `kill <child-pid>` reached only the direct
## child, leaking the GUI + its shell + child programs. Reaping by the recorded PGID, and (for
## orphans left by a crashed run) by the run's unique MARKER via the safe-pgrep/safe-pkill
## wrappers, is what stops the pile-up. NEVER `pkill -x python3` -- it would kill unrelated
## python GUIs across the whole session; NEVER bare `pgrep -f` / `pkill -f` -- they self-match
## this shell.

## A run's unique MARKER is its mktemp runtime dir path (present in every spawned process's argv
## -- via the shell's `--rcfile <runtime>/home/.strc` and the recorded pgid file). The registry
## records live-run markers so a crashed run's orphans can be reaped by the NEXT run's startup
## pre-clean or by `secure-terminal-shots --cleanup`. Overridable for tests; a fixed per-user path
## so it is shared between a run and a later cleanup invocation.
##
## PER-USER, non-shared: a world-writable /tmp path would let another local user pre-own the
## registry (silent registration failure) or plant a marker that shots_reap_registered feeds to a
## process-group kill. XDG_RUNTIME_DIR is already per-user 0700; otherwise a uid-scoped 0700 dir.
[ -v TMP ] || TMP=/tmp
if [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -d "${XDG_RUNTIME_DIR}" ]; then
   ## XDG_RUNTIME_DIR is per-user and already mode 0700: safe to nest under directly.
   shots_state_dir="${XDG_RUNTIME_DIR}/secure-terminal-shots"
   mkdir --parents -- "${shots_state_dir}" 2>/dev/null || true
   chmod 0700 -- "${shots_state_dir}" 2>/dev/null || true
else
   ## /tmp fallback: /tmp is world-writable + sticky, so a pre-existing entry at this fixed
   ## path could have been PLANTED by another local user, who could then read our run markers
   ## or plant a marker that shots_reap_registered feeds to a process-group kill. Trust it
   ## ONLY if it is a plain directory we OWN (never a symlink, never another uid's), and force
   ## it 0700; REFUSE a symlink / non-directory / foreign-owned entry rather than reuse it.
   shots_uid="$(id --user)"
   shots_state_dir="${TMP}/secure-terminal-shots-${shots_uid}"
   if [ -L "${shots_state_dir}" ] || { [ -e "${shots_state_dir}" ] && [ ! -d "${shots_state_dir}" ]; }; then
      printf '%s\n' "shots: refusing state dir '${shots_state_dir}': a symlink or non-directory at a world-writable temp path is a planting attack. Set XDG_RUNTIME_DIR or remove it." >&2
      exit 1
   fi
   if [ -d "${shots_state_dir}" ]; then
      shots_owner="$(stat --format='%u' -- "${shots_state_dir}" 2>/dev/null || true)"
      if [ "${shots_owner}" != "${shots_uid}" ]; then
         printf '%s\n' "shots: refusing state dir '${shots_state_dir}': owned by uid '${shots_owner:-unknown}', not us (${shots_uid}) -- another user planted it. Set XDG_RUNTIME_DIR or remove it." >&2
         exit 1
      fi
      chmod 0700 -- "${shots_state_dir}" 2>/dev/null || true
   else
      ( umask 077 && mkdir -- "${shots_state_dir}" ) || {
         printf '%s\n' "shots: failed to create private state dir '${shots_state_dir}'" >&2
         exit 1
      }
   fi
fi
shots_run_registry="${SHOTS_RUN_REGISTRY:-${shots_state_dir}/markers}"

## HARD-FAIL if the safe-pgrep/safe-pkill wrappers are absent. They ship with private-ai-config
## and are REQUIRED: reliable reaping must never fall back to bare pgrep/pkill (self-match trap)
## or to `pkill -x python3` (cross-session GUI kill). Their absence is a provisioning bug.
shots_require_safe_ps() {
   ## `type -P` (a bash builtin: no PATH lookup of its own, so it still answers under an empty
   ## PATH) resolves an executable ON PATH only -- unlike `command -v` it ignores aliases/
   ## functions, matching helper-scripts `has`. `has` itself is not used here: this fragment is
   ## deliberately self-contained (its sandbox has no helper-scripts checkout to source has.sh
   ## from), so it must not add that dependency.
   if type -P safe-pgrep >/dev/null 2>&1 && type -P safe-pkill >/dev/null 2>&1; then
      return 0
   fi
   printf '%s\n' 'shots: safe-pgrep/safe-pkill not found on PATH. They ship with private-ai-config and are REQUIRED for reliable process-group reaping (bare pgrep -f self-matches this shell; pkill -x python3 kills unrelated GUIs across sessions). This is a provisioning bug -- install private-ai-config in this sandbox. Refusing to fall back.' >&2
   return 1
}

## Echo the PGID of a PID (via ps -o pgid=, robust to a comm containing spaces/parens); return 1
## if unknown.
shots_pgid_of() {  ## $1=pid -> PGID
   local pid="$1" pgid
   [ -n "${pid}" ] || return 1
   pgid="$(ps -o pgid= -p "${pid}" 2>/dev/null | tr -d '[:space:]')" || return 1
   [ -n "${pgid}" ] || return 1
   printf '%s' "${pgid}"
}

## Launch a command in its OWN session (a fresh process group) and record that group's PGID into
## PGID-FILE, so teardown reaps the whole process tree with `kill -- -PGID`. Backgrounds; returns
## at once (the process is fully detached -- it does not need this shell to stay alive).
shots_spawn_session() {  ## $1=pgid-file  $2..=command
   local pgid_file="$1"
   shift
   ## setsid makes the inner bash a session/group leader, so its PID == its PGID == $$; it records
   ## that, then runs the real command as a CHILD in the same session. The child inherits that
   ## PGID, so teardown's `kill -- -PGID` reaps the whole group (leader bash + child + any tree it
   ## spawns) exactly as before. No explicit `exec` (R-103): whether bash forks the final command
   ## or last-command-optimises it into an in-place replacement, the recorded PGID is unchanged.
   setsid -- bash -c 'echo "$$" >"$1"; shift; "$@"' bash "${pgid_file}" "$@" &
}

## Reap ONE recorded process group: TERM the whole group, then KILL after a short grace. Guards
## against a non-numeric / bogus id and against ever signalling this shell's OWN group.
shots_reap_group() {  ## $1=pgid
   local pgid="$1" self i
   [ -n "${pgid}" ] || return 0
   case "${pgid}" in ''|*[!0-9]*) return 0 ;; esac
   [ "${pgid}" -gt 1 ] || return 0
   self="$(shots_pgid_of "$$" || true)"
   [ "${pgid}" = "${self}" ] && return 0
   kill -s TERM "-${pgid}" 2>/dev/null || true
   for i in 1 2 3 4 5 6; do
      kill -0 "-${pgid}" 2>/dev/null || return 0
      sleep 0.5
   done
   kill -s KILL "-${pgid}" 2>/dev/null || true
}

## Escape a string into a LITERAL POSIX-ERE pattern. safe-pgrep / safe-pkill match `--full` via
## `pgrep -f`, which is a REGEX (pgrep has no fixed-string mode), so a marker carrying a regex
## metacharacter -- the `.` in a default mktemp name, or a `+`/`[` in a custom TMPDIR -- would
## otherwise match loosely (a false straggler) or make pgrep error out (miss a real one).
## Backslash-escape every ERE metachar so the marker matches exactly its literal path.
shots_ere_escape() {  ## $1=literal -> ERE-escaped
   local s="$1" out='' c i
   for (( i=0; i<${#s}; i++ )); do
      c="${s:i:1}"
      case "${c}" in
         \\|'.'|'['|']'|'('|')'|'{'|'}'|'*'|'+'|'?'|'|'|'^'|'$')
            out+="\\${c}"
            ;;
         *)
            out+="${c}"
            ;;
      esac
   done
   printf '%s' "${out}"
}

## Reap every process group belonging to the run identified by its unique MARKER. Discovery is
## via safe-pgrep (read-only, self-match-safe); the kill is by NUMERIC PGID (kill -- -PGID), the
## only reliable way to take down a `python3` GUI and its whole child tree. A final safe-pkill
## sweep catches any marked straggler whose group was missed. Safe wrappers ONLY -- never bare
## pgrep -f / pkill -f / pkill -x. Because MARKER is a per-run mktemp path, this can NEVER touch a
## process that does not carry that exact marker.
shots_reap_run() {  ## $1=marker
   local marker="$1" pid pgid self pgids='' p marker_re
   shots_require_safe_ps || return 1
   [ -n "${marker}" ] || return 0
   ## match the marker LITERALLY (pgrep -f is a regex; the marker is a filesystem path).
   marker_re="$(shots_ere_escape "${marker}")"
   self="$(shots_pgid_of "$$" || true)"
   ## safe-pgrep exits 1 when nothing matches -- not an error here.
   for pid in $(safe-pgrep --full -- "${marker_re}" 2>/dev/null || true); do
      pgid="$(shots_pgid_of "${pid}" || true)"
      case "${pgid}" in ''|*[!0-9]*) continue ;; esac
      [ "${pgid}" -gt 1 ] || continue
      [ "${pgid}" = "${self}" ] && continue
      case " ${pgids} " in *" ${pgid} "*) : ;; *) pgids+=" ${pgid}" ;; esac
   done
   for p in ${pgids}; do kill -s TERM "-${p}" 2>/dev/null || true; done
   [ -n "${pgids}" ] && sleep 2
   for p in ${pgids}; do kill -s KILL "-${p}" 2>/dev/null || true; done
   ## final sweep: a MARKED straggler whose group we missed (exit 1 = none, forgiven).
   safe-pkill --signal KILL --full -- "${marker_re}" 2>/dev/null || true
}

## Record / drop / reap the run registry (markers of currently-live runs).
shots_register_run() {  ## $1=marker
   printf '%s\n' "$1" >> "${shots_run_registry}" 2>/dev/null || true
}
shots_deregister_run() {  ## $1=marker -- drop it from the registry on a clean exit
   local marker="$1" tmp
   [ -f "${shots_run_registry}" ] || return 0
   tmp="$(mktemp)" || return 0
   grep -Fxv -- "${marker}" "${shots_run_registry}" > "${tmp}" 2>/dev/null || true
   mv -- "${tmp}" "${shots_run_registry}" 2>/dev/null || safe-rm -f -- "${tmp}" 2>/dev/null || true
}
## Reap + clear EVERY registered marker (orphans from prior crashed runs). Each marker is unique,
## so this only ever touches that run's own processes.
shots_reap_registered() {
   local marker
   shots_require_safe_ps || return 1
   [ -f "${shots_run_registry}" ] || return 0
   while IFS= read -r marker; do
      [ -n "${marker}" ] || continue
      ## Defence in depth: a registry line is only ever a mktemp runtime-dir path this harness
      ## wrote. Reap only an absolute path of plausible length -- never a stray/relative token a
      ## corrupted registry could otherwise expand into a broad process-group kill.
      case "${marker}" in
         /?*)
            [ "${#marker}" -ge 6 ] || continue
            ;;
         *)
            continue
            ;;
      esac
      shots_reap_run "${marker}"
   done < "${shots_run_registry}"
   safe-rm -f -- "${shots_run_registry}" 2>/dev/null || true
}

## Per-capture deadline. A long-lived GUI must stay alive WHILE it is screenshotted, so it cannot
## run under `timeout` (that would kill it mid-capture). Instead a background watchdog reaps the
## capture's whole process group (read from PGID-FILE) if the orchestration has not finished
## within DEADLINE seconds, and touches FLAG-FILE so the caller can log the timeout. Cancel it
## with shots_watchdog_cancel once the capture completes in time.
shots_watchdog_start() {  ## $1=deadline-secs $2=pgid-file $3=flag-file -> echoes watchdog PID
   local deadline="$1" pgid_file="$2" flag_file="$3"
   ## A non-numeric deadline (callers read SHOT_DEADLINE from the environment) would make the
   ## loop's `[ i -lt deadline ]` error on the FIRST pass, so the watchdog would reap the capture
   ## group immediately and every capture would fail with no clear cause. Refuse it: no watchdog
   ## (the capture still runs, just unbounded) is far better than a self-inflicted instant reap.
   case "${deadline}" in
      ''|*[!0-9]*)
         printf '%s\n' "shots: ignoring invalid non-numeric deadline '${deadline}' (no watchdog armed)" >&2
         return 1
         ;;
   esac
   ## The watchdog's fds MUST be redirected off any command-substitution pipe: a caller does
   ## `wdog="$(shots_watchdog_start ...)"`, and a backgrounded child that inherited that pipe's
   ## write end would make the `$()` block until the watchdog exits -- i.e. stall every capture
   ## for the whole deadline. `</dev/null >/dev/null 2>&1` releases the pipe so `$()` returns at
   ## once with just the PID.
   (
      i=0
      while [ "${i}" -lt "${deadline}" ]; do
         sleep 1
         i=$(( i + 1 ))
      done
      pgid="$(cat "${pgid_file}" 2>/dev/null || true)"
      if [ -n "${pgid}" ]; then
         true > "${flag_file}" 2>/dev/null || true
         shots_reap_group "${pgid}"
      fi
   ) </dev/null >/dev/null 2>&1 &
   printf '%s' "$!"
}
shots_watchdog_cancel() {  ## $1=watchdog-pid
   local wp="$1"
   [ -n "${wp}" ] || return 0
   kill "${wp}" 2>/dev/null || true
   wait "${wp}" 2>/dev/null || true
}
