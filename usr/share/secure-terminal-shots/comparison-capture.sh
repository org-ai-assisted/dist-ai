#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Reproduce the secure-terminal "hostile byte streams" comparison, headless.
## For each installed Debian terminal emulator it starts an interactive shell,
## TYPES a command into it (so the shot shows the prompt, the command, its output
## and the state of the prompt AFTER it -- what a user actually sees, and how to
## reproduce it), and screenshots the DECORATED window (title bar included):
##   Case A (random) : cat random.payload         -- a FIXED pseudo-random garble field
##                     (deterministic, seeded; see lib-capture.sh), sized so the returned
##                     prompt stays visible below the garble.
##   Case B (crafted): cat crafted.payload       -- an OSC-0 title hijack plus a
##                     stuck colour and a DEC line-drawing charset shift, none reset
##                     (the terminal-poc-corpus crafted-hostile-log PoC, decoded by
##                     its reproduce.py -- the single source of truth for the bytes).
##   Case C (homoglyph): cat homoglyph.payload      -- a domain carrying a Cyrillic
##                     look-alike (U+0430 for Latin a), so
##                     a traditional terminal shows a clean "example.com". secure-
##                     terminal is shot in TWO modes: box (look-alike -> a coloured
##                     box) and detail (<U+0430 CYRILLIC SMALL LETTER A>).
##   Case D (tui-showcase): cat tui-showcase.payload -- a safe display-only board that
##                     exercises EVERY text-attack class at once (homoglyph, bidi,
##                     zero-width, BOM, combining, fullwidth, DEC charset, SGR, OSC 8,
##                     OSC 0 title, alt-screen); secure-terminal box + detail.
## secure-terminal (its real GUI, from ST_REPO) is captured the same way. Output
## PNGs go to ./shots/ (copy them to the site's comparison/shots/). Usually driven
## via 'secure-terminal-shots comparison'; see this dir's README.md. The sibling
## generator here, paste-warning-shot.py, does the headless review-bar shots.
##
## The prompt is a fixed "user@host:~$" -- deliberately CONTRASTING with the
## root@prod-db the OSC-0 escape forces into the title bar: the prompt shows who
## you really are, the hijacked title lies.
##
## Decorations come from labwc -- the wlroots compositor LXQt ships -- running
## nested on the host X server (WLR x11 backend) with the Clearlooks Openbox
## theme. labwc draws the SAME real, themed server-side title bar on EVERY window
## it manages, X11 (Xwayland) and toolkit alike, exactly as on a real LXQt
## desktop -- so an OSC-0 title hijack shows up in that bar as it would for a
## user. Each shot is cropped to the emulator's window by its real geometry grown
## by the WM's title bar (labwc's _NET_FRAME_EXTENTS). Nothing is painted on.
##
## Needs: an X server on $DISPLAY, labwc (+ its Xwayland), the Clearlooks Openbox
## theme, x11-xserver-utils (setxkbmap), xdotool, xprop, ImageMagick. Installs
## NOTHING itself (supply-chain hygiene).
##
## Usage (normally via the wrapper: 'secure-terminal-shots comparison'):
##   ST_REPO=/path/to/secure-terminal/checkout ./comparison-capture.sh
## Deterministic Case B; Case A is random by nature (that is the point).
##
## NOTE: on a hardened Kicksecure/Whonix system the permission-hardener strips the
## exec bit from urxvt; restore it first: sudo chmod a+x /usr/bin/urxvt
##
## REAPING (do not chase the wrong cause again): every terminal + the secure-terminal GUI is
## started in its OWN session (shots_spawn_session -> setsid) and reaped by the recorded PGID
## (kill -- -PGID) with a per-capture deadline; leaked orphans are swept by the run's unique
## MARKER via safe-pgrep/safe-pkill. This exists because the GUI runs as `python3
## .../secure-terminal` (process name `python3`), so a name kill never reaped it and there was
## no timeout, so GUIs piled up. Reaping model + cleanup command: lib-capture.sh.
##   MISDIAGNOSIS to NOT re-open: "TERMINALS='' makes secure-terminal capture first" is FALSE.
##   The loop below reads ${TERMINALS:-<full list>}, so an EMPTY TERMINALS coerces to the full
##   emulator list; the secure-terminal block always runs AFTER the loop, never before it.

## style-ok: no-tmp-hardcode -- /tmp/.X11-unix is the X11 socket directory fixed by
## the protocol; libX11 looks there and nowhere else, so it cannot follow TMPDIR.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

here="$(dirname -- "$(readlink --canonicalize -- "$0")")"
out="${here}/shots"
mkdir --parents -- "${out}"

## the shared hostile-DATA contract (payload command + log generation).
# shellcheck source=./lib-capture.sh
source "${here}/lib-capture.sh"

## Fail BEFORE the expensive capture if the bundled webp optimizer is missing -- a direct
## run (not via the secure-terminal-shots wrapper) resolves it checkout-relative, not by PATH.
shots_require_image_optimize || exit 1

## Resolve the corpus NOW, while HOME is still the operator's -- the reassignment
## below would otherwise hide the documented ~/private-sources default from the
## resolver. Export it so shots_generate_logs (run after the reassign) reuses it.
CORPUS_REPO="$(shots_resolve_corpus "${here}/../../../../terminal-poc-corpus" || true)"
export CORPUS_REPO

host_display="${DISPLAY:-:0}"
THEME='Clearlooks'
## Clearlooks title bar + border height (fallback if _NET_FRAME_EXTENTS is unread).
FRAME_TOP=26

runtime_dir="$(mktemp --directory)"
export XDG_RUNTIME_DIR="${runtime_dir}"
export HOME="${runtime_dir}/home"
export XDG_CONFIG_HOME="${runtime_dir}/config"
mkdir --parents -- "${HOME}" "${XDG_CONFIG_HOME}/labwc"

## The run's unique reaping MARKER: the mktemp runtime dir, which every spawned terminal / GUI
## carries in its argv (via `--rcfile ${HOME}/.strc` and the recorded pgid file), so a crashed
## run's orphans can be swept by exactly this string and nothing else.
run_marker="${runtime_dir}"
## Per-capture deadline (seconds): a render that hangs longer than this has its process group
## reaped and the loop continues, so a wedged terminal cannot stall the whole grid.
SHOT_DEADLINE="${SHOT_DEADLINE:-90}"

## Optional scope filters (a FAST PATH for iteration; the FULL matrix is the default, so a bare
## run never silently skips anything). --only NAME restricts the emulators (repeatable); --case C
## restricts the cases in BOTH loops (repeatable); --st-only skips the emulators; --quick is a
## smoke shortcut. The full case list is the single source of truth for both loops.
## notify is a secure-terminal-only case (emulators have no standard notify shot -- the page's
## kitty.notify popup is captured separately), so it is in the full matrix for the ST loop but
## skipped in the emulator loop below.
all_cases='escape contrast title random homoglyph bidi zerowidth altscreen notify art gradient unicode tui-showcase hero-compare'
CASES="${CASES:-${all_cases}}"
## The emulator set, single source of truth for BOTH the capture loop and the --jobs
## orchestrator's partition. lxterminal is omitted: its single-instance startup maps no
## window headless.
DEFAULT_TERMINALS='xterm urxvt st konsole gnome-terminal xfce4-terminal mate-terminal qterminal alacritty kitty'
only_terminals=''
cases_sel=''
st_only=''
## --jobs N (N>1): orchestrator mode -- partition the grid across N concurrent lanes, each
## its OWN nested Xvfb+compositor (via its own xvfb-run), then optimize once. --no-st skips the
## secure-terminal pass (for an emulator-only lane); --optimize-only just webp-converts existing
## PNGs (the orchestrator's final merge step); --no-optimize leaves PNGs for that merge.
jobs=1
no_st=''
no_optimize=''
optimize_only=''
## --prep-dir DIR: a lane copies its payloads + icon theme from DIR (pre-generated ONCE by the
## orchestrator) instead of running reproduce.py + rasterising the icon itself. Removes the
## redundant, memory-spiking per-lane setup that OOM-killed a lane at higher --jobs.
prep_dir=''
while [ "$#" -gt 0 ]; do
   case "$1" in
      --only)
         [ "$#" -ge 2 ] || { printf '%s\n' 'comparison-capture: --only needs a terminal name' >&2; exit 2; }
         only_terminals="${only_terminals:+${only_terminals} }$2"
         shift 2
         ;;
      --case)
         [ "$#" -ge 2 ] || { printf '%s\n' 'comparison-capture: --case needs a case name' >&2; exit 2; }
         cases_sel="${cases_sel:+${cases_sel} }$2"
         shift 2
         ;;
      --st-only)
         st_only='true'
         shift
         ;;
      --quick)
         only_terminals='kitty'
         cases_sel='escape'
         shift
         ;;
      --jobs)
         [ "$#" -ge 2 ] || { printf '%s\n' 'comparison-capture: --jobs needs a count' >&2; exit 2; }
         jobs="$2"
         shift 2
         ;;
      --no-st)
         no_st='true'
         shift
         ;;
      --no-optimize)
         no_optimize='true'
         shift
         ;;
      --optimize-only)
         optimize_only='true'
         shift
         ;;
      --prep-dir)
         [ "$#" -ge 2 ] || { printf '%s\n' 'comparison-capture: --prep-dir needs a directory' >&2; exit 2; }
         prep_dir="$2"
         shift 2
         ;;
      *)
         printf '%s\n' "comparison-capture: unknown argument '$1'" >&2
         exit 2
         ;;
   esac
done
if [ -n "${cases_sel}" ]; then
   CASES="${cases_sel}"
fi

case "${jobs}" in
   ''|*[!0-9]*)
      printf '%s\n' "comparison-capture: --jobs needs a non-negative integer, got '${jobs}'" >&2
      exit 2
      ;;
esac

## --optimize-only: webp-convert the PNGs already in ${out} and stop (the orchestrator's
## single final merge, after its --no-optimize lanes finished). No capture, no runtime dir.
if [ -n "${optimize_only}" ]; then
   safe-rm --recursive --force -- "${runtime_dir}" 2>/dev/null || true
   shots_optimize_to_webp "${out}"/*.png
   printf '%s\n' "optimized; webp in ${out}"
   exit 0
fi

## --jobs N (N>1): orchestrator. Partition the grid across N concurrent lanes, each a full
## comparison-capture.sh run over a scope subset in its OWN nested Xvfb + compositor (own
## xvfb-run --auto-servernum -> a distinct display, so no shared-compositor race). The capture
## code is reused UNCHANGED; only the work is split. A final --optimize-only pass webp-converts
## once, so concurrent lanes never race on the shared shots dir's optimize step.
if [ "${jobs}" -gt 1 ]; then
   self="${here}/comparison-capture.sh"
   ## the runtime dir this orchestrator made is unused -- each lane makes its own.
   safe-rm --recursive --force -- "${runtime_dir}" 2>/dev/null || true
   fwd_case=()
   for fc in ${cases_sel}; do fwd_case+=(--case "${fc}"); done
   if [ -n "${st_only}" ]; then
      emu_set=''
   elif [ -n "${only_terminals}" ]; then
      emu_set="${only_terminals}"
   else
      emu_set="${DEFAULT_TERMINALS}"
   fi
   ## Pre-generate the payloads + icon theme ONCE into a shared dir; lanes copy from it via
   ## --prep-dir instead of each running reproduce.py + rasterising the icon (the concurrent,
   ## memory-spiking setup that OOM-killed a lane). Not in dry-run (no capture happens).
   orch_prep=''
   if [ -z "${SHOTS_LANE_DRY_RUN:-}" ]; then
      orch_prep="$(mktemp --directory)"
      export XDG_DATA_HOME="${orch_prep}/data"
      shots_generate_logs "${here}" "${orch_prep}" || exit "$?"
      shots_install_icon_theme "${orch_prep}/data"
   fi
   lane_dir="$(mktemp --directory)"
   lane_pids=()
   lane_logs=()
   lane_i=0
   ## Stagger emulator-lane startup so their (brief) compositor-bringup phases do not all peak at
   ## once; the long capture phase still overlaps fully.
   lane_stagger="${SHOTS_LANE_STAGGER:-6}"
   spawn_lane() {  ## $@ = args forwarded to a comparison-capture.sh lane
      local log prep_args
      log="${lane_dir}/lane.${lane_i}.log"
      ## SHOTS_LANE_DRY_RUN: print the lane's scope instead of running it, to verify the
      ## partition (which emulators / ST / cases each lane gets) without a capture.
      if [ -n "${SHOTS_LANE_DRY_RUN:-}" ]; then
         printf '%s\n' "LANE ${lane_i}:$(printf ' %s' "$@") --no-optimize"
         lane_i=$(( lane_i + 1 ))
         return 0
      fi
      prep_args=()
      [ -n "${orch_prep}" ] && prep_args=(--prep-dir "${orch_prep}")
      [ "${lane_i}" -gt 0 ] && sleep "${lane_stagger}"
      xvfb-run --auto-servernum --server-args='-screen 0 1600x1000x24' \
         "${self}" "$@" "${prep_args[@]}" --no-optimize >"${log}" 2>&1 &
      lane_pids+=("$!")
      lane_logs+=("${log}")
      lane_i=$(( lane_i + 1 ))
   }
   rc=0
   wait_lanes() {  ## wait for all currently-spawned lanes; echo their logs
      ## A lane's exit code is NOT folded into the run's rc: under --jobs load a lane can die
      ## transiently (labwc bringup racing) yet every shot it lost is re-shot by the sequential
      ## re-capture net below. The AUTHORITATIVE emulator-phase verdict is that net's final
      ## missing-check (a genuinely absent terminal is caught by the installed-check there), so a
      ## fully-recovered grid exits 0 and the shots are pulled -- a transient lane failure alone
      ## must not fail the whole run. A non-zero lane is noted for visibility only.
      local i lrc
      i=0
      while [ "${i}" -lt "${#lane_pids[@]}" ]; do
         lrc=0
         wait "${lane_pids[i]}" || lrc="$?"
         cat -- "${lane_logs[i]}" 2>/dev/null || true
         [ "${lrc}" -eq 0 ] || printf '%s\n' "note: an emulator lane exited ${lrc} (transient under --jobs load; the re-capture net backstops any missing shot)"
         i=$(( i + 1 ))
      done
      lane_pids=()
      lane_logs=()
   }
   ## PHASE 1: the emulators, in ${jobs} parallel lanes (they tolerate CPU contention).
   if [ -n "${emu_set}" ]; then
      bucket=()
      idx=0
      for e in ${emu_set}; do
         b=$(( idx % jobs ))
         bucket[b]="${bucket[b]:+${bucket[b]} }${e}"
         idx=$(( idx + 1 ))
      done
      b=0
      while [ "${b}" -lt "${jobs}" ]; do
         if [ -n "${bucket[b]:-}" ]; then
            only_args=()
            for e in ${bucket[b]}; do only_args+=(--only "${e}"); done
            spawn_lane "${only_args[@]}" --no-st "${fwd_case[@]}"
         fi
         b=$(( b + 1 ))
      done
      wait_lanes
   fi
   ## PHASE 1.5: sequential re-capture net for the emulator pass. Under parallel CPU load a lane
   ## can screenshot an emulator window before its content paints; capture_settled DISCARDS that
   ## blank (never publishes black), so a discarded shot leaves no file and a full reshoot would
   ## omit it -- the residual "manual per-emulator re-run" problem. With every parallel lane now
   ## finished (zero CPU contention -- the condition under which a sequential re-run reliably
   ## succeeds), re-shoot any still-missing emulator shot SEQUENTIALLY, one xvfb-run at a time,
   ## like the ST pass. Bounded rounds; anything still missing after the net is a HARD failure
   ## (rc=1), never a silent stale shot.
   if [ -n "${emu_set}" ] && [ -z "${SHOTS_LANE_DRY_RUN:-}" ]; then
      ## only INSTALLED emulators are expected to yield shots. A genuinely ABSENT emulator is a
      ## hard error here (an incomplete grid misrepresents the comparison) unless ALLOW_SKIP
      ## authorizes it -- the same rule the per-lane loop enforces, restated here because lane
      ## exit codes are no longer folded into rc (a transient labwc failure must not fail the run,
      ## but a missing terminal must). Only the installed set is chased by the net below.
      emu_present=''
      for e in ${emu_set}; do
         e_path="$(type -P "${e}" 2>/dev/null || true)"
         if [ -n "${e_path}" ] && [ -x "${e_path}" ]; then
            emu_present="${emu_present:+${emu_present} }${e}"
         elif [ -n "${ALLOW_SKIP:-}" ]; then
            printf '%s\n' "SKIP ${e} (not installed/executable; ALLOW_SKIP authorized)" >&2
         else
            printf '%s\n' "ERROR: emulator ${e} is not installed/executable; install it or set ALLOW_SKIP=1" >&2
            rc=1
         fi
      done
      recap_prep=()
      [ -n "${orch_prep}" ] && recap_prep=(--prep-dir "${orch_prep}")
      recap_round=0
      while [ "${recap_round}" -lt 3 ]; do
         mapfile -t recap_missing < <(shots_missing_emulator_shots "${out}" "${emu_present}" "${CASES}")
         [ "${#recap_missing[@]}" -eq 0 ] && break
         printf '%s\n' "re-capture net (round $(( recap_round + 1 ))): ${#recap_missing[@]} emulator shot(s) missing after the parallel pass; re-shooting sequentially"
         for pair in "${recap_missing[@]}"; do
            read -r re_e re_c <<< "${pair}"
            ## A re-shoot may itself exit non-zero (labwc bringup can still flake) -- its rc is
            ## NOT folded into the run's rc. Whether the shot now exists is decided by the
            ## authoritative missing-check after the rounds; a shot still absent then fails hard.
            xvfb-run --auto-servernum --server-args='-screen 0 1600x1000x24' \
               "${self}" --only "${re_e}" --case "${re_c}" --no-st "${recap_prep[@]}" --no-optimize \
               > "${lane_dir}/recap.${re_e}.${re_c}.log" 2>&1 || true
            cat -- "${lane_dir}/recap.${re_e}.${re_c}.log" 2>/dev/null || true
         done
         recap_round=$(( recap_round + 1 ))
      done
      mapfile -t recap_missing < <(shots_missing_emulator_shots "${out}" "${emu_present}" "${CASES}")
      if [ "${#recap_missing[@]}" -gt 0 ]; then
         printf '%s\n' "ERROR: ${#recap_missing[@]} emulator shot(s) STILL missing after the re-capture net:" >&2
         for pair in "${recap_missing[@]}"; do
            printf '%s\n' "   ${pair}" >&2
         done
         rc=1
      else
         printf '%s\n' "re-capture net: emulator grid complete, 0 shots missing"
      fi
   fi
   ## PHASE 2: the secure-terminal pass, run SEQUENTIALLY and ALONE. Each ST spec is a fresh Qt
   ## '--new-instance' cold start; when it competes with the emulator captures (or other ST
   ## launches) for CPU its render is starved and the shot comes out blank. Running ST after the
   ## emulator phase, one launch at a time, is what keeps it reliable. (A --st-only request skips
   ## phase 1 and runs only this.)
   if [ -z "${SHOTS_LANE_DRY_RUN:-}" ]; then
      st_prep=()
      [ -n "${orch_prep}" ] && st_prep=(--prep-dir "${orch_prep}")
      st_rc=0
      xvfb-run --auto-servernum --server-args='-screen 0 1600x1000x24' \
         "${self}" --st-only "${fwd_case[@]}" "${st_prep[@]}" --no-optimize \
         > "${lane_dir}/st.log" 2>&1 || st_rc="$?"
      cat -- "${lane_dir}/st.log" 2>/dev/null || true
      [ "${st_rc}" -eq 0 ] || rc="${st_rc}"
   else
      printf '%s\n' "LANE st(sequential): --st-only$(printf ' %s' "${fwd_case[@]}") --no-optimize"
   fi
   safe-rm --recursive --force -- "${lane_dir}" 2>/dev/null || true
   [ -n "${orch_prep}" ] && safe-rm --recursive --force -- "${orch_prep}" 2>/dev/null || true
   "${self}" --optimize-only || true
   printf '%s\n' "done; emulators parallel + secure-terminal sequential; shots in ${out}"
   exit "${rc}"
fi

## Reliable reaping REQUIRES the safe-pgrep/safe-pkill wrappers -- fail loudly, never fall back.
shots_require_safe_ps || exit 1
## Pre-clean: reap orphaned groups left by any PRIOR crashed run (marker-scoped -- it can never
## touch a process lacking that run's unique marker), then register this run.
shots_reap_registered || true
shots_register_run "${run_marker}"

## Attack payloads come from the terminal-poc-corpus (single source of truth), decoded
## by its reproduce.py. shots_generate_logs resolves the checkout and returns 77
## (a SKIP, like a missing ST_REPO) ONLY when the corpus is absent; a real
## payload-generation failure returns a distinct non-77 code, which is propagated
## here so a broken reproduce.py is not reported as a skip.
export XDG_DATA_HOME="${runtime_dir}/data"
mkdir --parents -- "${XDG_DATA_HOME}"
if [ -n "${prep_dir}" ]; then
   ## Lane: reuse the orchestrator's pre-generated payloads + icon theme. COPY (not symlink) the
   ## payloads so this lane can strip its own tui-showcase copy without mutating the shared one.
   cp -- "${prep_dir}"/*.payload "${HOME}/" || exit 1
   if [ -d "${prep_dir}/data" ]; then
      cp --recursive -- "${prep_dir}/data/." "${XDG_DATA_HOME}/" 2>/dev/null || true
   fi
else
   ## Attack payloads come from the terminal-poc-corpus (single source of truth), decoded by its
   ## reproduce.py; secure-terminal's icon is rasterised into the session icon theme so labwc
   ## shows the real title-bar logo.
   shots_generate_logs "${here}" "${HOME}" || exit "$?"
   shots_install_icon_theme "${XDG_DATA_HOME}"
fi
## The shell prompt for every shot. Single-sourced so the content-verify
## (shots_transcript_has_content) strips the EXACT prompt the shell prints when
## deciding whether an injected payload actually rendered.
SHOT_PROMPT='user@host:~$ '
cat > "${HOME}/.strc" <<RC
PS1='${SHOT_PROMPT}'
RC

## labwc config: the Clearlooks theme, server-side decorations.
cat > "${XDG_CONFIG_HOME}/labwc/rc.xml" <<XML
<?xml version="1.0"?>
<labwc_config>
  <theme><name>${THEME}</name></theme>
  <core><decoration>server</decoration></core>
  <placement><policy>automatic</policy></placement>
</labwc_config>
XML

## launch each emulator FROM ${HOME} so a plain "cat escape.payload" finds it.
cd "${HOME}"

wm_pid=''
labwc_wid=''
xwl_display=''
base_wids=''
cleanup() {
   ## safety net: reap any capture group that leaked from a failed shoot, then drop this run
   ## from the registry (its groups are gone) BEFORE the runtime dir is removed.
   shots_reap_run "${run_marker}" 2>/dev/null || true
   shots_deregister_run "${run_marker}" 2>/dev/null || true
   [ -z "${wm_pid}" ] || kill "${wm_pid}" 2>/dev/null || true
   [ -z "${wm_pid}" ] || wait "${wm_pid}" 2>/dev/null || true
   safe-rm -r -f -- "${runtime_dir}" 2>/dev/null || true
}
trap cleanup EXIT

## start labwc nested on the host X server; discover its Xwayland display and its
## host window (the compositor output we screenshot).
start_labwc() {
   local before_sock before_win after_win _ s w f
   before_sock=' '
   for f in /tmp/.X11-unix/X*; do
      [ -e "${f}" ] || continue        # no match -> the literal glob; skip it
      before_sock+="${f##*/} "
   done
   before_win=" $(DISPLAY="${host_display}" xdotool search --onlyvisible '' 2>/dev/null | tr '\n' ' ')"
   ## WLR_RENDERER=pixman: force wlroots' software renderer. The default GL renderer needs a GPU
   ## / DRM device that a nested Xvfb does not provide, so labwc intermittently fails to start
   ## ("try WLR_RENDERER=pixman") -- more often under the parallel --jobs load, which stands up
   ## several labwc instances. Software rendering is deterministic and plenty for a screenshot.
   WLR_RENDERER=pixman WLR_BACKENDS=x11 WLR_X11_OUTPUTS=1 DISPLAY="${host_display}" \
      labwc >"${runtime_dir}/labwc.log" 2>&1 &
   wm_pid="$!"
   labwc_wid=''; xwl_display=''
   for _ in $(seq 1 60); do
      kill -0 "${wm_pid}" 2>/dev/null || return 1
      if [ -z "${xwl_display}" ]; then
         for f in /tmp/.X11-unix/X*; do
            [ -e "${f}" ] || continue
            s="${f##*/}"
            case "${before_sock}" in *" ${s} "*) : ;; *) xwl_display=":${s#X}" ;; esac
         done
      fi
      if [ -z "${labwc_wid}" ]; then
         after_win=" $(DISPLAY="${host_display}" xdotool search --onlyvisible '' 2>/dev/null | tr '\n' ' ')"
         for w in ${after_win}; do
            case "${before_win}" in *" ${w} "*) : ;; *) labwc_wid="${w}" ;; esac
         done
      fi
      if [ -n "${xwl_display}" ] && [ -n "${labwc_wid}" ]; then
         sleep 1
         ## give labwc a roomier output than the 1024x768 default.
         DISPLAY="${host_display}" xdotool windowsize "${labwc_wid}" 1440 900 2>/dev/null || true
         sleep 1
         base_wids=" $(DISPLAY="${xwl_display}" xdotool search --onlyvisible '' 2>/dev/null | tr '\n' ' ')"
         return 0
      fi
      sleep 0.5
   done
   return 1
}

## launch an emulator as an Xwayland (X11) client so labwc decorates it, in its OWN session so
## the whole tree (emulator + shell + any server it spawns) can be reaped by one recorded PGID.
launch() {  ## $1=emulator  $2=case  $3=pgid-file
   local e case pgf base sh rows kh cmd
   e="$1"; case="$2"; pgf="$3"
   base=(env --unset=WAYLAND_DISPLAY "DISPLAY=${xwl_display}")
   sh=(bash --rcfile "${HOME}/.strc" -i)
   ## The tui-showcase board paints ~26 lines on the alternate screen; at the 24 rows
   ## the short cases use, its title bar scrolled off the top. Only that case gets the
   ## taller window, so the other cases' shots (and their committed on-page dimensions)
   ## are unchanged. kitty is sized in pixels, so it gets a matching taller height.
   rows=24; kh=430; cols=84
   if [ "${case}" = tui-showcase ]; then rows=32; kh=620; fi
   ## hero-compare: match the secure-terminal hero window WIDTH (~640px -- the app's minimum with
   ## its labelled toolbar) at the shared Hack/72-DPI cell size, so the homepage slider's two
   ## windows are the same size and their text overlaps. 95 cols of Hack at 11pt/72-DPI lands near
   ## that width.
   if [ "${case}" = hero-compare ]; then cols=97; fi
   cmd=()
   case "${e}" in
      xterm)
         ## forceBoxChars: draw DEC line-drawing with xterm's own crisp integer
         ## line-drawing, not the AA'd font glyph. The font glyph rendered with a
         ## bistable 1px sub-pixel jitter run-to-run on the tui-showcase box border;
         ## the internal line-drawing is pixel-exact and deterministic.
         cmd=("${base[@]}" xterm -xrm 'XTerm.vt100.forceBoxChars: true' \
            -geometry "${cols}x${rows}" -fa 'Monospace' -fs 11 -e "${sh[@]}")
         ;;
      urxvt)
         cmd=("${base[@]}" urxvt -geometry "${cols}x${rows}" -fn 'xft:Monospace:size=11' -e "${sh[@]}")
         ;;
      st)
         cmd=("${base[@]}" st -g "${cols}x${rows}" -f 'Monospace:size=11' -e "${sh[@]}")
         ;;
      konsole)
         cmd=("${base[@]}" QT_QPA_PLATFORM=xcb konsole --nofork -p "TerminalColumns=${cols}" -p "TerminalRows=${rows}" -e "${sh[@]}")
         ;;
      qterminal)
         cmd=("${base[@]}" QT_QPA_PLATFORM=xcb qterminal -e "${sh[@]}")
         ;;
      xfce4-terminal)
         cmd=("${base[@]}" GDK_BACKEND=x11 xfce4-terminal --disable-server --geometry "${cols}x${rows}" -x "${sh[@]}")
         ;;
      gnome-terminal)
         ## gnome-terminal is a thin client to gnome-terminal-server over D-Bus, with no
         ## flag to force a private server: give each launch a PRIVATE session bus so its
         ## server starts fresh and dies with the bus, and --wait so the launched process stays
         ## alive until the window closes. The private bus + server sit in the same session, so
         ## reaping the recorded PGID takes the whole thing down. VTE reads its profile from
         ## dconf; with no dconf daemon on the private bus it falls back to the built-in default
         ## profile -- the shipped default we want to show.
         if [ "${case}" = hero-compare ]; then
            ## Match secure-terminal's Hack font at 72-DPI cell metrics so the homepage slider's text
            ## overlaps. The gsettings + Xft.dpi setup lives in a sibling helper (no inline sh -c /
            ## exec); it runs inside the dbus session and launches gnome-terminal --wait.
            cmd=("${base[@]}" GDK_BACKEND=x11 dbus-run-session -- \
               "${here}/gnome-hero-launch.sh" "${cols}x${rows}" -- "${sh[@]}")
         else
            cmd=("${base[@]}" GDK_BACKEND=x11 dbus-run-session -- \
               gnome-terminal --wait --geometry "${cols}x${rows}" -- "${sh[@]}")
         fi
         ;;
      mate-terminal)
         cmd=("${base[@]}" GDK_BACKEND=x11 mate-terminal --disable-factory --geometry "${cols}x${rows}" -x "${sh[@]}")
         ;;
      alacritty)
         cmd=("${base[@]}" WINIT_UNIX_BACKEND=x11 alacritty -o "window.dimensions.columns=${cols}" -o "window.dimensions.lines=${rows}" -o 'font.size=11' -e "${sh[@]}")
         ;;
      kitty)
         cmd=("${base[@]}" KITTY_ENABLE_WAYLAND=0 kitty -o 'remember_window_size=no' -o 'initial_window_width=720' -o "initial_window_height=${kh}" -o 'font_size=11' "${sh[@]}")
         ;;
   esac
   if [ "${#cmd[@]}" -eq 0 ]; then
      ## an unknown emulator name must SKIP this cell, not return non-zero: the call site is a
      ## bare top-level command and `set -o errexit` would abort the whole capture run.
      printf '%s\n' "launch: no launch recipe for '${e}', skipped" >&2
      return 0
   fi
   shots_spawn_session "${pgf}" "${cmd[@]}"
}

## type a command into the focused terminal window and run it, as if a user did.
inject() {  ## $1=window-id  $2=command
   local wid cmd
   wid="$1"; cmd="$2"
   DISPLAY="${xwl_display}" xdotool windowactivate --sync "${wid}" 2>/dev/null || true
   DISPLAY="${xwl_display}" setxkbmap us 2>/dev/null || true    # '/' else types as '&'
   sleep 0.4
   DISPLAY="${xwl_display}" xdotool type --delay 12 -- "${cmd}"
   sleep 0.3
   DISPLAY="${xwl_display}" xdotool key --clearmodifiers Return
}

## screenshot labwc's output, crop to the emulator's window by its geometry grown
## by the themed frame (labwc's _NET_FRAME_EXTENTS, fallback FRAME_TOP).
capture_window() {  ## $1=output-path  $2=xwayland-window-id
   local dest wid tmp X Y WIDTH HEIGHT ext l r t b
   dest="$1"; wid="$2"; X=''; Y=''; WIDTH=''; HEIGHT=''
   DISPLAY="${host_display}" xdotool mousemove 1439 899 2>/dev/null || true
   sleep 0.3
   tmp="$(mktemp --suffix=.png)"
   if ! import -display "${host_display}" -window "${labwc_wid}" "${tmp}" 2>/dev/null; then
      safe-rm -f -- "${tmp}"
      return 1
   fi
   eval "$(DISPLAY="${xwl_display}" xdotool getwindowgeometry --shell "${wid}" 2>/dev/null \
      | grep -E '^(X|Y|WIDTH|HEIGHT)=' || true)"
   ext="$(DISPLAY="${xwl_display}" xprop -id "${wid}" _NET_FRAME_EXTENTS 2>/dev/null | grep -oE '= .*' || true)"
   ext="${ext#= }"; ext="${ext//,/}"
   read -r l r t b <<< "${ext}"
   [ -n "${b:-}" ] || { l=1; r=1; t="${FRAME_TOP}"; b=1; }
   if [ -n "${X}" ] && [ -n "${WIDTH}" ] && [ "${WIDTH}" -gt 0 ]; then
      local cx cy cw ch
      cx=$(( X - l )); [ "${cx}" -lt 0 ] && cx=0
      cy=$(( Y - t )); [ "${cy}" -lt 0 ] && cy=0
      cw=$(( WIDTH + l + r )); ch=$(( HEIGHT + t + b ))
      convert "${tmp}" -crop "${cw}x${ch}+${cx}+${cy}" +repage "${dest}" \
         2>/dev/null || cp -- "${tmp}" "${dest}"
   else
      cp -- "${tmp}" "${dest}"
   fi
   safe-rm -f -- "${tmp}"
}

## Remove the largest contiguous run of empty (background) terminal rows from a shot,
## so a few lines of content no longer sit above a screenful of dead space. The
## payloads are short, and the ST GUI will not shrink its window below ~400px (a Qt
## minimum-size floor), so the tail of every short case is empty terminal rows. Handles
## both content-at-the-top (traditional emulators: void at the bottom) and a fixed
## bottom banner/status bar with a void above it (secure-terminal: void in the middle).
## Only PURE background rows are removed, so content is never touched; a screen-filling
## case (random) has no large run and is left untouched. Side columns are excluded when
## classifying a row so a full-height scrollbar cannot mask the void.
tighten_deadspace() {  ## $1=png-path
   local f w h side mw bg tmpmap best_start best_len run_start run_len y line
   local best_end top_h bot_y bot_h margin threshold
   margin=10
   threshold=40
   f="$1"
   [ -f "${f}" ] || return 0
   w="$(identify -format '%w' "${f}")"; h="$(identify -format '%h' "${f}")"
   side=40; [ "${w}" -gt 200 ] || side=0
   mw=$(( w - 2 * side ))
   ## background = most-frequent colour of the lower half (skips the light top chrome;
   ## background dominates even a screen of garble). grep -m1 closes the pipe after the
   ## top colour; '|| true' keeps the upstream SIGPIPE from tripping errexit+pipefail.
   bg="$(convert "${f}" -gravity South -crop "${w}x50%+0+0" +repage \
           -depth 8 -format '%c' histogram:info:- \
         | sort -rn | grep -m1 -oiE '#[0-9A-F]{6}')" || true
   [ -n "${bg}" ] || bg="$(convert "${f}" -format "#%[hex:p{2,$(( h - 4 ))}]" info: | cut -c1-7)"
   ## per-row emptiness map: drop the side columns, take the absolute difference from a
   ## solid-background image (robust to any bg colour, incl. pure black/white) and
   ## threshold it (background -> black, content -> white), then the per-row maximum so
   ## any content pixel lights the whole row. Column 0 read out: an empty row is #000000.
   ## The statistic neighbourhood is CENTRED, so a width of mw would leave column 0's max
   ## covering only the left half and miss content near the right edge; 2*mw makes column
   ## 0 span the full row. Erring wide is safe -- it can only classify a row as non-empty,
   ## never delete real content.
   tmpmap="$(mktemp)"
   convert "${f}" -crop "${mw}x${h}+${side}+0" +repage \
      \( +clone -fill "${bg}" -colorize 100 \) \
      -compose difference -composite -threshold 6% \
      -statistic maximum "$(( 2 * mw ))x1" -crop "1x${h}+0+0" +repage txt:- \
      | tail -n +2 > "${tmpmap}"
   best_start=-1; best_len=0; run_start=-1; run_len=0; y=0
   while IFS= read -r line; do
      case "${line}" in
         *"#000000"*)
            [ "${run_start}" -ge 0 ] || run_start="${y}"
            run_len=$(( run_len + 1 ))
            if [ "${run_len}" -gt "${best_len}" ]; then best_len="${run_len}"; best_start="${run_start}"; fi
            ;;
         *)
            run_start=-1; run_len=0
            ;;
      esac
      y=$(( y + 1 ))
   done < "${tmpmap}"
   safe-rm -f -- "${tmpmap}"
   [ "${best_start}" -ge 0 ] && [ "${best_len}" -ge "${threshold}" ] || return 0
   best_end=$(( best_start + best_len - 1 ))
   top_h=$(( best_start + margin ))
   bot_y=$(( best_end - margin )); [ "${bot_y}" -lt "${top_h}" ] && bot_y="${top_h}"
   bot_h=$(( h - bot_y ))
   convert "${f}" \
      \( -clone 0 -crop "${w}x${top_h}+0+0" +repage \) \
      \( -clone 0 -crop "${w}x${bot_h}+0+${bot_y}" +repage \) \
      -delete 0 -append "${f}"
}

## Compose the homepage before/after slider pair from the hero-compare shots: secure-terminal's
## SHOW-mode board and the gnome-terminal render of the SAME board. The site's CSS resize slider
## overlays them, so they must be identical size AND their terminal text must sit at the same
## coordinates. hero-slider-compose.py keeps the title bars aligned at the top, inserts a white band
## above the shallower-chrome terminal's text so both text tops line up (secure-terminal carries a
## toolbar + tab strip + a bottom notice a plain terminal lacks), then pads both to one shared canvas.
## Runs at the END of a single-lane run, from the two .png shots before webp optimization; a no-op
## (logged) if either is absent (e.g. an emulator-only or --jobs lane). gnome-terminal is the
## traditional side: it HONOURS the OSC-0 title hijack (the spoofed title shows in its title bar)
## where konsole resets it, and -- captured with secure-terminal's own Hack font at 72 DPI (see
## launch()) -- its text is cell-for-cell the same size, so the wipe reads as ONE session secured vs not.
compose_hero_slider() {  ## $1=out-dir
   local out sec trad
   out="$1"
   sec="${out}/secure-terminal.hero-compare-show.png"
   trad="${out}/gnome-terminal.hero-compare.png"
   if [ ! -f "${sec}" ] || [ ! -f "${trad}" ]; then
      printf '%s\n' 'compose_hero_slider: secure-terminal + gnome-terminal hero-compare shots not both present; skipping slider compose' >&2
      return 0
   fi
   "${here}/hero-slider-compose.py" "${sec}" "${trad}" "${out}/hero-secure.png" "${out}/hero-traditional.png"
   ## Drop the raw per-terminal hero-compare shots: only the composed pair is referenced by the
   ## site, so leaving the sources behind would land them in comparison/shots/ (the driver pulls
   ## every .webp) as ORPHANS that website-tests rejects. Removing them here keeps the site green on
   ## every regeneration with no step to remember. The honest per-terminal captures still exist
   ## mid-run; only the composed hero-secure/hero-traditional are published.
   safe-rm -f -- "${out}"/*.hero-compare.png "${out}"/*.hero-compare.webp \
      "${out}/secure-terminal.hero-compare-show.png" "${out}/secure-terminal.hero-compare-show.webp" 2>/dev/null || true
   printf '%s\n' 'composed hero slider pair: hero-secure.png, hero-traditional.png (raw hero-compare shots dropped)'
}

## Capture the window, then guard against a blank/black grab (the content had not finished
## rendering when the screenshot was taken -- more likely under the parallel --jobs CPU load).
## Re-grab a couple of times WITHOUT re-injecting (the command already ran; it just needs to
## finish painting), then tighten. A shot still blank after retries is warned, never silent.
capture_settled() {  ## $1=output-path  $2=window-id  [$3='skip-tighten']
   local dest wid skip_tighten tries
   dest="$1"; wid="$2"; skip_tighten="${3:-}"; tries=0
   while [ "${tries}" -lt 3 ]; do
      if ! capture_window "${dest}" "${wid}"; then
         printf '%s\n' "warn: screenshot failed for $(basename -- "${dest}")"
         return 1
      fi
      if ! shots_shot_is_blank "${dest}"; then
         ## skip-tighten: the pinned full-viewport colour boards fill the terminal, so there
         ## is no screenful of dead space to trim, and tighten's content/background boundary
         ## detection is non-deterministic on a board whose edge colour is close to the
         ## terminal background -- it drifts the crop height run-to-run. The raw grab is the
         ## pinned window geometry, so leaving it untightened keeps the dimensions deterministic.
         [ "${skip_tighten}" = 'skip-tighten' ] || tighten_deadspace "${dest}"
         return 0
      fi
      tries=$(( tries + 1 ))
      printf '%s\n' "warn: $(basename -- "${dest}") blank (attempt ${tries}); waiting to re-grab"
      sleep 2
   done
   ## Still blank: DISCARD it rather than emit a black shot. A missing PNG is not webp'd or
   ## pulled, so a previously-good published shot is left intact instead of being overwritten
   ## with black. The caller warns.
   safe-rm --force -- "${dest}" 2>/dev/null || true
   printf '%s\n' "warn: $(basename -- "${dest}") still blank after retries -- discarded (kept any prior good shot)"
   return 1
}

## Block until the window's rendering has SETTLED: grab throwaway frames until two consecutive
## grabs match within a jitter tolerance. capture_settled only rejects a BLANK frame, so a heavy
## still-painting TUI pyte grid would be grabbed half-drawn; a whole unpainted row band differs by
## thousands of pixels between grabs, while the known ~1px sub-pixel border jitter differs by only
## a handful, so a small AE tolerance settles without waiting forever. Best-effort: a failed grab
## or a missing `compare` just returns and lets capture_settled proceed.
st_wait_render_settled() {  ## $1=window-id
   local wid a b i diff
   wid="$1"
   type -P compare >/dev/null || return 0
   a="$(mktemp -- "${runtime_dir}/settle.XXXXXX.png")"
   b="$(mktemp -- "${runtime_dir}/settle.XXXXXX.png")"
   if ! capture_window "${a}" "${wid}" 2>/dev/null; then
      safe-rm --force -- "${a}" "${b}" 2>/dev/null || true
      return 0
   fi
   for i in 1 2 3 4 5 6 7 8 9 10; do
      sleep 0.8
      capture_window "${b}" "${wid}" 2>/dev/null || break
      diff="$(compare -metric AE "${a}" "${b}" null: 2>&1 || true)"
      diff="${diff%%[!0-9]*}"
      case "${diff}" in '') diff=999999 ;; esac
      [ "${diff}" -lt 300 ] 2>/dev/null && break   # only jitter left -> settled
      ## Copy (not move) the newer frame to the baseline: mv would unlink ${b}, and the next
      ## capture_window would recreate that path OUTSIDE mktemp's protection. ${runtime_dir} is
      ## owner-only, so this is belt-and-braces, but it keeps ${b} a mktemp-created file.
      cp --force -- "${b}" "${a}"
   done
   safe-rm --force -- "${a}" "${b}" 2>/dev/null || true
}

## Wait until a freshly-launched window has actually RENDERED (its content is no longer a flat
## blank) before typing into it. The first secure-terminal launch is a Qt cold start that, under
## the parallel --jobs CPU load, can still be painting nothing when the fixed settle elapses --
## so the injected 'cat' is typed into a not-yet-ready app and never runs, leaving a black shot.
## Polls a light grab of the window; proceeds anyway on timeout (the capture's own blank-retry +
## warning is the backstop).
wait_window_ready() {  ## $1=window-id
   local wid tmp tries
   wid="$1"; tries=0
   tmp="$(mktemp --suffix=.png)"
   ## Generous ceiling: the first secure-terminal cold start under parallel --jobs contention can
   ## take tens of seconds (until the competing lane frees CPU). Each poll is a light grab.
   while [ "${tries}" -lt 30 ]; do
      if capture_window "${tmp}" "${wid}" 2>/dev/null && ! shots_shot_is_blank "${tmp}"; then
         safe-rm --force -- "${tmp}" 2>/dev/null || true
         return 0
      fi
      tries=$(( tries + 1 ))
      sleep 1
   done
   safe-rm --force -- "${tmp}" 2>/dev/null || true
   return 0
}

clear_windows() {
   local wid
   for wid in $(DISPLAY="${xwl_display}" xdotool search --onlyvisible '' 2>/dev/null || true); do
      case "${base_wids}" in *" ${wid} "*) continue ;; esac
      DISPLAY="${xwl_display}" xdotool windowkill "${wid}" 2>/dev/null || true
   done
}

## the largest NEW (non-baseline) window: the emulator's real top-level.
find_window() {
   local _ cur wid best X Y WIDTH HEIGHT area
   for _ in $(seq 1 80); do
      kill -0 "${wm_pid}" 2>/dev/null || return 1
      wid=''; best=0
      for cur in $(DISPLAY="${xwl_display}" xdotool search --onlyvisible '' 2>/dev/null || true); do
         case "${base_wids}" in *" ${cur} "*) continue ;; esac
         X=''; Y=''; WIDTH=''; HEIGHT=''
         eval "$(DISPLAY="${xwl_display}" xdotool getwindowgeometry --shell "${cur}" 2>/dev/null | grep -E '^(WIDTH|HEIGHT)=' || true)"
         area=$(( ${WIDTH:-0} * ${HEIGHT:-0} ))
         if [ "${area}" -gt "${best}" ]; then best="${area}"; wid="${cur}"; fi
      done
      if [ -n "${wid}" ] && [ "${best}" -gt 40000 ]; then
         printf '%s' "${wid}"
         return 0
      fi
      sleep 0.25
   done
   return 1
}

shoot() {  ## $1=emulator  $2=case
   local e case wid ww rescue_h pgf flagf epgid wdog cur_w
   e="$1"; case="$2"; wid=''
   ## the tall tui-showcase board needs a taller pixel-resized window (qterminal +
   ## the shrink rescue); the short cases keep their prior heights so their shots and
   ## committed page dimensions do not move.
   rescue_h=430; [ "${case}" = tui-showcase ] && rescue_h=620
   pgf="$(mktemp -- "${runtime_dir}/pgid.XXXXXX")"
   flagf="${pgf}.timeout"
   ## launch the emulator in its own session (records its PGID into pgf); arm a per-capture
   ## watchdog that reaps that group if the render hangs past the deadline.
   launch "${e}" "${case}" "${pgf}" >/dev/null 2>&1
   ## A non-numeric SHOT_DEADLINE makes shots_watchdog_start refuse (return 1); under errexit
   ## that must NOT abort the whole capture -- run this shot unbounded (no watchdog) instead.
   wdog="$(shots_watchdog_start "${SHOT_DEADLINE}" "${pgf}" "${flagf}")" || wdog=''
   wid="$(find_window || true)"
   if [ -z "${wid}" ]; then
      printf '%s\n' "warn ${e}.${case}: window never appeared, no shot"
      shots_watchdog_cancel "${wdog}"
      epgid="$(cat "${pgf}" 2>/dev/null || true)"
      clear_windows
      shots_reap_group "${epgid}"
      safe-rm -f -- "${pgf}" "${flagf}" 2>/dev/null || true
      return 1
   fi
   ## qterminal opens maximized and ignores a plain resize; unmaximize it first.
   if [ "${e}" = qterminal ]; then
      DISPLAY="${xwl_display}" wmctrl -i -r "${wid}" -b remove,maximized_vert,maximized_horz 2>/dev/null || true
      DISPLAY="${xwl_display}" xdotool windowsize "${wid}" 720 "${rescue_h}" 2>/dev/null || true
      sleep 0.7
   fi
   sleep 2
   ## tui-showcase's ~26-line board is taller than some emulators actually render (konsole
   ## ignores TerminalRows headlessly and paints ~22 rows), so the board's TOP line -- the
   ## embedded 'cat tui-showcase.payload' prompt that shows what produced the board -- scrolls
   ## off. Force a taller WINDOW before the board renders (the emulator reflows on the resize),
   ## keeping the emulator's own width, so that top line stays on-screen.
   if [ "${case}" = tui-showcase ]; then
      cur_w="$(DISPLAY="${xwl_display}" xdotool getwindowgeometry --shell "${wid}" 2>/dev/null | sed -n 's/^WIDTH=//p' || true)"
      [ -n "${cur_w}" ] || cur_w=1100
      DISPLAY="${xwl_display}" xdotool windowsize "${wid}" "${cur_w}" 880 2>/dev/null || true
      sleep 0.6
   fi
   wait_window_ready "${wid}"
   inject "${wid}" "$(shots_payload_cmd "${case}")"
   sleep 3
   ww="$(DISPLAY="${xwl_display}" xdotool getwindowgeometry --shell "${wid}" 2>/dev/null | sed -n 's/^WIDTH=//p' || true)"
   if [ -n "${ww}" ] && [ "${ww}" -lt 300 ]; then
      DISPLAY="${xwl_display}" xdotool windowsize "${wid}" 720 "${rescue_h}" 2>/dev/null || true
      sleep 1.5
   fi
   capture_settled "${out}/${e}.${case}.png" "${wid}" \
      || printf '%s\n' "warn ${e}.${case}: screenshot failed"
   shots_watchdog_cancel "${wdog}"
   [ -e "${flagf}" ] && printf '%s\n' "warn ${e}.${case}: capture exceeded ${SHOT_DEADLINE}s deadline, group reaped"
   epgid="$(cat "${pgf}" 2>/dev/null || true)"
   clear_windows
   shots_reap_group "${epgid}"
   safe-rm -f -- "${pgf}" "${flagf}" 2>/dev/null || true
}

## labwc intermittently fails to come up under the parallel --jobs load (its wlroots x11
## backend racing several nested compositors) -- the single dominant cause of lost shots in a
## full --jobs run. Retry its bringup a few times, killing a half-started instance first so the
## next attempt starts clean. The orchestrator's re-capture net is the outer backstop, but
## retrying here removes most of its work (and most of the transient lane failures).
labwc_started=''
for labwc_try in 1 2 3 4; do
   if start_labwc; then
      labwc_started=1
      break
   fi
   [ -z "${wm_pid}" ] || kill "${wm_pid}" 2>/dev/null || true
   [ -z "${wm_pid}" ] || wait "${wm_pid}" 2>/dev/null || true
   wm_pid=''
   printf '%s\n' "labwc bringup attempt ${labwc_try} failed; retrying" >&2
   sleep 1
done
if [ -z "${labwc_started}" ]; then
   printf '%s\n' 'labwc did not start after retries; log:'; tail -6 "${runtime_dir}/labwc.log"; exit 1
fi

## lxterminal is omitted: its single-instance startup maps no window headless.
## TERMINALS can be overridden to trial a subset (e.g. TERMINALS='xterm st').
## A MISSING terminal is a HARD ERROR, not a silent skip -- an incomplete grid
## would misrepresent the comparison. Install the emulator, or set ALLOW_SKIP=1 to
## deliberately authorize skipping (it is then logged, never silent).
if [ -n "${st_only}" ]; then
   TERMINALS=''
elif [ -n "${only_terminals}" ]; then
   TERMINALS="${only_terminals}"
else
   TERMINALS="${TERMINALS:-${DEFAULT_TERMINALS}}"
fi
for e in ${TERMINALS}; do
   ## `type -P` finds a binary that is on PATH and carries SOME exec bit, but that does
   ## not mean the CURRENT user may run it: a hardened Kicksecure/Whonix permission-hardener
   ## strips the others-exec bit from urxvt (mode 0754, owner root), so `type -P` succeeds
   ## yet the launch dies with "Permission denied" and the shot silently never appears.
   ## `[ -x ]` tests access for THIS user, so it catches that -- with an actionable message.
   e_path="$(type -P "${e}" 2>/dev/null || true)"
   if [ -z "${e_path}" ] || [ ! -x "${e_path}" ]; then
      if [ -z "${e_path}" ]; then
         reason="is not installed"
      else
         reason="is present at ${e_path} but not executable by you (a permission-hardener may have stripped its exec bit; restore it with: sudo chmod a+x ${e_path})"
      fi
      if [ -n "${ALLOW_SKIP:-}" ]; then
         printf '%s\n' "SKIP ${e} (${reason}; ALLOW_SKIP authorized)" >&2
         continue
      fi
      printf '%s\n' "ERROR: terminal ${e} ${reason}. Install/fix it, or set ALLOW_SKIP=1 to authorize skipping." >&2
      exit 1
   fi
   for c in ${CASES}; do
      ## notify + art are secure-terminal showcases, not attack comparisons: notify has no
      ## standard emulator shot (kitty's popup is captured separately), and art is a capability
      ## demo of secure-terminal's own truecolor rendering across its modes. Skip both in the
      ## emulator loop even though they are in the full ST matrix. SHOTS_EMULATOR_SKIP_CASES
      ## (lib-capture.sh) is the single source of truth, shared with the re-capture net's
      ## expected-shot accounting so the two never drift.
      case "${SHOTS_EMULATOR_SKIP_CASES}" in *" ${c} "*) continue ;; esac
      shoot "${e}" "${c}" || true
   done
   printf '%s\n' "captured ${e}"
done

## tui-showcase board: its embedded 'cat tui-showcase.payload' line is what puts 'cat' at the
## top of an ALT-SCREEN shot (the alt screen hides the real typed command). secure-terminal in
## CLI mode renders the board INLINE and shows the REAL typed prompt, so there the embedded line
## would DUPLICATE it -- so tui-showcase.payload is stripped IN PLACE for the CLI specs (they cat
## it by its clean name, and the real echo reads 'cat tui-showcase.payload'). secure-terminal in
## TUI mode enters the alt screen just like the emulators, so it needs the WITH-prompt board:
## saved first as a sibling (tui-showcase-withprompt.payload). Its real echo (the sibling's name)
## is hidden by the alt screen; the board's EMBEDDED clean-name prompt is what shows at the top.
## shots_st_inject_cmd picks the right one per mode. An emulator-only lane (--no-st) skips both
## the strip and the whole secure-terminal pass. Strip via the dedicated sibling script (not
## inline scripting).
if [ -n "${no_st}" ]; then
   printf '%s\n' 'skipping secure-terminal pass (--no-st)'
else
cp -- "${HOME}/tui-showcase.payload" "${HOME}/tui-showcase-withprompt.payload"
"${here}/strip-tui-showcase-prompt.py" "${HOME}/tui-showcase.payload"

st_bin="${ST_REPO:-}/usr/bin/secure-terminal"
st_pkg="${ST_REPO:-}/usr/lib/python3/dist-packages"
if [ -n "${ST_REPO:-}" ] && [ -f "${st_bin}" ]; then
   ## Each entry is "<case> <mode> <output-suffix>". secure-terminal is captured in
   ## the display mode that matters for each case: box for the byte-stream cases,
   ## including the homoglyph -- box flags the look-alike byte as a coloured box.
   ## The homoglyph-strip suffix is kept for the committed PNG / Pages reference
   ## (the mode it captures is box; the file name is a label).
   ## Capture width for the ST GUI window. 860 is the app's own default width
   ## (main.py TOOLBAR_DEFAULT_WIDTH): the responsive toolbar renders its "labeled"
   ## tier there -- icon-only action buttons plus every chip group captioned
   ## (unicode / mode / colours / Zoom) -- with no ">>" overflow chevron (labeled
   ## sizeHint 730 < 860 < full 902, so the compact tier is the one that fits). A
   ## wider frame only shrank the terminal text relative to the window; this matches
   ## how the app actually opens and keeps the frame close to the competitor shots.
   st_win_w=860
   ## Each entry is "<case> <mode> <suffix> [tui]". The optional 4th field 'tui' launches
   ## secure-terminal with --tui (opt-in full-screen mode) instead of the default CLI mode.
   ## The tui-showcase board is captured across the CLI/TUI mode x box/show/detail
   ## unicode matrix so the page's view switcher has a real shot per combo. Show renders
   ## printable unicode as its glyph (readable) while still boxing invisible/bidi/control
   ## bytes; detail names each codepoint inline. Even in full-screen TUI every cell stays
   ## character-filtered.
   ## Every demo case is captured in all 5 VALID secure-terminal views so the page's per-row
   ## switcher has a real shot per combo: CLI x {box, detail, show} + TUI x {box, show}. Detail
   ## (and Reveal) are CLI-only -- the fixed TUI grid cannot expand a codepoint inline. Suffix
   ## scheme: <box-suffix>, -detail, -show, -tui, -tui-show (matching tui-showcase's).
   st_specs=(
      'escape box escape'
      'escape detail escape-detail'
      'escape show escape-show'
      'escape box escape-tui tui'
      'escape show escape-tui-show tui'
      'contrast box contrast'
      'contrast detail contrast-detail'
      'contrast show contrast-show'
      'contrast box contrast-tui tui'
      'contrast show contrast-tui-show tui'
      'title box title'
      'title detail title-detail'
      'title show title-show'
      'title box title-tui tui'
      'title show title-tui-show tui'
      'notify box notify'
      'notify detail notify-detail'
      'notify show notify-show'
      'notify box notify-tui tui'
      'notify show notify-tui-show tui'
      'art box art'
      'art detail art-detail'
      'art show art-show'
      'art box art-tui tui'
      'art show art-tui-show tui'
      'gradient box gradient'
      'gradient detail gradient-detail'
      'gradient show gradient-show'
      'gradient box gradient-tui tui'
      'gradient show gradient-tui-show tui'
      'unicode show unicode-show'
      'unicode show unicode-tui-show tui'
      'unicode detail unicode-detail'
      'random box random'
      'random detail random-detail'
      'random show random-show'
      'random box random-tui tui'
      'random show random-tui-show tui'
      'homoglyph box homoglyph-strip'
      'homoglyph detail homoglyph-strip-detail'
      'homoglyph show homoglyph-strip-show'
      'homoglyph box homoglyph-strip-tui tui'
      'homoglyph show homoglyph-strip-tui-show tui'
      'bidi box bidi'
      'bidi detail bidi-detail'
      'bidi show bidi-show'
      'bidi box bidi-tui tui'
      'bidi show bidi-tui-show tui'
      'zerowidth box zerowidth'
      'zerowidth detail zerowidth-detail'
      'zerowidth show zerowidth-show'
      'zerowidth box zerowidth-tui tui'
      'zerowidth show zerowidth-tui-show tui'
      'altscreen box altscreen'
      'altscreen detail altscreen-detail'
      'altscreen show altscreen-show'
      'altscreen box altscreen-tui tui'
      'altscreen show altscreen-tui-show tui'
      'tui-showcase box tui-showcase'
      'tui-showcase show tui-showcase-show'
      'tui-showcase detail tui-showcase-detail'
      'tui-showcase box tui-showcase-tui tui'
      'tui-showcase show tui-showcase-tui-show tui'
      ## hero-compare: the homepage before/after slider. Captured in SHOW mode only (the
      ## page shows content AND flags danger) -- the one secure-terminal view the hero
      ## slider overlays against the traditional-emulator shot of the SAME board.
      'hero-compare show hero-compare-show'
   )
   ## Cold-start warmup: the FIRST secure-terminal launch in a lane, under parallel --jobs
   ## contention, has been observed to never paint the spec it captures (a black shot) even after
   ## a long wait -- the first launch pays for building fontconfig / Qt / icon caches. Prime the
   ## app with ONE throwaway launch (waited-on, then killed) so every real spec below is warm.
   warm_pgf="$(mktemp -- "${runtime_dir}/pgid.XXXXXX")"
   shots_spawn_session "${warm_pgf}" \
      env --unset=WAYLAND_DISPLAY "DISPLAY=${xwl_display}" QT_QPA_PLATFORM=xcb \
      QT_FONT_DPI=72 SECURE_TERMINAL_SHOT=1 \
      PYTHONPATH="${st_pkg}" python3 "${st_bin}" --new-instance --mode box \
      -- bash --rcfile "${HOME}/.strc" -i >/dev/null 2>&1
   warm_wid="$(find_window || true)"
   [ -n "${warm_wid}" ] && wait_window_ready "${warm_wid}"
   clear_windows
   shots_reap_group "$(cat "${warm_pgf}" 2>/dev/null || true)"
   safe-rm --force -- "${warm_pgf}" 2>/dev/null || true

   for spec in "${st_specs[@]}"; do
      read -r st_case st_mode st_suffix st_tui <<< "${spec}"
      ## honour --case: skip a spec whose case is not selected (default = all cases).
      st_case_selected=false
      case " ${CASES} " in
         *" ${st_case} "*)
            st_case_selected=true
            ;;
      esac
      if [ "${st_case_selected}" = false ]; then
         continue
      fi
      st_mode_flags=(--mode "${st_mode}")
      [ "${st_tui:-}" = tui ] && st_mode_flags+=(--tui)
      ## tui-showcase: secure-terminal strips the alt-screen escape and renders the
      ## banner + ~26 board rows INLINE (no alt buffer), so a short window would show
      ## only the footer -- give it a taller window (820 fits the 900px labwc output
      ## once grown by the frame). The short cases keep 620 so their committed page
      ## dimensions do not move; tighten_deadspace trims either back to its content.
      st_win_h=620; [ "${st_case}" = tui-showcase ] && st_win_h=820
      ## hero-compare: request a narrower secure-terminal window than the 860 comparison default so
      ## the homepage slider shot scales to a ~390px phone with legible text and the board fills the
      ## frame. Qt clamps the width up to the app's own minimum for the fully-labeled toolbar (~640
      ## under the capture compositor's 72-DPI metrics), so the toolbar stays complete (no ">>"
      ## overflow) at that clamped size -- which is the narrow hero width we want. RE-MEASURE if the
      ## toolbar/chip CSS changes; the emulator width (65 cols) above is matched to this result.
      st_win_w=860; [ "${st_case}" = hero-compare ] && st_win_w=700
      ## The GUI runs as `python3 .../secure-terminal` -- process name `python3` -- so it MUST
      ## be reaped by its session PGID, never by name. Launch it in its own session and arm the
      ## per-capture watchdog, exactly like the emulator shots.
      st_pgf="$(mktemp -- "${runtime_dir}/pgid.XXXXXX")"
      st_flagf="${st_pgf}.timeout"
      ## secure-terminal writes its live transcript here (fresh per spec) via the generic
      ## SECURE_TERMINAL_TRANSCRIPT_FILE config. Read after the grab to VERIFY the injected
      ## payload actually rendered -- a screenshot cannot tell an empty terminal from a
      ## full one (the window chrome paints either way).
      st_transcript="${st_pgf}.transcript"
      safe-rm -f -- "${st_transcript}" 2>/dev/null || true
      ## Pin the font DPI to 72 so the render is deterministic regardless of the X
      ## server's DPI. The responsive toolbar's 860 default (st_win_w) is calibrated
      ## to the real compositor's ~9pt/72-DPI metrics (labeled tier: captioned chips,
      ## no ">>" overflow); a default Xvfb reports 96 DPI, which widens the toolbar
      ## and silently drops it to the leaner icons tier (captions hidden). Same
      ## font-metric determinism the test runner pins for the tier assertions.
      ## SECURE_TERMINAL_SHOT=1: deterministic screenshot mode (caret hidden +
      ## synchronous render) so the GUI shot is byte-reproducible run-to-run. Set on
      ## the secure-terminal GUI launch ONLY -- never on the competitor terminals.
      shots_spawn_session "${st_pgf}" \
         env --unset=WAYLAND_DISPLAY "DISPLAY=${xwl_display}" QT_QPA_PLATFORM=xcb \
         QT_FONT_DPI=72 SECURE_TERMINAL_SHOT=1 \
         "SECURE_TERMINAL_TRANSCRIPT_FILE=${st_transcript}" \
         PYTHONPATH="${st_pkg}" python3 "${st_bin}" --new-instance "${st_mode_flags[@]}" \
         -- bash --rcfile "${HOME}/.strc" -i >/dev/null 2>&1
      ## same guard as the emulator shots: an invalid SHOT_DEADLINE must not errexit-abort.
      st_wdog="$(shots_watchdog_start "${SHOT_DEADLINE}" "${st_pgf}" "${st_flagf}")" || st_wdog=''
      stwid="$(find_window || true)"
      if [ -n "${stwid}" ]; then
         sleep 2
         ## Size the window so the whole toolbar fits (no ">>" overflow chevron),
         ## then let the layout settle before injecting + grabbing.
         DISPLAY="${xwl_display}" xdotool windowsize "${stwid}" "${st_win_w}" "${st_win_h}" 2>/dev/null || true
         sleep 0.6
         ## Qt cold start: wait until the app has actually painted its prompt before typing,
         ## or the 'cat' is injected into a not-yet-ready window and never runs (a black shot,
         ## seen on the FIRST secure-terminal launch under the parallel --jobs load).
         wait_window_ready "${stwid}"
         ## The command to inject (mode-aware; see shots_st_inject_cmd). secure-terminal now
         ## pins the alternate screen to the top (as a real terminal does), so a short
         ## alt-screen frame (the altscreen demo's one line) stays visible even when the
         ## shell's prompt returns below it.
         st_cmd="$(shots_st_inject_cmd "${st_case}" "${st_tui:-}")"
         ## Inject, grab, and VERIFY via the transcript file that the payload actually
         ## rendered; re-inject + re-grab on an empty transcript, and DISCARD (never
         ## publish an empty shot) if it never lands. The transcript catches an injection
         ## that never reached the window (a focus race under --jobs load) -- the shell is
         ## back at its prompt in that case, so a re-inject runs cleanly.
         st_verify_tries=0
         while : ; do
            ## Clear the transcript at the START of each attempt so the content check reflects
            ## THIS injection only -- else a prior attempt that rendered content but whose grab
            ## was discarded could leave stale content that validates a later empty grab.
            safe-rm -f -- "${st_transcript}" 2>/dev/null || true
            inject "${stwid}" "${st_cmd}"
            ## SECURE_TERMINAL_SHOT=1 renders synchronously, so a long fixed settle is unneeded.
            sleep 1
            ## The full-viewport colour boards paint a large grid (rows x cols cells rebuilt into the
            ## document) -- much heavier than a short attack payload, and capture_settled only rejects
            ## a BLANK frame, not a half-drawn one. In BOTH CLI and TUI, wait until the frame stops
            ## changing before the grab. (CLI too: it also grabs a partially-painted board otherwise.)
            ## These boards fill the viewport, so there is nothing for tighten_deadspace to trim, and
            ## its content/background boundary detection is non-deterministic on a board whose edge
            ## colour is near the terminal background (the gradient's near-white greyscale ramp on the
            ## light theme drifts the crop height by a row run-to-run). Skip tighten so the shot is the
            ## pinned window geometry -- deterministic dimensions, mode-agnostic (box/detail too).
            st_tighten_arg=''
            if [ "${st_case}" = art ] || [ "${st_case}" = gradient ]; then
               st_wait_render_settled "${stwid}"
               st_tighten_arg='skip-tighten'
            fi
            capture_settled "${out}/secure-terminal.${st_suffix}.png" "${stwid}" "${st_tighten_arg}"
            ## A shot passes once it exists AND the transcript carries real content (capture_settled
            ## discards a blank grab, leaving no file -- also a miss).
            if [ -f "${out}/secure-terminal.${st_suffix}.png" ] \
                  && shots_transcript_has_content "${st_transcript}" "${SHOT_PROMPT}"; then
               break
            fi
            st_verify_tries=$(( st_verify_tries + 1 ))
            if [ "${st_verify_tries}" -ge 3 ]; then
               safe-rm --force -- "${out}/secure-terminal.${st_suffix}.png" 2>/dev/null || true
               printf '%s\n' "warn secure-terminal.${st_suffix}: injected content never rendered (transcript empty after ${st_verify_tries} tries) -- discarded, not published"
               break
            fi
            printf '%s\n' "warn secure-terminal.${st_suffix}: transcript still empty (attempt ${st_verify_tries}); re-injecting"
            sleep 1
         done
      else
         printf '%s\n' "warn secure-terminal.${st_suffix}: window never appeared"
      fi
      shots_watchdog_cancel "${st_wdog}"
      [ -e "${st_flagf}" ] && printf '%s\n' "warn secure-terminal.${st_suffix}: capture exceeded ${SHOT_DEADLINE}s deadline, group reaped"
      st_epgid="$(cat "${st_pgf}" 2>/dev/null || true)"
      clear_windows
      shots_reap_group "${st_epgid}"
      safe-rm -f -- "${st_pgf}" "${st_flagf}" "${st_transcript}" 2>/dev/null || true
   done
   printf '%s\n' 'captured secure-terminal (real GUI)'
elif [ -n "${ALLOW_SKIP:-}" ]; then
   printf '%s\n' 'SKIP secure-terminal (ST_REPO not set/found; ALLOW_SKIP authorized)' >&2
else
   printf '%s\n' 'ERROR: secure-terminal not found. Set ST_REPO=/path/to/checkout, or set ALLOW_SKIP=1 to authorize skipping.' >&2
   exit 1
fi
fi

## Homepage hero slider: pad the secure-terminal + gnome-terminal hero-compare shots to one shared
## canvas so the site's CSS resize slider overlays them at identical dimensions. Before optimize, so
## the produced PNGs are webp-converted with the rest. Only when hero-compare was actually captured.
case " ${CASES} " in
   *' hero-compare '*)
      compose_hero_slider "${out}"
      ;;
esac

## Convert the captured PNGs to webp (the site references them as .webp). A lane run with
## --no-optimize leaves the PNGs for the orchestrator's single final --optimize-only merge.
if [ -z "${no_optimize}" ]; then
   shots_optimize_to_webp "${out}"/*.png
fi

printf '%s\n' "done; shots in ${out}"
