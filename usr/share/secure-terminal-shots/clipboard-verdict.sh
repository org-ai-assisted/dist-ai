#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Per-terminal OSC 52 clipboard-write VERDICT lane for the secure-terminal comparison.
##
## The screenshot lanes (comparison-capture.sh) show what a terminal DISPLAYS. This lane
## measures a NON-display outcome that no screenshot can show: whether program output can
## silently overwrite your system CLIPBOARD via an OSC 52 write. For each installed Debian
## terminal (and secure-terminal) it:
##   1. seeds the real X CLIPBOARD with a sentinel it can recognise,
##   2. cat's the terminal-poc-corpus osc52-clipboard-write payload in that terminal -- the
##      payload is a single OSC 52 escape that sets the clipboard to a BENIGN canary token,
##   3. reads the real X CLIPBOARD back via PyQt6 (no xclip), and records a verdict:
##        honored -- the clipboard now holds the canary token: the terminal let untrusted
##                   output overwrite your clipboard (a paste-hijack primitive).
##        refused -- the clipboard still holds the sentinel: output could not touch it.
## secure-terminal gates OSC 52 write off by default, so it MUST read 'refused'.
##
## Headless under Xvfb (uses $DISPLAY if already an X server, else starts one on :99).
## X selection ownership is live: the terminal that wrote it must still be alive when we
## read, so each terminal cat's the payload and then sleeps while we read, before it is
## killed. Sandbox-only. Emits a text table to stdout and shots/clipboard-verdict.tsv
## (terminal <TAB> verdict <TAB> read-back) for the page to cite.
##
## Bytes come from the terminal-poc-corpus (single source of truth), decoded by its
## reproduce.py; the canary token is defined once in lib-capture.sh. Installs NOTHING.
##
## Usage (normally via the wrapper: 'secure-terminal-shots clipboard'):
##   ST_REPO=/path/to/secure-terminal/checkout ./clipboard-verdict.sh
##   ALLOW_SKIP=1 authorises a LOGGED skip of a missing emulator or of secure-terminal.

## style-ok: no-tmp-hardcode -- /tmp/.X11-unix is the X11 socket directory fixed by the
## protocol; libX11 looks there and nowhere else, so it cannot follow TMPDIR.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

here="$(dirname -- "$(readlink --canonicalize -- "$0")")"
out="${here}/shots"
mkdir --parents -- "${out}"

## the shared hostile-DATA contract (corpus id + token).
# shellcheck source=./lib-capture.sh
source "${here}/lib-capture.sh"

CORPUS_REPO="$(shots_resolve_corpus "${here}/../../../../terminal-poc-corpus" || true)"
export CORPUS_REPO
if [ -z "${CORPUS_REPO}" ]; then
   printf '%s\n' 'clipboard-verdict: terminal-poc-corpus not found (set CORPUS_REPO)' >&2
   exit 77
fi

TOKEN="${shots_clipboard_token}"          # what a HONORED terminal writes (corpus canary)
SENTINEL='CLIPBOARD-UNTOUCHED-BY-OUTPUT'  # what we seed before every test

runtime_dir="$(mktemp --directory)"
export HOME="${runtime_dir}/home"
mkdir --parents -- "${HOME}"
payload="${runtime_dir}/clipboard.payload"

## Reproduce the OSC 52 payload from the corpus (its bytes, not hand-written here).
POC_CORPUS_IN_SANDBOX=1 python3 "${CORPUS_REPO}/tools/reproduce.py" \
   "$(shots_corpus_id clipboard)" --out "${payload}"

## A PyQt6 clipboard owner (sets text, then holds ownership so the value survives) and a
## one-shot reader. No xclip: PyQt6 talks to the X CLIPBOARD selection directly.
seeder_py="${runtime_dir}/seed.py"
reader_py="${runtime_dir}/read.py"
cat > "${seeder_py}" <<'PY'
import sys
from PyQt6.QtWidgets import QApplication
app = QApplication(sys.argv)
app.clipboard().setText(sys.argv[1])
app.exec()   # hold the selection until killed
PY
cat > "${reader_py}" <<'PY'
import sys
from PyQt6.QtWidgets import QApplication
app = QApplication(sys.argv)
sys.stdout.write(app.clipboard().text())
PY

xvfb_pid=''
ob_pid=''
seeder_pid=''
cleanup() {
   [ -z "${seeder_pid}" ] || kill "${seeder_pid}" 2>/dev/null || true
   [ -z "${ob_pid}" ] || kill "${ob_pid}" 2>/dev/null || true
   [ -z "${xvfb_pid}" ] || kill "${xvfb_pid}" 2>/dev/null || true
   safe-rm -r -f -- "${runtime_dir}" 2>/dev/null || true
}
trap cleanup EXIT

## A private headless X server plus a lightweight WM. Let Xvfb pick a FREE display
## (-displayfd) instead of a hard-coded number: a fixed display already in use -- a
## concurrent clipboard run -- would leave OUR Xvfb dead while the script silently attached
## to the OTHER server and blended two runs' clipboard measurements (identical sentinel and
## token). We read the number Xvfb reports and confirm the server we started is alive.
##
## openbox is REQUIRED, not cosmetic: some terminals (alacritty) only honour an OSC 52
## write while their window is FOCUSED -- a deliberate anti-hijack gate -- so a bare X
## server with no WM would report them 'refused' spuriously. openbox focuses each
## newly-mapped window; the payload waits a moment before firing so focus has settled.
Xvfb -displayfd 1 -screen 0 1024x768x24 >"${runtime_dir}/display" 2>"${runtime_dir}/xvfb.log" &
xvfb_pid="$!"
disp_num=''
for _ in $(seq 1 40); do
   kill -0 "${xvfb_pid}" 2>/dev/null || break
   disp_num="$(tr -dc '0-9' < "${runtime_dir}/display" 2>/dev/null || true)"
   [ -n "${disp_num}" ] && break
   sleep 0.25
done
if [ -z "${disp_num}" ] || ! kill -0 "${xvfb_pid}" 2>/dev/null; then
   printf '%s\n' 'ERROR: Xvfb did not start (no free display?); see the xvfb log' >&2
   exit 1
fi
export DISPLAY=":${disp_num}"
## Xvfb reports its display number over -displayfd before it is fully ready to accept
## clients; give it a moment (and confirm it stays up) so the first subjects do not race a
## half-started server and read a spurious 'error'.
sleep 2
kill -0 "${xvfb_pid}" 2>/dev/null || { printf '%s\n' 'ERROR: Xvfb exited during startup; see the xvfb log' >&2; exit 1; }
if ! type -P openbox >/dev/null 2>&1; then
   if [ -n "${ALLOW_SKIP:-}" ]; then
      printf '%s\n' 'WARN openbox not installed; focus-gated terminals (alacritty) may read refused spuriously (ALLOW_SKIP authorized)' >&2
   else
      printf '%s\n' 'ERROR: openbox is not installed. Focus-gated terminals would under-report. Install openbox, or set ALLOW_SKIP=1 to run anyway.' >&2
      exit 1
   fi
else
   openbox >"${runtime_dir}/openbox.log" 2>&1 &
   ob_pid="$!"
   sleep 1
fi

read_clip() { QT_QPA_PLATFORM=xcb python3 "${reader_py}" 2>/dev/null || true; }

## Seed the clipboard with the sentinel and hold it (background owner). Returns after the
## value is readable, so a later 'refused' really means "still the sentinel", not a race.
seed_clipboard() {
   [ -z "${seeder_pid}" ] || { kill "${seeder_pid}" 2>/dev/null || true; wait "${seeder_pid}" 2>/dev/null || true; }
   QT_QPA_PLATFORM=xcb python3 "${seeder_py}" "${SENTINEL}" >/dev/null 2>&1 &
   seeder_pid="$!"
   local _ now
   for _ in $(seq 1 20); do
      now="$(read_clip)"
      [ "${now}" = "${SENTINEL}" ] && return 0
      sleep 0.25
   done
   return 1
}

## Launch an emulator that cat's the payload and then sleeps, so it still OWNS any clipboard
## it wrote while we read. Runs with a fresh empty HOME -> shipped defaults.
launch_cat() {  ## $1=emulator  $2=command
   local e cmd
   e="$1"; cmd="$2"
   case "${e}" in
      xterm)
         xterm -e bash -c "${cmd}"
         ;;
      urxvt)
         urxvt -e bash -c "${cmd}"
         ;;
      st)
         st -e bash -c "${cmd}"
         ;;
      konsole)
         QT_QPA_PLATFORM=xcb konsole --nofork -e bash -c "${cmd}"
         ;;
      qterminal)
         QT_QPA_PLATFORM=xcb qterminal -e bash -c "${cmd}"
         ;;
      xfce4-terminal)
         GDK_BACKEND=x11 xfce4-terminal --disable-server -x bash -c "${cmd}"
         ;;
      mate-terminal)
         GDK_BACKEND=x11 mate-terminal --disable-factory -x bash -c "${cmd}"
         ;;
      alacritty)
         WINIT_UNIX_BACKEND=x11 alacritty -e bash -c "${cmd}"
         ;;
      kitty)
         KITTY_ENABLE_WAYLAND=0 kitty bash -c "${cmd}"
         ;;
   esac
}

## Reap a backgrounded subject and its emulator. 'launch_cat ... &' is a subshell whose
## CHILD is the emulator (no process-replacement exec, per the style gate), so killing the
## subshell alone would orphan the emulator to linger through its trailing 'sleep 8' and
## overlap the next subject. '-P' is parent-based (not the pattern match the safe-pkill
## rule guards against), so it targets exactly this subshell's children.
kill_tree() {  ## $1=pid
   pkill -P "$1" 2>/dev/null || true
   kill "$1" 2>/dev/null || true
}

## Left-pad a subject to a fixed column so the table lines up, without a printf width
## verb (R-030 keeps the printf format a fixed '%s'/'%s\n').
prow() {  ## $1=subject  $2=phrase
   local c1
   c1="$1                "
   printf '%s\n' "${c1:0:16} $2"
}

tab=$'\t'
declare -A verdicts
verdict_tsv="${out}/clipboard-verdict.tsv"
## Build into a temp first; publish atomically at the end only after the integrity gates
## pass, so a failed or partial run never clobbers a prior good table (codex P2).
verdict_tmp="${runtime_dir}/verdict.tsv"
true > "${verdict_tmp}"
prow 'TERMINAL' 'OSC 52 clipboard write'
prow '--------' '----------------------'

## classify a subject's result into a verdict word + a human phrase. A subject that never
## CONSUMED the payload (crashed on launch, missing runtime plugin, ...) leaves no
## done-marker and is recorded 'error', NOT 'refused' -- a crash must never read as a clean
## refusal, which for secure-terminal would be a FABRICATED security pass (codex P1).
record() {  ## $1=subject  $2=read-back  $3=consumed(1/0)
   local subj rb consumed verdict phrase
   subj="$1"; rb="$2"; consumed="$3"
   if [ "${consumed}" != '1' ]; then
      verdict='error'; phrase='error -- subject never ran the payload (crashed on launch?)'
   elif [ "${rb}" = "${TOKEN}" ]; then
      verdict='honored'; phrase='honored -- output overwrote the clipboard'
   elif [ "${rb}" = "${SENTINEL}" ]; then
      verdict='refused'; phrase='refused -- clipboard untouched'
   else
      verdict='inconclusive'; phrase="inconclusive -- read back [${rb}]"
   fi
   verdicts["${subj}"]="${verdict}"
   prow "${subj}" "${phrase}"
   printf '%s\n' "${subj}${tab}${verdict}${tab}${rb}" >> "${verdict_tmp}"
}

## The command a subject runs: wait a beat so the WM has focused the new window (some
## terminals gate OSC 52 write on focus), cat the payload (fires the write), TOUCH a
## done-marker to prove it consumed the payload, then linger so it keeps clipboard
## ownership while we read. Paths are %q-quoted so a spaced temp dir cannot break it.
subject_cmd() {  ## $1=done-marker -> the shell command string
   printf '%s' "sleep 1; cat $(printf '%q' "${payload}"); touch $(printf '%q' "${1}"); sleep 8"
}

TERMINALS="${TERMINALS:-xterm urxvt st konsole xfce4-terminal mate-terminal qterminal alacritty kitty}"
for e in ${TERMINALS}; do
   if ! type -P "${e}" >/dev/null 2>&1; then
      if [ -n "${ALLOW_SKIP:-}" ]; then
         printf '%s\n' "SKIP ${e} (not installed; ALLOW_SKIP authorized)" >&2
         continue
      fi
      printf '%s\n' "ERROR: terminal ${e} is not installed. Install it, or set ALLOW_SKIP=1." >&2
      exit 1
   fi
   if ! seed_clipboard; then
      printf '%s\n' "warn ${e}: could not seed the clipboard; skipping" >&2
      continue
   fi
   done_marker="${runtime_dir}/${e}.done"
   safe-rm -f -- "${done_marker}" 2>/dev/null || true
   launch_cat "${e}" "$(subject_cmd "${done_marker}")" >/dev/null 2>&1 &
   epid="$!"
   sleep 6
   consumed=0
   [ -e "${done_marker}" ] && consumed=1
   record "${e}" "$(read_clip)" "${consumed}"
   kill_tree "${epid}"
   sleep 1
done

## secure-terminal (its real GUI). Its default gates OSC 52 write off, so it MUST refuse.
st_bin="${ST_REPO:-}/usr/bin/secure-terminal"
st_pkg="${ST_REPO:-}/usr/lib/python3/dist-packages"
if [ -n "${ST_REPO:-}" ] && [ -f "${st_bin}" ]; then
   seed_clipboard || printf '%s\n' 'warn secure-terminal: could not seed the clipboard' >&2
   done_marker="${runtime_dir}/secure-terminal.done"
   safe-rm -f -- "${done_marker}" 2>/dev/null || true
   env QT_QPA_PLATFORM=xcb PYTHONPATH="${st_pkg}" \
      python3 "${st_bin}" --new-instance -- bash -c "$(subject_cmd "${done_marker}")" >/dev/null 2>&1 &
   epid="$!"
   sleep 7
   consumed=0
   [ -e "${done_marker}" ] && consumed=1
   record 'secure-terminal' "$(read_clip)" "${consumed}"
   kill_tree "${epid}"
   sleep 1
elif [ -n "${ALLOW_SKIP:-}" ]; then
   printf '%s\n' 'SKIP secure-terminal (ST_REPO not set/found; ALLOW_SKIP authorized)' >&2
else
   printf '%s\n' 'ERROR: secure-terminal not found. Set ST_REPO=/path/to/checkout, or ALLOW_SKIP=1.' >&2
   exit 1
fi

## Integrity gates before the table is trusted or published:
##  - kitty writes OSC 52 by default, so a tested kitty MUST read 'honored'. If it does
##    not, the rig is broken (no focus / no X clipboard / wrong display) and every
##    'refused' is a fabricated pass -- the exact failure this lane exists to avoid.
##  - secure-terminal MUST read a definitive 'refused'. An 'error' (it crashed on launch)
##    or anything but 'refused' must never publish as a clean security result: it is either
##    a broken rig or a real regression, and both need a human, not a green table.
integrity_fail() {  ## $1=message
   printf '%s\n' "ERROR: ${1}" \
      '  Not publishing the verdict table. Check openbox, the X clipboard and the subjects.' >&2
   exit 1
}
case " ${TERMINALS} " in
   *' kitty '*)
      [ "${verdicts[kitty]:-}" = 'honored' ] \
         || integrity_fail "integrity canary failed -- kitty writes OSC 52 by default, but read '${verdicts[kitty]:-<none>}'."
      ;;
esac
if [ -n "${verdicts[secure-terminal]:-}" ] && [ "${verdicts[secure-terminal]}" != 'refused' ]; then
   integrity_fail "secure-terminal read '${verdicts[secure-terminal]}', not the expected 'refused' (a crash, or a real regression)."
fi

mv -- "${verdict_tmp}" "${verdict_tsv}"
printf '%s\n' "done; verdicts in ${verdict_tsv}"
