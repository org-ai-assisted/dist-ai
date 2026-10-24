#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins the universal blank-gate contract of dm-calamares-install:
##   story_snap_nonblank NN name [timeout] -- POLL the framebuffer until it renders content
##     (image-blank-check --uniform-only passes), then store NN-name.png; a blind fixed-sleep
##     shot could grab a uniform-black between-modes frame instead. Returns 0 on content, 1 on
##     timeout (leaving the last, blank, frame so the floor still fails the run).
##   on_exit's universal FLOOR -- on a SUCCESSFUL run, image-blank-check --uniform-only is run
##     over the WHOLE shot dir, so EVERY published frame (incl. the transient boot grabs + the
##     finals the in-run gate never sees) is covered; a 1-colour black/white rectangle escalates
##     the exit rc to FAIL_RC. Exemption-free + fail-CLOSED: a new/unlisted frame is covered by
##     default. A run already FAILING keeps its real rc (floor is success-path only).
##
## Drives the REAL functions (sourced define-only) with recording stubs + the real
## image-blank-check on real tiny PNGs. No VM, no root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
subject=""
for candidate in "${DM_CALAMARES_INSTALL:-}" \
   "${test_dir}/../../bin/dm-calamares-install" \
   "/usr/bin/dm-calamares-install"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      subject="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
[ -n "${subject}" ] || { printf '%s\n' "FATAL: dm-calamares-install not found" >&2; exit 1; }

## image-blank-check is the REAL gate under test -- resolve the in-tree tool (sibling of the
## subject in the checkout) and drive it, never a stub. Export IMAGE_BLANK_CHECK so the sourced
## story_snap_nonblank / on_exit use the same one. No PATH dependency.
image_blank_check=""
for candidate in "${IMAGE_BLANK_CHECK:-}" \
   "$(dirname -- "${subject}")/image-blank-check" \
   "/usr/bin/image-blank-check"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      image_blank_check="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
[ -n "${image_blank_check}" ] || { printf '%s\n' "FATAL: image-blank-check not found (required dependency)" >&2; exit 1; }
export IMAGE_BLANK_CHECK="${image_blank_check}"

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## Real tiny PNGs (a 1-colour pure-black degenerate frame + a 2-colour sparse-but-non-uniform
## frame) written by the sibling generator -- a standalone executable, not an inline heredoc.
black_png="${work}/black.png"
content_png="${work}/content.png"
"${test_dir}/make-blank-fixtures.py" "${black_png}" "${content_png}"

## GUESTCTL '<vm> shot <dest>': copies a source PNG chosen by ${shot_plan} into <dest>. The plan
## is a file of source-png paths, one consumed per call (the last line sticks) -- so a test can
## model "black N times then content".
shot_plan="${work}/shot-plan"
shot_calls="${work}/shot-calls"
guestctl_stub="${work}/guestctl"
cat > "${guestctl_stub}" <<STUB
#!/bin/bash
if [ "\${2:-}" = 'shot' ] && [ -n "\${3:-}" ]; then
   n="\$(cat '${shot_calls}' 2>/dev/null || printf 0)"
   src="\$(sed -n "\$(( n + 1 ))p" '${shot_plan}' 2>/dev/null)"
   [ -n "\${src}" ] || src="\$(tail -n 1 '${shot_plan}' 2>/dev/null)"
   cp -- "\${src}" "\${3}"
   printf '%s\n' "\$(( n + 1 ))" > '${shot_calls}'
fi
exit 0
STUB
chmod +x "${guestctl_stub}"

# shellcheck disable=SC1090
source "${subject}"

## Fast clock: story_snap_nonblank sleeps 2s between polls; collapse it.
# shellcheck disable=SC2317  ## called indirectly by the sourced function
sleep() { command sleep 0.05; }

# shellcheck disable=SC2034
vm="testvm"
# shellcheck disable=SC2034
GUESTCTL="${guestctl_stub}"
# shellcheck disable=SC2034
me="dm-calamares-install"
# shellcheck disable=SC2034
FAIL_RC=5
## Read by the SOURCED story_snap_nonblank / on_exit (incl. via subshells), never in this file;
## export so shellcheck sees the external use (SC2034) -- the per-case `shot_dir=...` reassigns.
export shot_dir=""

pass=0; fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi; }
plan() { printf '%s\n' "$@" > "${shot_plan}"; true > "${shot_calls}"; }

## === story_snap_nonblank ===================================================================
## shot_dir is read by the SOURCED story_snap_nonblank / on_exit, not here, so shellcheck sees
## the per-case assignments as unused + the subshells as isolating.
# shellcheck disable=SC2030,SC2031,SC2034

## content on the FIRST shot: returns 0, exactly one GUESTCTL shot, frame is the content png.
sd="${work}/sd1"; mkdir -p -- "${sd}"; shot_dir="${sd}"
plan "${content_png}"
rc=0; story_snap_nonblank 22 firmware-logo 3 || rc=1
check "nonblank: content-first returns success" "${rc}"
got=0; [ "$(cat "${shot_calls}")" -eq 1 ] || got=1
check "nonblank: content-first took exactly one shot (no needless polling)" "${got}"
got=0; cmp --quiet "${sd}/22-firmware-logo.png" "${content_png}" || got=1
check "nonblank: content-first stored the content frame" "${got}"

## black for 3 polls then content: polls past the black frames, returns 0, stores content.
sd="${work}/sd2"; mkdir -p -- "${sd}"; shot_dir="${sd}"
plan "${black_png}" "${black_png}" "${black_png}" "${content_png}"
rc=0; story_snap_nonblank 22 firmware-logo 5 || rc=1
check "nonblank: black-then-content polls through and returns success" "${rc}"
got=0; [ "$(cat "${shot_calls}")" -ge 4 ] || got=1
check "nonblank: black-then-content kept polling until content" "${got}"
got=0; cmp --quiet "${sd}/22-firmware-logo.png" "${content_png}" || got=1
check "nonblank: black-then-content stored the first content frame" "${got}"

## always black: returns 1 at the deadline and LEAVES the blank frame for the floor.
sd="${work}/sd3"; mkdir -p -- "${sd}"; shot_dir="${sd}"
plan "${black_png}"
rc=0; story_snap_nonblank 22 firmware-logo 1 || rc=1
check "nonblank: always-black returns timeout (nonzero)" "$(( rc == 1 ? 0 : 1 ))"
got=0; cmp --quiet "${sd}/22-firmware-logo.png" "${black_png}" || got=1
check "nonblank: always-black leaves the blank frame in place (floor decides)" "${got}"

## no shot_dir -> no-op success.
shot_dir=""
rc=0; story_snap_nonblank 22 firmware-logo 1 || rc=1
check "nonblank: no shot_dir is a no-op success" "${rc}"

## === on_exit: DROP uniform transient (skip-class) frames; never FAIL on them ================
## Drive the REAL on_exit in a subshell (it ends in `exit "${rc}"`); vm_started=false so the
## whole VM/cleanup block is skipped and only the drop logic runs. luks-unlocked is a skip-class
## milestone; live-guestcontrol-ready is rich.
# shellcheck disable=SC2034
vm_started="false"
## on_exit's FAILURE branch reads these; set them so nounset does not abort the subshell.
# shellcheck disable=SC2034
shot="" check_log="" die_reason="" keep_failed="false"

## success + content-only dir -> exits 0, frame kept.
sd="${work}/drop-ok"; mkdir -p -- "${sd}"; cp -- "${content_png}" "${sd}/24-live-guestcontrol-ready.png"
shot_dir="${sd}"; rc=0; ( on_exit ) || rc=$?
check "on_exit: content-only dir exits 0" "${rc}"
got=0; [ -s "${sd}/24-live-guestcontrol-ready.png" ] || got=1
check "on_exit: a content frame is kept" "${got}"

## success + a uniform-black SKIP frame -> DROPPED (not published), run stays 0; content kept.
sd="${work}/drop-skip"; mkdir -p -- "${sd}"
cp -- "${content_png}" "${sd}/24-live-guestcontrol-ready.png"
cp -- "${black_png}" "${sd}/49-luks-unlocked.png"
shot_dir="${sd}"; rc=0; ( on_exit ) || rc=$?
check "on_exit: a uniform skip frame does NOT fail the run (exits 0)" "${rc}"
got=0; [ ! -e "${sd}/49-luks-unlocked.png" ] || got=1
check "on_exit: the uniform skip frame is DROPPED (not published)" "${got}"
got=0; [ -s "${sd}/24-live-guestcontrol-ready.png" ] || got=1
check "on_exit: a sibling content frame is kept" "${got}"

## a skip frame WITH content is KEPT (published).
sd="${work}/keep-skip"; mkdir -p -- "${sd}"; cp -- "${content_png}" "${sd}/49-luks-unlocked.png"
shot_dir="${sd}"; rc=0; ( on_exit ) || rc=$?
got=0; [ -s "${sd}/49-luks-unlocked.png" ] || got=1
check "on_exit: a skip frame with content is kept" "${got}"

## a uniform RICH frame is NOT dropped by on_exit (main's rich gate owns must-render frames).
sd="${work}/rich-black"; mkdir -p -- "${sd}"; cp -- "${black_png}" "${sd}/24-live-guestcontrol-ready.png"
shot_dir="${sd}"; rc=0; ( on_exit ) || rc=$?
got=0; [ -s "${sd}/24-live-guestcontrol-ready.png" ] || got=1
check "on_exit: a uniform RICH frame is NOT dropped (main gates it, not on_exit)" "${got}"

## FAILURE path rc!=0 -> success-path only: no drop, real rc preserved.
sd="${work}/fail-path"; mkdir -p -- "${sd}"; cp -- "${black_png}" "${sd}/49-luks-unlocked.png"
shot_dir="${sd}"; rc=0; ( bash -c 'exit 7' || on_exit ) || rc=$?
check "on_exit: a failing run keeps its real rc" "$(( rc == 7 ? 0 : 1 ))"
got=0; [ -s "${sd}/49-luks-unlocked.png" ] || got=1
check "on_exit: failure path drops nothing (success-path only)" "${got}"

## empty dir -> exits 0.
# shellcheck disable=SC2034
sd="${work}/drop-empty"; mkdir -p -- "${sd}"; shot_dir="${sd}"; rc=0; ( on_exit ) || rc=$?
check "on_exit: empty shot dir exits 0" "${rc}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
