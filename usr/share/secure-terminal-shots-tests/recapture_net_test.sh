#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: the --jobs orchestrator's sequential re-capture net must find EXACTLY the emulator
## shots that a parallel lane left missing (a discarded blank grab), so a full reshoot never
## leaves a stale/missing shot needing a manual per-emulator re-run. Tests the pure set-difference
## helper shots_missing_emulator_shots against a fabricated shots dir:
##   - a present .png OR a present .webp counts as present (pre-merge / post-merge),
##   - the secure-terminal-only showcases (notify, art) are NEVER expected of an emulator,
##   - every genuinely-missing (emulator, case) is reported, and nothing else.
## No display, no capture -- pure shell, milliseconds.
##
## FAILS on the old harness (no shots_missing_emulator_shots), so it is a real regression
## tripwire, not a tautology.
##
## Subject: lib-capture.sh, resolved from SECURE_TERMINAL_SHOTS_DIR, a checkout default, or the
## installed path. Absent -> exit 1 (FATAL): a required subject is an environment bug (R-220).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

lib=''
for cand in \
   "${SECURE_TERMINAL_SHOTS_DIR:-}/lib-capture.sh" \
   "${script_dir}/../secure-terminal-shots/lib-capture.sh" \
   "${script_dir}/../../share/secure-terminal-shots/lib-capture.sh" \
   '/usr/share/secure-terminal-shots/lib-capture.sh'; do
   if [ -n "${cand}" ] && [ -f "${cand}" ]; then
      lib="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${lib}" ]; then
   printf '%s\n' 'FATAL: lib-capture.sh not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 1
fi

# shellcheck source=../secure-terminal-shots/lib-capture.sh
source "${lib}"

pass=0
fail=0
check() {  ## $1=got $2=want $3=label
   if [ "$1" = "$2" ]; then
      printf '%s\n' "PASS: $3"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $3"
      printf '%s\n' "  got : $1"
      printf '%s\n' "  want: $2"
      fail=$(( fail + 1 ))
   fi
}

## The helper MUST exist -- absent means the old harness with no re-capture net (regression trip).
if ! declare -F shots_missing_emulator_shots >/dev/null 2>&1; then
   printf '%s\n' 'FAIL: shots_missing_emulator_shots not defined -- old harness has no re-capture net'
   printf '%s\n' '' '0 pass, 1 fail, 0 skip'
   exit 1
fi

tmp="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${tmp}" 2>/dev/null || true; }
trap cleanup EXIT
out="${tmp}/shots"
mkdir --parents -- "${out}"

emus='xterm st konsole'
cases='escape contrast notify art title'

## Present shots: a .png (pre-merge) and a .webp (post-merge) BOTH count as present.
touch -- "${out}/xterm.escape.png"      # xterm/escape present via png
touch -- "${out}/xterm.contrast.webp"   # xterm/contrast present via webp
touch -- "${out}/st.escape.png"         # st/escape present via png
touch -- "${out}/konsole.title.png"     # konsole/title present via png
## A notify/art file for an emulator must be IGNORED entirely (never an expected emulator shot),
## so its absence is never reported and its presence never suppresses a real miss.
touch -- "${out}/xterm.notify.png"

## Expected missing = every (emulator x case) minus notify/art minus the present ones above.
want="$(printf '%s\n' \
   'konsole contrast' \
   'konsole escape' \
   'st contrast' \
   'st title' \
   'xterm title' | sort)"

got="$(shots_missing_emulator_shots "${out}" "${emus}" "${cases}" | sort)"
check "${got}" "${want}" 'reports EXACTLY the missing emulator shots (notify/art excluded, png|webp = present)'

## No notify/art line may ever appear, even though xterm.notify.png exists and st.art.* does not.
if grep --quiet --extended-regexp '(^| )(notify|art)$' <<< "${got}"; then
   check present absent 'never reports a notify/art case as a missing emulator shot'
else
   check absent absent 'never reports a notify/art case as a missing emulator shot'
fi

## A complete grid reports nothing.
touch -- "${out}/konsole.contrast.png"
touch -- "${out}/konsole.escape.png"
touch -- "${out}/st.contrast.png"
touch -- "${out}/st.title.png"
touch -- "${out}/xterm.title.png"
empty="$(shots_missing_emulator_shots "${out}" "${emus}" "${cases}")"
check "${empty}" '' 'a complete emulator grid yields no missing shots'

## The shared skip-case constant is the single source of truth and must hold notify + art.
case "${SHOTS_EMULATOR_SKIP_CASES}" in
   *' notify '*)
      check present present 'SHOTS_EMULATOR_SKIP_CASES contains notify'
      ;;
   *)
      check missing present 'SHOTS_EMULATOR_SKIP_CASES contains notify'
      ;;
esac
case "${SHOTS_EMULATOR_SKIP_CASES}" in
   *' art '*)
      check present present 'SHOTS_EMULATOR_SKIP_CASES contains art'
      ;;
   *)
      check missing present 'SHOTS_EMULATOR_SKIP_CASES contains art'
      ;;
esac

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: re-capture net missing-shot accounting'
