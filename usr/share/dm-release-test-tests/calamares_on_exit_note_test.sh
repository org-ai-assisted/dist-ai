#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-calamares-install's on_exit writes a FAILED note into the published check-log.
## It must only point at "the published screenshot" when one was ACTUALLY published
## (a non-empty ${shot} after the stuck-screenshot copy); otherwise a bare 'FAILED
## (rc=N)' note. Previously the screenshot sentence was unconditional, so a run that
## captured no screenshot still told the results plane to "see the published
## screenshot" -- a false diagnostic. Extracts the REAL on_exit from the shipped
## script (no copy) and drives it; vm_started=false so no VBox call is made.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

subject="${DM_CALAMARES_INSTALL_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -f "${test_dir}/../../bin/dm-calamares-install" ]; then
      subject="${test_dir}/../../bin/dm-calamares-install"
   else
      subject='/usr/bin/dm-calamares-install'
   fi
fi
[ -r "${subject}" ] || { printf 'FATAL: dm-calamares-install not found at %s\n' "${subject}" >&2; exit 1; }

## Extract the real on_exit() -- header to its first column-0 '}'.
on_exit_src="$(awk '
   /^on_exit\(\) \{/ { f = 1 }
   f               { print }
   f && /^\}$/     { exit }
' "${subject}")"
if [ -z "${on_exit_src}" ]; then
   printf '%s\n' 'FATAL: could not extract on_exit() from dm-calamares-install' >&2
   exit 1
fi
eval "${on_exit_src}"

workdir="$(mktemp --directory --tmpdir calamares-on-exit-test.XXXXXX)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

pass=0
fail=0
check() {
   local label got want
   label="$1"
   got="$2"
   want="$3"
   if [ "${got}" = "${want}" ]; then
      printf 'PASS: %s\n' "${label}"
      pass=$((pass + 1))
   else
      printf 'FAIL: %s (got %s, want %s)\n' "${label}" "${got}" "${want}"
      fail=$((fail + 1))
   fi
}

## Drive the real on_exit with a simulated exit rc, a given shot path, and whether a
## stuck screenshot exists; print the resulting check-log, classified: 'shot-note'
## (points at a screenshot), 'generic' (bare FAILED), or 'empty' (nothing written).
run_on_exit() {
   local rc="$1" shot_arg="$2" want_stuck="$3"
   local run_home="${workdir}/home.$$.${RANDOM}"
   local clog="${workdir}/clog.$$.${RANDOM}"
   mkdir --parents -- "${run_home}"
   touch -- "${clog}"
   if [ "${want_stuck}" = yes ]; then
      printf 'STUCK-SCREENSHOT-BYTES' > "${run_home}/dm-calamares-install-stuck.png"
   fi
   ## on_exit reads these as globals via dynamic scope -- shellcheck cannot see the
   ## use through the eval'd function, hence SC2034. The subshell inherits them and
   ## on_exit's final 'exit' terminates only that subshell.
   # shellcheck disable=SC2034
   local me='dm-calamares-install' shot="${shot_arg}" check_log="${clog}" \
      vm_started='false' VBOXMANAGE=':' HOME="${run_home}"
   (
      ## Set $? to the simulated run rc that on_exit reads as 'local rc=$?'.
      ( exit "${rc}" )
      on_exit
   ) >/dev/null 2>&1 || true
   local out
   out="$(cat -- "${clog}")"
   case "${out}" in
      '')
         printf 'empty'
         ;;
      *'see the published screenshot'*)
         printf 'shot-note'
         ;;
      *FAILED*)
         printf 'generic'
         ;;
      *)
         printf 'other:%s' "${out}"
         ;;
   esac
}

## 1. A real screenshot WAS published (stuck copied into the empty shot) -> the note
##    may point at it.
shot_a="${workdir}/shot_a.png"
touch -- "${shot_a}"
check "published screenshot -> note points at it" "$(run_on_exit 5 "${shot_a}" yes)" 'shot-note'

## 2. A shot path was given but NO screenshot captured (no stuck) -> generic note,
##    never 'see the published screenshot'. (Canary: the pre-fix note was unconditional.)
shot_b="${workdir}/shot_b.png"
touch -- "${shot_b}"
check "shot path but none captured -> generic note" "$(run_on_exit 5 "${shot_b}" no)" 'generic'

## 3. No --shot at all -> generic note, no screenshot text.
check "no shot configured -> generic note" "$(run_on_exit 5 '' no)" 'generic'

## 4. A successful run writes no failure note at all.
check "rc 0 writes no note" "$(run_on_exit 0 '' no)" 'empty'

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
