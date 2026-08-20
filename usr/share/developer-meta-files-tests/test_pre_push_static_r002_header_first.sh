#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for R-002 (header first): pre-push-static FLAGS a file whose
## '## style-ok:' waiver sits ABOVE the '## Copyright' line, and SPARES a file
## whose waiver is below the header, a file with no waiver, and a file with a
## waiver but no Copyright line (the rule only fires when both lines exist).
##
## A flagged fixture must make the gate EXIT NON-ZERO (enforcement, not just a
## diagnostic); a spared fixture must leave the gate GREEN (so a crash cannot
## masquerade as 'spared').
##
## The waiver token is assembled from fragments so no real '## style-ok:' comment
## line appears at column 0 in THIS tracked file (the gate scans it too).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

if ! test -r /usr/libexec/helper-scripts/has.sh ; then
   printf '%s\n' "FATAL: helper-scripts has.sh is not installed" >&2
   exit 1
fi
# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.sh
# shellcheck disable=SC1091
source /usr/libexec/helper-scripts/has.sh

if ! has safe-rm ; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi
if ! has git ; then
   printf '%s\n' "FATAL: git not on PATH" >&2
   exit 1
fi

tool_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
GATE="${tool_dir}/../../bin/pre-push-static"
if [ ! -x "${GATE}" ]; then
   GATE='/usr/bin/pre-push-static'
fi

test_dir="$(mktemp --directory)"
cleanup_handler() {
   safe-rm -r -f -- "${test_dir}"
}
trap cleanup_handler EXIT

pass=0
fail=0

## Assemble the waiver so no literal '## style-ok:' comment line is in this file.
hh='##'
so="${hh} style-ok: no-strict"
copy="${hh} Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>"
lic="${hh} See the file COPYING for copying conditions."

strict=(
   'set -o errexit'
   'set -o nounset'
   'set -o pipefail'
   'set -o errtrace'
   'shopt -s inherit_errexit'
   'shopt -s shift_verbose'
)

## Builds a one-file repo around a script body; sets gate_output and gate_rc.
run_gate_on_body() {
   local name body repo base_sha
   name="$1"
   body="$2"
   repo="${test_dir}/gate-${name}"
   mkdir --parents -- "${repo}/usr/bin"
   printf '%s\n' "${body}" >"${repo}/usr/bin/subject"
   chmod 0755 -- "${repo}/usr/bin/subject"
   git -c init.defaultBranch=master -c core.hooksPath=/dev/null init --quiet -- "${repo}"
   git -C "${repo}" -c core.hooksPath=/dev/null \
      -c user.name=test -c user.email=test@example.com \
      commit --quiet --allow-empty --message "base"
   base_sha="$(git -C "${repo}" rev-parse HEAD)"
   git -C "${repo}" -c core.hooksPath=/dev/null add --all
   git -C "${repo}" -c core.hooksPath=/dev/null \
      -c user.name=test -c user.email=test@example.com \
      commit --quiet --message "fixture"
   gate_rc=0
   gate_output="$( cd -- "${repo}" && "${GATE}" "${base_sha}" 2>&1 )" || gate_rc=$?
}

## R-002 must appear AND the gate must reject (non-zero).
assert_flagged() {
   run_gate_on_body "$1" "$2"
   if grep --fixed-strings -- "R-002" <<< "${gate_output}" >/dev/null \
      && [ "${gate_rc}" -ne 0 ]; then
      printf '%s\n' "PASS: R-002 rejected $1"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: R-002 did not reject $1 (rc=${gate_rc})"
      printf '%s\n' "${gate_output}" | tail -5
      fail=$((fail + 1))
   fi
}

## R-002 must NOT appear AND the gate must be green (a crash cannot pass here).
assert_spared() {
   run_gate_on_body "$1" "$2"
   if grep --fixed-strings -- "R-002" <<< "${gate_output}" >/dev/null; then
      printf '%s\n' "FAIL: R-002 wrongly flagged $1"
      printf '%s\n' "${gate_output}" | grep --fixed-strings -- 'R-002' | head -2
      fail=$((fail + 1))
   elif [ "${gate_rc}" -ne 0 ]; then
      printf '%s\n' "FAIL: gate not green on spared fixture $1 (rc=${gate_rc})"
      printf '%s\n' "${gate_output}" | tail -5
      fail=$((fail + 1))
   else
      printf '%s\n' "PASS: R-002 spared $1"
      pass=$((pass + 1))
   fi
}

## Waiver ABOVE the Copyright header -> flagged, gate rejects.
assert_flagged "above" \
   "$(printf '%s\n' '#!/bin/bash' '' "${so}" "${copy}" "${lic}" '' 'true')"

## Waiver BELOW the header (with the waiver exempting the strict block) -> spared.
assert_spared "below" \
   "$(printf '%s\n' '#!/bin/bash' '' "${copy}" "${lic}" '' "${so}" '' 'true')"

## No waiver, a real strict block -> spared.
assert_spared "no-waiver" \
   "$(printf '%s\n' '#!/bin/bash' '' "${copy}" "${lic}" '' "${strict[@]}" '' 'true')"

## Waiver but no Copyright line -> spared (rule needs both).
assert_spared "no-copyright" \
   "$(printf '%s\n' '#!/bin/bash' '' "${so}" '' 'true')"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
