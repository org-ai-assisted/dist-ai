#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for R-002 (header first): pre-push-static FLAGS a file whose
## '## style-ok:' waiver sits ABOVE the '## Copyright' line, and SPARES a file
## whose waiver is below the header, a file with no waiver, and a file with a
## waiver but no Copyright line (the rule only fires when both lines exist).
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
   printf '%s\n' "SKIP: helper-scripts has.sh is not installed" >&2
   exit 77
fi
# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.sh
# shellcheck disable=SC1091
source /usr/libexec/helper-scripts/has.sh

if ! has safe-rm ; then
   printf '%s\n' "SKIP: safe-rm not on PATH" >&2
   exit 77
fi
if ! has git ; then
   printf '%s\n' "SKIP: git not on PATH" >&2
   exit 77
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

fail=0

## Assemble the waiver so no literal '## style-ok:' comment line is in this file.
hh='##'
so="${hh} style-ok: no-strict"
copy="${hh} Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>"
lic="${hh} See the file COPYING for copying conditions."

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

## assert_flagged <name> <body> -- R-002 must appear.
assert_flagged() {
   run_gate_on_body "$1" "$2"
   if grep --fixed-strings -- "R-002" <<< "${gate_output}" >/dev/null; then
      printf '%s\n' "PASS: R-002 flagged $1"
   else
      printf '%s\n' "FAIL: R-002 did NOT flag $1"
      printf '%s\n' "${gate_output}" | tail -5
      fail=1
   fi
}

## assert_not_flagged <name> <body> -- R-002 must NOT appear (green not required,
## so an unrelated fixture stays valid input without over-constraining it).
assert_not_flagged() {
   run_gate_on_body "$1" "$2"
   if grep --fixed-strings -- "R-002" <<< "${gate_output}" >/dev/null; then
      printf '%s\n' "FAIL: R-002 wrongly flagged $1"
      printf '%s\n' "${gate_output}" | grep --fixed-strings -- 'R-002' | head -2
      fail=1
   else
      printf '%s\n' "PASS: R-002 spared $1"
   fi
}

## Waiver ABOVE the Copyright header -> flagged.
assert_flagged "above" \
   "$(printf '%s\n' '#!/bin/bash' '' "${so}" "${copy}" "${lic}" '' 'true')"

## Waiver BELOW the header -> spared.
assert_not_flagged "below" \
   "$(printf '%s\n' '#!/bin/bash' '' "${copy}" "${lic}" '' "${so}" '' 'true')"

## No waiver at all -> spared.
assert_not_flagged "no-waiver" \
   "$(printf '%s\n' '#!/bin/bash' '' "${copy}" "${lic}" '' 'true')"

## Waiver but no Copyright line -> spared (rule needs both).
assert_not_flagged "no-copyright" \
   "$(printf '%s\n' '#!/bin/bash' '' "${so}" '' 'true')"

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "" "FAILED"
   exit 1
fi
printf '%s\n' "" "OK"
