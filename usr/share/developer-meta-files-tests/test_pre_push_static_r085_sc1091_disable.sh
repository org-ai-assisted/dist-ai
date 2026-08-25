#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for pre-push-static's R-085: a '# shellcheck disable=SC1091'
## paired with an adjacent '# shellcheck source=' directive is flagged (ADVISORY)
## because the reusable gate's helper-scripts sibling checkout makes shellcheck
## FOLLOW the source= directive, leaving the disable dead. Asserts the rule
## fires, that '## style-ok: allow-sc1091-disable' waives it, that a file with no
## disable is not flagged, that a disable with NO adjacent source= directive
## (an unfollowable runtime source) is not flagged, and that being advisory it
## never turns the gate red.
##
## Drives the real, shipped gate as a subprocess, not a private copy.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if ! test -r /usr/libexec/helper-scripts/has.sh ; then
   printf '%s\n' "FATAL: helper-scripts has.sh is not installed (/usr/libexec/helper-scripts/has.sh)" >&2
   exit 1
fi
# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.sh
source "${HELPER_SCRIPTS_PATH:-}"/usr/libexec/helper-scripts/has.sh

if ! has safe-rm ; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi

gate_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
GATE="${gate_test_dir}/../../bin/pre-push-static"
if [ ! -x "${GATE}" ]; then
   GATE='/usr/bin/pre-push-static'
fi

test_dir="$(mktemp --directory)"
cleanup() {
   safe-rm -r -f -- "${test_dir}"
}
trap cleanup EXIT

repo="${test_dir}/repo"
mkdir --parents -- "${repo}/bin"

## The sibling the source= directive resolves to, so shellcheck follows it and
## SC1091 never fires -- exactly the situation that makes the disable dead.
cat >"${repo}/bin/helper.sh" <<'HELPER'
#!/bin/bash

## style-ok: no-strict
##
## Sourced, never executed.

# shellcheck disable=SC2034
helper_value="set-by-helper"
HELPER

## Case FLAGGED: carries the dead disable.
cat >"${repo}/bin/flagged" <<'FLAGGED'
#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

# shellcheck source=./helper.sh
# shellcheck disable=SC1091
source "${0%/*}"/helper.sh

printf '%s\n' "${helper_value}"
FLAGGED

## Case WAIVED: same disable, plus the documented waiver.
cat >"${repo}/bin/waived" <<'WAIVED'
#!/bin/bash

## style-ok: allow-sc1091-disable

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

# shellcheck source=./helper.sh
# shellcheck disable=SC1091
source "${0%/*}"/helper.sh

printf '%s\n' "${helper_value}"
WAIVED

## Case CLEAN: no disable at all.
cat >"${repo}/bin/clean" <<'CLEAN'
#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

# shellcheck source=./helper.sh
source "${0%/*}"/helper.sh

printf '%s\n' "${helper_value}"
CLEAN

## Case UNFOLLOWABLE: a disable with NO adjacent source= directive. The source is
## a runtime path shellcheck can never follow, so the disable is load-bearing and
## must NOT be flagged. Regression: the old rule flagged every SC1091 disable
## regardless of an accompanying source= directive.
cat >"${repo}/bin/unfollowable" <<'UNFOLLOWABLE'
#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

runtime_file="${0%/*}/helper.sh"
# shellcheck disable=SC1090,SC1091
source "${runtime_file}"
UNFOLLOWABLE

chmod 0755 -- "${repo}/bin/helper.sh" "${repo}/bin/flagged" \
   "${repo}/bin/waived" "${repo}/bin/clean" "${repo}/bin/unfollowable"

git -c init.defaultBranch=master -c core.hooksPath=/dev/null init --quiet -- "${repo}"
git -C "${repo}" -c core.hooksPath=/dev/null \
   -c user.name=test -c user.email=test@example.com \
   commit --quiet --allow-empty --message "base"
base_sha="$(git -C "${repo}" rev-parse HEAD)"
git -C "${repo}" -c core.hooksPath=/dev/null add --all
git -C "${repo}" -c core.hooksPath=/dev/null \
   -c user.name=test -c user.email=test@example.com \
   commit --quiet --message "fixture"

gate_output=""
gate_rc=0
gate_output="$( cd -- "${repo}" && "${GATE}" "${base_sha}" 2>&1 )" || gate_rc=$?

fail=0

## Bind every assertion to the R-085 diagnostic RECORD, not to the whole gate
## output: the note prints '<path>:<lineno>:# shellcheck disable=...SC1091...'
## hit lines, and no other check emits an SC1091 disable token, so an unrelated
## rule that merely names one of these paths cannot satisfy or break a check
## vacuously. Match SC1091 as a token (the rule's own regex), not the literal
## 'disable=SC1091' -- a hit line may carry other codes ('disable=SC1090,SC1091')
## that the fixed-string form silently misses (a dead assertion).
r085_hits="$(printf '%s\n' "${gate_output}" \
   | grep --extended-regexp 'disable=([A-Z0-9]+,)*SC1091([,[:space:]]|$)' || true)"

## The rule fires for the flagged file (canary: 0 hits = 0 coverage).
if [[ "${gate_output}" == *"R-085"* ]] && [[ "${r085_hits}" == *"bin/flagged"* ]]; then
   printf '%s\n' "PASS: R-085 flags the file carrying the dead disable"
else
   printf '%s\n' "FAIL: R-085 did not flag bin/flagged"
   printf '%s\n' "${gate_output}"
   fail=1
fi

## The waiver silences it: no R-085 record for bin/waived.
if [[ "${r085_hits}" == *"bin/waived"* ]]; then
   printf '%s\n' "FAIL: '## style-ok: allow-sc1091-disable' did not waive R-085 on bin/waived"
   fail=1
else
   printf '%s\n' "PASS: the waiver silences R-085"
fi

## The clean file is not flagged (no false positive): no R-085 record for it.
if [[ "${r085_hits}" == *"bin/clean"* ]]; then
   printf '%s\n' "FAIL: R-085 falsely flagged bin/clean (no disable present)"
   fail=1
else
   printf '%s\n' "PASS: R-085 does not flag a file with no SC1091 disable"
fi

## The unfollowable file is not flagged: a disable with no adjacent source=
## directive is load-bearing, not dead. Regression for the FP that flagged every
## SC1091 disable.
if [[ "${r085_hits}" == *"bin/unfollowable"* ]]; then
   printf '%s\n' "FAIL: R-085 falsely flagged bin/unfollowable (disable has no adjacent source= directive)"
   fail=1
else
   printf '%s\n' "PASS: R-085 does not flag a disable lacking an adjacent source= directive"
fi

## Advisory: the disable being present must NOT turn the gate red.
if [ "${gate_rc}" -ne 0 ]; then
   printf '%s\n' "FAIL: the gate went red -- R-085 must be advisory (rc=${gate_rc})"
   printf '%s\n' "${gate_output}" | tail -8
   fail=1
else
   printf '%s\n' "PASS: gate stays green -- R-085 is advisory"
fi

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "" "FAILED"
   exit 1
fi
printf '%s\n' "" "OK"
