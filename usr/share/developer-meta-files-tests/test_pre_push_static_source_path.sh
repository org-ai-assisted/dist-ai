#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test for pre-push-static's shellcheck invocation: assert that a
## '# shellcheck source=' path written RELATIVE TO THE SCRIPT resolves no matter
## which directory the gate is run from.
##
## THE BUG: shellcheck resolves such a path relative to the CURRENT WORKING
## DIRECTORY unless given --source-path=SCRIPTDIR. Every directive in these
## repos is script-relative -- helper-scripts' usr/bin/gpg-dearmor carries
## 'source=../libexec/helper-scripts/has.sh', correct from usr/bin/ -- so
## running the gate from the repo root made them resolve OUTSIDE the repo and
## report SC1091 "does not exist", and every variable the sourced file defines
## then looked unassigned (SC2154).
##
## The fixture reproduces exactly that layout: a script in bin/ sourcing a
## helper in lib/ via '../lib/helper.sh', with the gate run from the repo root.
## It drives the real, shipped gate as a subprocess, not a private copy of the
## invocation.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

## shellcheck is a HARD PREREQUISITE, not an optional nicety. pre-push-static
## SKIPS its entire shellcheck tier and returns SUCCESS when shellcheck is
## absent -- so without this every assertion below would pass while never
## exercising --source-path at all. A skipped check is a failure, not a pass.
if ! test -r /usr/libexec/helper-scripts/has.sh ; then
   printf '%s\n' "FATAL: helper-scripts has.sh is not installed (/usr/libexec/helper-scripts/has.sh)" >&2
   exit 1
fi
# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.sh
# shellcheck disable=SC1091
source /usr/libexec/helper-scripts/has.sh

if ! has shellcheck ; then
   printf '%s\n' "FATAL: shellcheck not on PATH (apt-get install shellcheck)" >&2
   printf '%s\n' "This test cannot validate --source-path without it." >&2
   exit 1
fi

if ! has safe-rm ; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi

## Resolve the gate RELATIVE to this test file (usr/share/<suite>/ -> usr/bin/),
## exactly as test_pre_push_static_style_rules.sh does. A bare 'pre-push-static'
## takes whatever is on PATH -- the INSTALLED copy -- so a developer editing the
## in-tree gate would be testing the packaged one and every assertion would
## report on code they did not change.
gate_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
GATE="${gate_test_dir}/../../bin/pre-push-static"
if [ ! -x "${GATE}" ]; then
   GATE='/usr/bin/pre-push-static'
fi

base_sha=""
test_dir="$(mktemp --directory)"
cleanup() {
   safe-rm -r -f -- "${test_dir}"
}
trap cleanup EXIT

repo="${test_dir}/repo"
mkdir --parents -- "${repo}/bin" "${repo}/lib"

## The sourced helper defines a variable the caller reads, so a failure to
## follow it shows up as SC2154 as well as SC1091.
cat >"${repo}/lib/helper.sh" <<'HELPER'
#!/bin/bash

## style-ok: no-strict
##
## Sourced, never executed -- a strict-mode block here would rewrite the
## CALLER's shell. This mirrors how the real sourced helpers in these repos are
## written, so the fixture passes the gate for the same reasons they do.

## Read by the caller, not by this file.
# shellcheck disable=SC2034
helper_value="set-by-helper"
HELPER

## Script-relative source= path: correct from bin/, wrong from the repo root.
cat >"${repo}/bin/caller" <<'CALLER'
#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

# shellcheck source=../lib/helper.sh
source "${0%/*}"/../lib/helper.sh

printf '%s\n' "${helper_value}"
CALLER
chmod 0755 -- "${repo}/bin/caller" "${repo}/lib/helper.sh"

## 'core.hooksPath=/dev/null': this fixture is not testing the operator's hooks.
git -c init.defaultBranch=master -c core.hooksPath=/dev/null init --quiet -- "${repo}"

## An EMPTY first commit gives the gate a base ref to diff against. Without one
## it fails on "cannot resolve base ref '@{u}'" -- the fixture has no upstream --
## and the shellcheck step never runs at all.
git -C "${repo}" -c core.hooksPath=/dev/null \
   -c user.name=test -c user.email=test@example.com \
   commit --quiet --allow-empty --message "base"
base_sha="$(git -C "${repo}" rev-parse HEAD)"

git -C "${repo}" -c core.hooksPath=/dev/null add --all
git -C "${repo}" -c core.hooksPath=/dev/null \
   -c user.name=test -c user.email=test@example.com \
   commit --quiet --message "fixture"

## Run the REAL gate from the repo ROOT -- the directory that made the
## script-relative path resolve outside the repo.
gate_output=""
gate_rc=0
gate_output="$( cd -- "${repo}" && "${GATE}" "${base_sha}" 2>&1 )" || gate_rc=$?

fail=0

if printf '%s\n' "${gate_output}" | grep --quiet --fixed-strings 'SC1091'; then
   printf '%s\n' "FAIL: SC1091 -- the script-relative source= path did not resolve"
   printf '%s\n' "${gate_output}" | grep --fixed-strings 'SC1091' | head -2
   fail=1
else
   printf '%s\n' "PASS: script-relative source= resolves from the repo root"
fi

if printf '%s\n' "${gate_output}" | grep --quiet --fixed-strings 'SC2154'; then
   printf '%s\n' "FAIL: SC2154 -- the sourced assignment was not seen"
   printf '%s\n' "${gate_output}" | grep --fixed-strings 'SC2154' | head -2
   fail=1
else
   printf '%s\n' "PASS: the variable the sourced helper defines is seen as assigned"
fi

## The fixture is otherwise compliant, so the gate must be green overall. This
## catches the case where the two greps pass because the gate never ran the
## shellcheck step at all.
if [ "${gate_rc}" -ne 0 ]; then
   printf '%s\n' "FAIL: the gate did not pass on a compliant fixture (rc=${gate_rc})"
   printf '%s\n' "${gate_output}" | tail -5
   fail=1
else
   printf '%s\n' "PASS: gate green on the compliant fixture"
fi

## Belt and braces: if the gate reports the shellcheck tier skipped for ANY
## reason, the three assertions above are meaningless.
if printf '%s\n' "${gate_output}" | grep --quiet --fixed-strings 'shellcheck not on PATH'; then
   printf '%s\n' "FAIL: the gate SKIPPED its shellcheck tier -- nothing was tested"
   fail=1
fi

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "" "FAILED"
   exit 1
fi
printf '%s\n' "" "OK"
