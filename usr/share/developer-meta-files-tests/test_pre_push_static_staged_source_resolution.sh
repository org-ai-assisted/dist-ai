#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Functional test: staged/committed-blob shellcheck must resolve an intra-repo
## '# shellcheck source=' the SAME as an on-disk check.
##
## A blob (--staged / --range) is materialized to a /tmp temp file, so shellcheck's
## SCRIPTDIR is /tmp and a project '.shellcheckrc' entry 'source-path=SCRIPTDIR/..'
## used to miss the real sibling -- SC1091 (unfollowable source) plus SC2034 (a var
## the installer sets but that is used only INSIDE the un-followed lib) fired in
## staged/range mode while the identical file is clean IN PLACE. That drove sessions
## to add load-bearing SC1091/SC2034 disables that R-085 (working-tree mode) then
## calls "dead" -- a contradiction. external.py now re-anchors the materialized rc's
## SCRIPTDIR source-paths to the real dir, so the source resolves and neither code
## fires. Asserts NO SC1091/SC2034 for the sourcing installer, and a green gate.
##
## Drives the real, shipped gate as a subprocess, not a private copy.
## CANARY: run with GATE=/usr/bin/dist-ai-style (a pre-fix installed copy) -- SC1091
## and SC2034 fire there, failing this test.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if ! test -r /usr/libexec/helper-scripts/has.bsh ; then
   printf '%s\n' "FATAL: helper-scripts has.bsh is not installed (/usr/libexec/helper-scripts/has.bsh)" >&2
   exit 1
fi
# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.bsh
source "${HELPER_SCRIPTS_PATH:-}"/usr/libexec/helper-scripts/has.bsh

if ! has safe-rm ; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi
if ! has shellcheck ; then
   printf '%s\n' "FATAL: shellcheck not on PATH" >&2
   exit 1
fi

gate_test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
GATE="${GATE:-${gate_test_dir}/../../bin/dist-ai-style}"
if [ ! -x "${GATE}" ]; then
   GATE='/usr/bin/dist-ai-style'
fi

test_dir="$(mktemp --directory)"
cleanup() {
   safe-rm -r -f -- "${test_dir}"
}
trap cleanup EXIT

repo="${test_dir}/repo"
mkdir --parents -- "${repo}/usr/bin" "${repo}/usr/libexec/private-ai-config"

## The project rc: locate the sourced lib via a SCRIPTDIR-relative source-path, as
## private-ai-config's own rc does.
cat >"${repo}/.shellcheckrc" <<'RC'
external-sources=true
source-path=SCRIPTDIR/../libexec/private-ai-config
RC

## The intra-repo sourced lib: defines a function that consumes the caller-contract
## var the installer sets -- so resolving the source is what makes that var "used".
cat >"${repo}/usr/libexec/private-ai-config/vt-gate.sh" <<'LIB'
#!/bin/bash

## style-ok: no-strict
##
## Sourced, never executed.
# shellcheck shell=bash

## Caller-contract var with a fail-closed default set at source time (so the lib is
## clean standalone: assigned here, consumed in gate_run) -- mirrors vt-gate.sh's real
## '[ -v do_vt ] || do_vt=...' contract.
[ -v gate_fallback ] || gate_fallback="the pinned sha256"

gate_run() {
   printf '%s\n' "${gate_fallback}"
}
LIB

## The installer: sources the lib by a source= directive and sets the contract var.
## NO SC1091 / SC2034 disable -- the whole point is that staged resolution makes them
## unnecessary.
cat >"${repo}/usr/bin/installer" <<'INSTALLER'
#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

self_dir="$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")"
# shellcheck source=./vt-gate.sh
source "${self_dir}/../libexec/private-ai-config/vt-gate.sh"

gate_fallback="the pinned sha256"
gate_run
INSTALLER

chmod 0755 -- "${repo}/usr/bin/installer" "${repo}/usr/libexec/private-ai-config/vt-gate.sh"

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
gate_output="$( cd -- "${repo}" && "${GATE}" --check --range "${base_sha}" 2>&1 )" || gate_rc=$?

fail=0

## The sourced lib resolves in blob mode -> SC1091 does NOT fire on the installer.
if grep --quiet --extended-regexp 'SC1091' <<< "${gate_output}"; then
   printf '%s\n' "FAIL: SC1091 fired -- the intra-repo source= did not resolve in staged/blob mode"
   grep --extended-regexp 'SC1091|installer' <<< "${gate_output}" | head
   fail=1
else
   printf '%s\n' "PASS: no SC1091 -- the intra-repo source= resolves in staged/blob mode"
fi

## The contract var is seen used inside the resolved lib -> SC2034 does NOT fire.
if grep --quiet --extended-regexp 'SC2034' <<< "${gate_output}"; then
   printf '%s\n' "FAIL: SC2034 fired -- a var used only in the sourced lib read as unused"
   grep --extended-regexp 'SC2034|gate_fallback' <<< "${gate_output}" | head
   fail=1
else
   printf '%s\n' "PASS: no SC2034 -- a var used in the resolved lib is seen as used"
fi

## And the gate is green (a clean sourcing installer must pass the staged check with
## no disable at all).
if [ "${gate_rc}" -ne 0 ]; then
   printf '%s\n' "FAIL: gate went red (rc=${gate_rc}) on a clean sourcing installer"
   printf '%s\n' "${gate_output}" | tail -12
   fail=1
else
   printf '%s\n' "PASS: gate stays green on a clean sourcing installer"
fi

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "" "FAILED"
   exit 1
fi
printf '%s\n' "" "OK"
