#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'build-steps.d/1100_sanity-tests'
## 'check-redistributable-builds-requirements()': the UPLOAD credential ('~/.ssh')
## and the SIGNING credential ('~/.signify') are INDEPENDENT axes.
##
##   - '~/.ssh' is required ONLY for a real upload ('--upload true'); the default
##     simulates the upload (rsync mocked in 'variables.d/35_rsync.bsh'), so a
##     redistributable build needs NO '~/.ssh'.
##   - '~/.signify' (+ '~/buildconfig.d') is ALWAYS required for a real
##     redistributable build (not CI, not dry-run), because signing keys are not
##     auto-generated for redistributable builds.
##
## Canary: fails on the pre-change code, which required '~/.ssh' for every
## redistributable build regardless of upload.
##
## The REAL function is SOURCED (was_executed gates 1100 main(); its top-level
## pre/variables run with the build args supplied below). Needs no root, no build.

# shellcheck disable=SC2034
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

dm_checkout="${DERIVATIVE_MAKER_DIR:-${HOME}/derivative-maker}"
subject="${DM_SANITY_TESTS:-${dm_checkout}/build-steps.d/1100_sanity-tests}"
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FAIL: cannot read ${subject}" >&2
   exit 1
fi

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*"; }

## Source the real build step WITHOUT running it (was_executed is false when
## sourced). 1100 sources help-steps/pre + variables at top level; feed them what
## a real build step gets. CI=true only to satisfy variables at SOURCE time -- it
## is cleared below, because the function early-returns on CI.
export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH:-${dm_checkout}/packages/kicksecure/helper-scripts}"
export CI=true dist_build_unlock_dangerous_options=true dist_build_allow_root=true
export user_name="${SUDO_USER:-user}"
set -- --repo true --arch amd64 --tb closed --freedom false --freshness frozen --target iso --flavor kicksecure-lxqt
# shellcheck disable=SC1090
source "${subject}" >/dev/null
## pre installs strict-mode traps for the build; this harness keeps control itself.
trap - ERR EXIT INT TERM HUP
set +o xtrace
set --
if [ "$(type -t check-redistributable-builds-requirements)" != "function" ]; then
   printf '%s\n' "FAIL: sourcing 1100 did not expose check-redistributable-builds-requirements (source-able broken?)" >&2
   exit 1
fi

## Real redistributable build: NOT ci, NOT dry-run, so the folder checks run.
CI=""
build_dry_run=""
dist_build_redistributable=true

## Message sinks (print so the capturing subshell sees them). 'error' aborts 42.
# shellcheck disable=SC2317
true() { printf '%s\n' "$*"; }
# shellcheck disable=SC2317
error() { printf '%s\n' "ERROR: $*"; exit 42; }
export reset="" bold="" red="" cyan=""

workdir=""
cleanup() {
   [ -z "${workdir}" ] || safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT
workdir="$(mktemp --directory)"

## make_home <name> <subdir...> : a fixture HOME containing exactly the named dirs.
make_home() {
   local name="$1"; shift
   local h="${workdir}/${name}" d
   mkdir --parents -- "${h}"
   for d in "$@"; do
      mkdir --parents -- "${h}/${d}"
   done
   printf '%s\n' "${h}"
}

## run_req <HOME> <dist_build_upload> : run the function in a subshell (so its
## error()/exit is contained); capture rc in CAP_RC, output in CAP.
run_req() {
   local home_dir="$1" upload="$2" remote="${3:-}"
   if CAP="$( HOME="${home_dir}" dist_build_upload="${upload}" build_remote_derivative_pkgs="${remote}" check-redistributable-builds-requirements 2>&1 )"; then
      CAP_RC=0
   else
      CAP_RC=$?
   fi
}

## --- CANARY: credential-less default (no --upload): no ~/.ssh needed ---------
home_no_ssh="$(make_home no-ssh buildconfig.d .signify)"
run_req "${home_no_ssh}" ""
if [ "${CAP_RC}" -eq 0 ]; then
   pass "default (no --upload), .signify + buildconfig.d present, NO .ssh: passes (upload simulated)"
else
   fail "canary: default build wrongly required ~/.ssh (rc=${CAP_RC}) -- ${CAP}"
fi

## --- real upload (--upload true) with no ~/.ssh: must abort ------------------
run_req "${home_no_ssh}" "true"
if [ "${CAP_RC}" -eq 42 ] && grep --quiet '\.ssh' <<< "${CAP}"; then
   pass "--upload true with NO .ssh: aborts (real upload needs the credential)"
else
   fail "--upload true with no .ssh did not abort on ~/.ssh (rc=${CAP_RC}) -- ${CAP}"
fi

## --- signing axis independent: no .signify always aborts --------------------
home_no_signify="$(make_home no-signify buildconfig.d .ssh)"
run_req "${home_no_signify}" ""
if [ "${CAP_RC}" -eq 42 ] && grep --quiet '\.signify' <<< "${CAP}"; then
   pass "no .signify (default): aborts (signing credential is an independent axis)"
else
   fail "missing .signify did not abort (rc=${CAP_RC}) -- the signing axis regressed -- ${CAP}"
fi

## --- real upload with all three present passes ------------------------------
home_all="$(make_home all buildconfig.d .ssh .signify)"
run_req "${home_all}" "true"
if [ "${CAP_RC}" -eq 0 ]; then
   pass "--upload true with .ssh + .signify + buildconfig.d: passes"
else
   fail "--upload true with all credentials present wrongly aborted (rc=${CAP_RC}) -- ${CAP}"
fi

## --- remote-derivative-packages never uploads: ~/.ssh not required even with ---
## --- --upload true (opaque prebuilt packages are not publishable). ------------
run_req "${home_no_ssh}" "true" "true"
if [ "${CAP_RC}" -eq 0 ]; then
   pass "--upload true + build_remote_derivative_pkgs=true, NO .ssh: passes (remote build never uploads)"
else
   fail "--upload true + remote pkgs wrongly required ~/.ssh (rc=${CAP_RC}) -- ${CAP}"
fi

if [ "${fail_count}" -ne 0 ]; then
   printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip" >&2
   exit 1
fi
printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
