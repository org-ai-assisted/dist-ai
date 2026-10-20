#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guards help-steps/determine-build-user.bsh (sourced by variables.d/00_preamble.bsh),
## which picks the build user whose $HOME is the output tree (binary_build_folder_dist).
##
## The regression it locks: a NON-ROOT launch MUST resolve to the EFFECTIVE user, NOT
## SUDO_USER / logname. Preferring SUDO_USER unconditionally (the old inline logic) sent
## a `sudo -u admin` build to the CALLER's home (/home/debian) -> `mkdir: Permission
## denied` at signing-key-create. Only a ROOT build recovers the invoker via
## SUDO_USER then logname.
##
## Self-contained: sources only the fragment (side-effect-free by contract), then calls
## the function with a per-call env + the optional euid arg. No root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

frag_rel='help-steps/determine-build-user.bsh'
frag=""
candidates=()
[ -z "${DERIVATIVE_MAKER_DIR:-}" ] || candidates+=( "${DERIVATIVE_MAKER_DIR}/${frag_rel}" )
candidates+=( "${dm_checkout}/${frag_rel}" )
candidates+=( "/${frag_rel}" )
for candidate in "${candidates[@]}"; do
   if [ -r "${candidate}" ]; then
      frag="${candidate}"
      break
   fi
done
if [ -z "${frag}" ]; then
   printf '%s\n' "FATAL: help-steps/determine-build-user.bsh not found (set DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi

mock_dir=""
cleanup() {
   [ -z "${mock_dir}" ] || safe-rm --recursive --force -- "${mock_dir}"
}
trap cleanup EXIT

pass_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
test_failures=0
fail() { test_failures=$((test_failures + 1)); printf '%s\n' "FAIL: $*" >&2; }

## Side-effect-free by contract, so sourcing in-process (then calling in a subshell with
## a per-call env) is safe and keeps the REAL fragment under test.
# shellcheck disable=SC1090  # path resolved at runtime
source "${frag}"

me="$(id --user --name)"

## 1. NON-ROOT: the effective user wins; SUDO_USER is IGNORED (the core regression).
got="$( SUDO_USER=ghost-caller determine_build_user 1000 )"
if [ "${got}" = "${me}" ]; then
   pass "non-root resolves to the effective user (${me}), SUDO_USER ignored"
else
   fail "non-root resolved to '${got}', wanted the effective user '${me}' (SUDO_USER must NOT win)"
fi

## 2. ROOT + SUDO_USER: recover the invoking user.
got="$( SUDO_USER=ghost-caller determine_build_user 0 )"
if [ "${got}" = "ghost-caller" ]; then
   pass "root recovers the invoking user via SUDO_USER"
else
   fail "root resolved to '${got}', wanted SUDO_USER 'ghost-caller'"
fi

## 3. ROOT + no SUDO_USER: fall back to logname (mocked on PATH).
mock_dir="$(mktemp --directory --tmpdir determine-build-user-test.XXXXXX)"
printf '%s\n' '#!/bin/bash' 'printf "%s\n" login-user' > "${mock_dir}/logname"
chmod +x "${mock_dir}/logname"
got="$( unset SUDO_USER; PATH="${mock_dir}:${PATH}"; determine_build_user 0 )"
if [ "${got}" = "login-user" ]; then
   pass "root with no SUDO_USER falls back to logname"
else
   fail "root+no-SUDO_USER resolved to '${got}', wanted logname 'login-user'"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: determine_build_user (${pass_count} assertions)."
