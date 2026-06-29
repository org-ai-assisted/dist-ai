#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit test for open-link-confirmation's source_config() precedence: the
## on-disk /etc/open_link_confirm.d/*.conf files are the baseline, and a value
## provided via the environment must win over them. Verifies the fix for the
## bug where the shipped 31_default.conf was sourced unconditionally and always
## clobbered any env-provided value.
##
## It extracts the real source_config() from the installed/checkout script and
## redirects its two hardcoded config directories to throwaway sandboxes, so
## the exact shipped logic runs without needing root or touching /etc.
##
## Override the script location with OPEN_LINK_CONFIRMATION_BIN.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

resolve_script() {
   if [ -n "${OPEN_LINK_CONFIRMATION_BIN:-}" ]; then
      printf '%s\n' "${OPEN_LINK_CONFIRMATION_BIN}"
      return 0
   fi
   local installed
   installed='/usr/libexec/open-link-confirmation/open-link-confirmation'
   if [ -f "${installed}" ]; then
      printf '%s\n' "${installed}"
      return 0
   fi
   printf '%s\n' "/home/user/derivative-maker/packages/kicksecure/open-link-confirmation/usr/libexec/open-link-confirmation/open-link-confirmation"
}

script_path="$(resolve_script)"

if [ ! -f "${script_path}" ]; then
   printf '%s\n' "ERROR: open-link-confirmation not found at '${script_path}'; set OPEN_LINK_CONFIRMATION_BIN"
   exit 2
fi

work_dir="$(mktemp --directory)"
cleanup() {
   rm --recursive --force -- "${work_dir}"
}
trap cleanup EXIT

## Extract source_config() (from its definition line to the first line that is
## a bare closing brace) and redirect the two real config directories to the
## sandbox, so the shipped logic runs unmodified except for the paths.
etc_dir="${work_dir}/etc"
local_dir="${work_dir}/local"
mkdir --parents -- "${etc_dir}" "${local_dir}"

## Redirect the longer '/usr/local/etc/...' path FIRST: it contains the
## '/etc/open_link_confirm.d' substring, so rewriting the shorter path first
## would corrupt it.
func_file="${work_dir}/source_config.bash"
sed --quiet '/^source_config() {/,/^}/p' -- "${script_path}" \
   | sed \
      --expression "s#/usr/local/etc/open_link_confirm.d#${local_dir}#g" \
      --expression "s#/etc/open_link_confirm.d#${etc_dir}#g" \
   > "${func_file}"

if [ ! -s "${func_file}" ]; then
   printf '%s\n' "ERROR: could not extract source_config() from the script"
   exit 2
fi

## Feature detection: the env-over-config precedence is implemented by saving
## the environment-provided values into *_env locals before sourcing the
## config files and restoring them afterwards. A copy of the script that
## predates that fix (e.g. an older installed package) lacks it; skip rather
## than fail, and point at the checkout that carries the change.
if ! grep --quiet 'link_confirmation_for_links_env' -- "${func_file}"; then
   printf '%s\n' "[D] source_config() env-over-config precedence"
   printf '%s\n' "script: ${script_path}"
   printf '%s\n' "  SKIP  this open-link-confirmation predates the env-override feature."
   printf '%s\n' "        Point at a checkout that has it via OPEN_LINK_CONFIRMATION_BIN to run these checks."
   printf '%s\n' "RESULT: SKIP"
   exit 0
fi

## A single scenario runs source_config() in a fresh bash so no state leaks
## between cases. Prints the resulting two values as 'links files'.
run_scenario() {
   local etc_conf local_conf
   etc_conf="$1"
   local_conf="$2"
   shift 2

   local env_array
   env_array=( "$@" )

   true > "${etc_dir}/31_default.conf"
   true > "${local_dir}/50_user.conf"
   if [ -n "${etc_conf}" ]; then
      printf '%s\n' "${etc_conf}" > "${etc_dir}/31_default.conf"
   fi
   if [ -n "${local_conf}" ]; then
      printf '%s\n' "${local_conf}" > "${local_dir}/50_user.conf"
   fi

   ## The single-quoted body is intentionally expanded by the inner bash, not
   ## this shell (SC2016).
   # shellcheck disable=SC2016
   env "${env_array[@]}" bash -c '
      source "$1"
      source_config
      printf "%s %s\n" "${link_confirmation_for_links:-unset}" "${link_confirmation_for_files:-unset}"
   ' bash "${func_file}"
}

passed=0
failed=0

check() {
   local name expected actual
   name="$1"
   expected="$2"
   actual="$3"
   if [ "${actual}" = "${expected}" ]; then
      passed=$((passed + 1))
      printf '%s\n' "  PASS  ${name}"
   else
      failed=$((failed + 1))
      printf '%s\n' "  FAIL  ${name}: expected '${expected}', got '${actual}'"
   fi
}

printf '%s\n' "[D] source_config() env-over-config precedence"
printf '%s\n' "script: ${script_path}"

## 1. config baseline, no env: config values are used as-is.
result="$(run_scenario 'link_confirmation_for_links=1' 'link_confirmation_for_files=1')"
check "config-baseline-no-env" "1 1" "${result}"

## 2. config says confirm (1), env disables (0): env wins.
result="$(run_scenario 'link_confirmation_for_links=1
link_confirmation_for_files=1' '' 'link_confirmation_for_links=0')"
check "env-overrides-config-to-0" "0 1" "${result}"

## 3. no config at all, env disables: env applies.
result="$(run_scenario '' '' 'link_confirmation_for_links=0' 'link_confirmation_for_files=0')"
check "env-only-no-config" "0 0" "${result}"

## 4. config disables (0), env re-enables (1): env wins in both directions.
result="$(run_scenario 'link_confirmation_for_links=0' '' 'link_confirmation_for_links=1')"
check "env-overrides-config-to-1" "1 unset" "${result}"

## 5. /usr/local config overrides /etc, and env still wins over both.
result="$(run_scenario 'link_confirmation_for_links=1' 'link_confirmation_for_links=0' 'link_confirmation_for_links=1')"
check "env-wins-over-local-and-etc" "1 unset" "${result}"

printf '%s\n' "${passed} passed, ${failed} failed"
if [ "${failed}" -ne 0 ]; then
   printf '%s\n' "RESULT: FAIL"
   exit 1
fi
printf '%s\n' "RESULT: PASS"
