#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## build-steps.d/1050_early-build-setup runs BEFORE the build environment exists:
## by design it does not source help-steps/pre or help-steps/variables. So every
## name its install path uses must be defined by 1050 itself -- a reference to a
## pre/variables-only name (SUDO_TO_ROOT, DIST_APTGETOPT_*, apt_unattended_opts,
## an undefined retry_run) aborts under nounset, but only on a host that is
## MISSING an early dependency (a prepared host skips the install entirely).
##
## Runs the REAL 1050 end-to-end in a scrubbed environment (no build vars
## inherited) on a HERMETIC PATH: stubs plus only the base tools 1050 itself
## needs, so no early dependency (git, curl, ...) is reachable -- as on a fresh
## host. 'dpkg-query' reports every package missing; 'sudo' records its argv
## instead of acting as root; 'apt-get' outside sudo is recorded as a failure
## and never reaches the real one. Asserts:
##   - exit 0, no 'unbound variable', no command run outside sudo;
##   - exactly one 'apt-get update' and one 'apt-get install', both through
##     sudo keeping http_proxy/https_proxy, with Error-Mode=any; install with
##     the list-form --force-confold and exactly $dist_build_early_dependencies.
## Canary: fails on a 1050 that uses ${SUDO_TO_ROOT} without sourcing variables.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

subject="${dm_checkout}/build-steps.d/1050_early-build-setup"
if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: cannot read '${subject}' (set DERIVATIVE_MAKER_DIR)." >&2
   exit 1
fi

work_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work_dir}"; }
trap cleanup EXIT

stub_dir="${work_dir}/stub"
sys_dir="${work_dir}/sys"
mkdir -- "${stub_dir}" "${sys_dir}"
sudo_log="${work_dir}/sudo.log"
unsudoed_log="${work_dir}/unsudoed.log"
touch -- "${sudo_log}" "${unsudoed_log}"

## Base tools only: 1050 + check_runtime.bsh + package_installed_check.sh +
## 60_dependencies.bsh + help-steps/retry-run. Early dependencies stay absent.
for sys_cmd in awk dirname mktemp rm tee uname; do
   ln --symbolic -- "$(type -P "${sys_cmd}")" "${sys_dir}/${sys_cmd}"
done

## Stub bodies are literal text, expanded when the stub runs.
# shellcheck disable=SC2016
{
   ## dpkg-query: nothing is installed -> 1050 must take the install path.
   printf '%s\n' '#!/bin/bash' 'exit 1' > "${stub_dir}/dpkg-query"
   ## sudo: record one argv per line, never act as root.
   printf '%s\n' '#!/bin/bash' \
      'printf "%s\n" "$*" >> "${SUDO_STUB_LOG}"' > "${stub_dir}/sudo"
   ## apt-get / env reached WITHOUT sudo: record and fail, never run the real one.
   printf '%s\n' '#!/bin/bash' \
      'printf "%s\n" "${0##*/} $*" >> "${UNSUDOED_STUB_LOG}"' 'exit 1' > "${stub_dir}/apt-get"
}
cp -- "${stub_dir}/apt-get" "${stub_dir}/env"
chmod +x -- "${stub_dir}/dpkg-query" "${stub_dir}/sudo" "${stub_dir}/apt-get" "${stub_dir}/env"

out_file="${work_dir}/out.log"
rc=0
env -i \
   PATH="${stub_dir}:${sys_dir}" \
   HOME="${work_dir}" \
   SUDO_STUB_LOG="${sudo_log}" \
   UNSUDOED_STUB_LOG="${unsudoed_log}" \
   "$(type -P bash)" "${subject}" > "${out_file}" 2>&1 || rc=$?

if [ "${rc}" -eq 0 ]; then
   pass "1050 completes on a fresh-host PATH with early deps missing"
else
   fail "1050 exited ${rc} on a fresh-host PATH; tail of output:"
   tail -n 15 -- "${out_file}" >&2
fi

if grep --quiet --fixed-strings -- 'unbound variable' "${out_file}"; then
   fail "1050 references a name it does not define: $(grep --fixed-strings -- 'unbound variable' "${out_file}" | head -n1)"
else
   pass "1050 references no undefined name (no 'unbound variable')"
fi

if [ -s "${unsudoed_log}" ]; then
   fail "1050 ran apt-get/env outside sudo: $(cat -- "${unsudoed_log}")"
else
   pass "every privileged command went through sudo"
fi

## sudo_split <line>: sudo options (before the first ' -- ') -> sudo_opts, the
## command after it -> sudo_cmd. A line with no ' -- ' has no command.
sudo_split() {
   sudo_opts=""
   sudo_cmd=""
   if [[ "$1" == *" -- "* ]]; then
      sudo_opts="${1%% -- *}"
      sudo_cmd="${1#* -- }"
   fi
}

## preserves_proxies <sudo_opts>: a --preserve-env=LIST sudo option whose
## comma list names both http_proxy and https_proxy.
preserves_proxies() {
   local opt list
   for opt in $1; do
      case "${opt}" in
         --preserve-env=*)
            list=",${opt#--preserve-env=},"
            [[ "${list}" == *",http_proxy,"* ]] && [[ "${list}" == *",https_proxy,"* ]] && return 0
            ;;
      esac
   done
   return 1
}

mapfile -t sudo_lines < "${sudo_log}"
update_lines=()
install_lines=()
for line in "${sudo_lines[@]}"; do
   sudo_split "${line}"
   case " ${sudo_cmd} " in
      *" apt-get "*" update ")
         update_lines+=( "${line}" )
         ;;
      *" apt-get "*" install "*)
         install_lines+=( "${line}" )
         ;;
   esac
done
if [ "${#sudo_lines[@]}" -eq 2 ] && [ "${#update_lines[@]}" -eq 1 ] && [ "${#install_lines[@]}" -eq 1 ]; then
   pass "exactly one apt-get update and one apt-get install, both through sudo"
else
   fail "expected one update + one install through sudo; sudo log: $(cat -- "${sudo_log}")"
fi

for line in "${update_lines[@]}" "${install_lines[@]}"; do
   sudo_split "${line}"
   if preserves_proxies "${sudo_opts}"; then
      pass "sudo keeps http_proxy/https_proxy: '${sudo_opts}'"
   else
      fail "sudo drops the proxy variables (sudo resets the environment): '${line}'"
   fi
   if [[ " ${sudo_cmd} " == *" -o APT::Update::Error-Mode=any "* ]]; then
      pass "apt-get runs with Error-Mode=any"
   else
      fail "apt-get lacks '-o APT::Update::Error-Mode=any': '${line}'"
   fi
done

## The installed set must be exactly the single-source list from
## 60_dependencies.bsh, evaluated as 1050 sees it (no inherited value).
early_deps="$(
   unset dist_build_early_dependencies
   ## The checkout's single-source dep list, located at runtime.
   # shellcheck disable=SC1090,SC1091
   source "${dm_checkout}/variables.d/60_dependencies.bsh"
   ## Assigned by the sourced fragment.
   # shellcheck disable=SC2154
   printf '%s' "${dist_build_early_dependencies}"
)"
## Word lists: neither spaces nor newlines in the list's formatting matter.
read -r -d '' -a expected_words <<< "${early_deps}" || true
install_line="${install_lines[0]:-}"
sudo_split "${install_line}"
read -r -d '' -a installed_words <<< "${sudo_cmd##* install }" || true
if [ "${#expected_words[@]}" -eq 0 ]; then
   fail "dist_build_early_dependencies is empty; nothing to compare against"
elif [ -z "${install_line}" ]; then
   fail "no 'apt-get ... install' recorded through sudo; sudo log: $(cat -- "${sudo_log}")"
elif [ "${installed_words[*]}" != "${expected_words[*]}" ]; then
   fail "apt-get install set '${installed_words[*]}' != dist_build_early_dependencies '${expected_words[*]}'"
## The LIST form: a scalar 'Dpkg::Options=' is silently never passed to dpkg.
elif [[ " ${sudo_cmd} " != *" -o Dpkg::Options::=--force-confold "* ]]; then
   fail "apt-get install lacks the list-form '-o Dpkg::Options::=--force-confold': '${install_line}'"
else
   pass "apt-get install ran through sudo for exactly \$dist_build_early_dependencies"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: 1050 installs the early dependencies without pre/variables."
