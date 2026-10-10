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
## inherited) with 'dpkg-query' stubbed to report every package missing and
## 'sudo' stubbed to record its argv instead of acting as root. Asserts:
##   - exit 0, no 'unbound variable';
##   - 'apt-get update' and 'apt-get install <dist_build_early_dependencies>'
##     both ran through sudo, with Error-Mode=any.
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

stub_dir="${work_dir}/bin"
mkdir -- "${stub_dir}"
sudo_log="${work_dir}/sudo.log"
touch -- "${sudo_log}"

## dpkg-query: nothing is installed -> 1050 must take the install path.
printf '%s\n' '#!/bin/bash' 'exit 1' > "${stub_dir}/dpkg-query"
## sudo: record one argv per line, never act as root (stub body is literal text).
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/bash' \
   'printf "%s\n" "$*" >> "${SUDO_STUB_LOG}"' \
   'exit 0' > "${stub_dir}/sudo"
chmod +x -- "${stub_dir}/dpkg-query" "${stub_dir}/sudo"

out_file="${work_dir}/out.log"
rc=0
env -i \
   PATH="${stub_dir}:/usr/sbin:/usr/bin:/sbin:/bin" \
   HOME="${work_dir}" \
   SUDO_STUB_LOG="${sudo_log}" \
   bash "${subject}" > "${out_file}" 2>&1 || rc=$?

if [ "${rc}" -eq 0 ]; then
   pass "1050 completes in a scrubbed environment with early deps missing"
else
   fail "1050 exited ${rc} in a scrubbed environment; tail of output:"
   tail -n 15 -- "${out_file}" >&2
fi

if grep --quiet --fixed-strings -- 'unbound variable' "${out_file}"; then
   fail "1050 references a name it does not define: $(grep --fixed-strings -- 'unbound variable' "${out_file}" | head -n1)"
else
   pass "1050 references no undefined name (no 'unbound variable')"
fi

if grep --quiet -- ' apt-get -o APT::Update::Error-Mode=any update$' "${sudo_log}"; then
   pass "apt-get update ran through sudo with Error-Mode=any"
else
   fail "no 'sudo ... apt-get -o APT::Update::Error-Mode=any update' recorded; sudo log: $(cat -- "${sudo_log}")"
fi

## sudo resets the environment; the proxy variables must survive it (as the
## build's SUDO_TO_ROOT keeps them), else a proxy-only host cannot fetch.
if [ -s "${sudo_log}" ] && ! grep --quiet --invert-match -- '--preserve-env=http_proxy,https_proxy ' "${sudo_log}"; then
   pass "every sudo call preserves http_proxy/https_proxy"
else
   fail "a sudo call drops the proxy variables; sudo log: $(cat -- "${sudo_log}")"
fi

## The installed set must be exactly the single-source list from 60_dependencies.bsh.
early_deps="$(
   ## The checkout's single-source dep list, located at runtime.
   # shellcheck disable=SC1090,SC1091
   source "${dm_checkout}/variables.d/60_dependencies.bsh"
   ## Assigned by the sourced fragment.
   # shellcheck disable=SC2154
   printf '%s' "${dist_build_early_dependencies}"
)"
## Compare as word lists so the list's whitespace formatting does not matter.
install_line="$(grep -- ' apt-get .* install ' "${sudo_log}" | head -n1 || true)"
read -r -a expected_words <<< "${early_deps}"
read -r -a installed_words <<< "${install_line##* install }"
if [ "${#expected_words[@]}" -eq 0 ]; then
   fail "dist_build_early_dependencies is empty; nothing to compare against"
elif [ -z "${install_line}" ]; then
   fail "no 'apt-get ... install' recorded through sudo; sudo log: $(cat -- "${sudo_log}")"
elif [ "${installed_words[*]}" != "${expected_words[*]}" ]; then
   fail "apt-get install set '${installed_words[*]}' != dist_build_early_dependencies '${expected_words[*]}'"
elif [[ "${install_line}" != *"APT::Update::Error-Mode=any"* ]]; then
   fail "apt-get install lacks Error-Mode=any: '${install_line}'"
## The LIST form: a scalar 'Dpkg::Options=' is silently never passed to dpkg.
elif [[ "${install_line}" != *" -o Dpkg::Options::=--force-confold "* ]]; then
   fail "apt-get install lacks the list-form '-o Dpkg::Options::=--force-confold': '${install_line}'"
else
   pass "apt-get install ran through sudo for exactly \$dist_build_early_dependencies"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: 1050 installs the early dependencies without pre/variables."
