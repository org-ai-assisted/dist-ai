#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: repo-add-dist (runs as root) must store a default VERBATIM, never
## parse it as shell code. A 'codename' carrying a single quote flows into the
## sources_list_build_remote_derivative default and must not break out and run
## a command.
##
## SUBJECT: the real usr/bin/repo-add-dist, EXECUTED end to end. It is
## self-contained by design (derivative-maker copies it alone into the build
## chroot), so it is driven whole, not sourced. Hermetic, no root: a PATH 'id'
## stub answers uid 0 for root_check, and every output path is redirected into a
## temp dir through the script's own pre-set variable overrides.
##
## Canary: on the eval-based code the injected 'touch' runs and the stored
## sources entry is truncated, so both assertions fail.
##
## Exit: 0 pass | 1 fail | 77 usability-misc checkout absent (target-absent).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

repo="${USABILITY_MISC_REPO:-}"
if [ -z "${repo}" ]; then
   repo="${HOME}/derivative-maker/packages/kicksecure/usability-misc"
fi
subject="${repo}/usr/bin/repo-add-dist"
if [ ! -r "${subject}" ]; then
   printf '%s\n' "SKIP: not readable: '${subject}'" >&2
   printf '%s\n' "set USABILITY_MISC_REPO to a usability-misc checkout." >&2
   ## style-ok: allow-skip: usability-misc is a cross-component subject; absent = target-absent SKIP, --allow-skip governs it
   exit 77
fi

harness="$(dirname -- "$(readlink --canonicalize -- "${BASH_SOURCE[0]}")")/../dist-ai-tests-common/stub-path-harness.bash"
[ -r "${harness}" ] || harness='/usr/share/dist-ai-tests-common/stub-path-harness.bash'
# shellcheck source=../dist-ai-tests-common/stub-path-harness.bash
source "${harness}"

work_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   stub_path_cleanup
   safe-rm --recursive --force -- "${work_dir}" || true
}
trap cleanup EXIT

stub_path_init
stub_cmd id 0 0

pass=0
fail=0
check() {
   local desc="$1"
   shift
   if "$@"; then
      printf '%s\n' "PASS: ${desc}"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: ${desc}"
      fail=$(( fail + 1 ))
   fi
}

marker="${work_dir}/injected"
payload="trixie'; touch -- '${marker}'; '"
sources_file="${work_dir}/sources/derivative.sources"
target_key="${work_dir}/keyrings/derivative.asc"
mkdir --parents -- "${work_dir}/keyrings"

rc=0
env \
   codename="${payload}" \
   apt_target_key_derivative="${target_key}" \
   apt_source_key_temp_folder_derivative="${work_dir}/key-temp" \
   apt_source_key_derivative="${work_dir}/key-temp/derivative.asc" \
   sources_list_target_folder_build_remote_derivative="${work_dir}/sources" \
   sources_list_target_build_remote_derivative="${sources_file}" \
   bash -- "${subject}" >"${work_dir}/log" 2>&1 \
   || rc=$?

check 'script exits 0' test "${rc}" = 0
check 'id stub reached root_check' stub_called_with id -u
check 'quote payload does not execute' test ! -e "${marker}"
check 'quote payload stored verbatim' \
   grep --quiet --line-regexp --fixed-strings -- "Suites: ${payload}" "${sources_file}"
check 'signing key installed' \
   grep --quiet --line-regexp --fixed-strings -- '-----BEGIN PGP PUBLIC KEY BLOCK-----' "${target_key}"

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' '--- subject output ---'
   cat -- "${work_dir}/log"
fi

printf '%s\n' "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
