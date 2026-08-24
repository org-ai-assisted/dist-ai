#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## sandbox-app-launcher: argument dispatch, and the optional-config defaulting.
##
## THE BUG: each dispatch arm sets only its OWN variables, so 'remove' and
## 'list' aborted on an unset start_program under nounset. Three reviewers
## found it independently, which is the point: an earlier pass never ran a
## SUBCOMMAND at all, so nothing exercised the arms.
##
## Both dispatch and the config defaulting happen before any privileged
## operation, so they can be exercised as a normal user.
##
## Two guards make the cases mean something, and both were added because
## without them everything passed while reaching nothing:
##   - the app must exist in PATH. sandbox-app-launcher resolves it and exits 1
##     with "Could not find 'testapp'" LONG before the dispatch chain at the
##     bottom of the file, so a case without a real executable dies there.
##   - /etc is tmpfs'd so bwrap can create /etc/sandbox-app-launcher, then the
##     files the script genuinely reads are bound back.
##
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp
[ -v SANDBOX_APP_LAUNCHER_REPO ] || SANDBOX_APP_LAUNCHER_REPO=""

if [ -n "${SANDBOX_APP_LAUNCHER_REPO}" ]; then
   subject="${SANDBOX_APP_LAUNCHER_REPO}/usr/bin/sandbox-app-launcher"
else
   subject='/usr/bin/sandbox-app-launcher'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: sandbox-app-launcher not found at '${subject}'" >&2
   printf '%s\n' "set SANDBOX_APP_LAUNCHER_REPO to a checkout, or install the package" >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/sal-dispatch-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

## SC2016: the stub body is LITERAL code written into a file.
# shellcheck disable=SC2016
run_launcher() {
   local config conf_dir bin_dir

   config="$1"
   shift

   conf_dir="${work_dir}/conf"
   bin_dir="${work_dir}/bin"
   safe-rm --recursive --force -- "${conf_dir}" "${bin_dir}"
   mkdir --parents -- "${conf_dir}" "${bin_dir}"

   printf '%s\n' '#!/bin/bash' 'printf "%s\n" "STUB testapp"' >"${bin_dir}/testapp"
   chmod 0755 -- "${bin_dir}/testapp"

   if [ "${config}" = yes ]; then
      printf '%s\n' 'allow_dynamic_native_code_exec=no' 'allow_net=yes' \
         'allow_mic=no' 'allow_webcam=no' 'shared_storage=no' \
         >"${conf_dir}/testapp.conf"
   fi

   bwrap --dev-bind / / \
      --tmpfs /etc \
      --ro-bind /etc/passwd /etc/passwd \
      --ro-bind /etc/group /etc/group \
      --ro-bind /etc/nsswitch.conf /etc/nsswitch.conf \
      --ro-bind /etc/os-release /etc/os-release \
      --bind "${conf_dir}" /etc/sandbox-app-launcher \
      -- env PATH="${bin_dir}:${PATH}" \
      timeout 20 bash "${subject}" "$@" 2>&1 || true
}

## check <description> <config: yes|no> [args...]
check() {
   local description output verdict

   description="$1"
   shift
   output="$(run_launcher "$@")"

   verdict=PASS
   if printf '%s\n' "${output}" | grep --extended-regexp -- '^bwrap:' >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: the script never ran (bwrap setup failed)"
   elif printf '%s\n' "${output}" | grep --fixed-strings -- 'Could not find' >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: never reached dispatch (the app is not in PATH)"
   elif printf '%s\n' "${output}" | grep --fixed-strings -- 'unbound variable' >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: nounset abort -- this is the bug"
   fi

   if [ "${verdict}" = PASS ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${description}"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "  output: $(printf '%s' "${output}" | tr '\n' '|' | head -c 200)"
   fi
}

## Each arm sets only its OWN variables, so every arm has to be run.
check 'setup testapp, config present'  yes setup  testapp
check 'start testapp, config present'  yes start  testapp
check 'remove testapp, config present' yes remove testapp
check 'list, config present'           yes list
check 'no arguments at all'            yes
## The optional-config path: an app with no .conf at all.
check 'start testapp, NO config file'  no  start  testapp
check 'remove testapp, NO config file' no  remove testapp

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
