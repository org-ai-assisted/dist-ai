#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## setup-dist: the four branches it dispatches on -- distro marker, password
## state, and whether the disclaimer has already been shown.
##
## THIS IS A BEHAVIOUR-PRESERVATION TEST, not a bug reproduction.
## enumerate-nounset found NO reachable nounset trap in this file, so the
## strict-mode conversion was not a fix here and there is no predecessor that
## fails. It is canaried by INJECTION instead -- see the commit that adds it.
## Saying so matters: running it against the pre-conversion script passes, and
## that is the correct result, not a broken test.
##
## The script sources three absolute paths and shells out to dialog_wrapper and
## leaprun, so every case runs under bwrap with stub trees bound over them.
##
## No root, no network, no dialog.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp
[ -v SETUP_DIST_REPO ] || SETUP_DIST_REPO=""

if [ -n "${SETUP_DIST_REPO}" ]; then
   subject="${SETUP_DIST_REPO}/usr/bin/setup-dist"
else
   subject='/usr/bin/setup-dist'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: setup-dist not found at '${subject}'" >&2
   printf '%s\n' "set SETUP_DIST_REPO to a checkout, or install the package" >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/setup-dist-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

## SC2016: the stub bodies are LITERAL code written into a file.
# shellcheck disable=SC2016
run_setup_dist() {
   local password_state marker disclaimer base

   password_state="$1"
   marker="$2"
   disclaimer="$3"

   base="${work_dir}/case"
   safe-rm --recursive --force -- "${base}"
   mkdir --parents -- "${base}/sd-libexec" "${base}/helpers" "${base}/bin" \
      "${base}/share-ws" "${base}/share-gw" "${base}/var-cache" "${base}/share-sd"

   ## 'shared' provides ft_disclaimer / ft_m_end; get_colors.sh provides the
   ## colour variables the NOTICE line interpolates. The sentinel is printed at
   ## SOURCE time, so every case that got as far as sourcing has something to
   ## assert on -- including the one whose normal output is otherwise empty.
   {
      printf '%s\n' 'printf "%s\n" "STUB shared sourced"'
      printf '%s\n' 'ft_disclaimer() { printf "%s\n" "STUB ft_disclaimer"; }'
      printf '%s\n' 'ft_m_end() { printf "%s\n" "STUB ft_m_end"; }'
   } >"${base}/sd-libexec/shared"
   {
      printf '%s\n' 'yellow="_Y_"'
      printf '%s\n' 'nocolor="_N_"'
   } >"${base}/helpers/get_colors.sh"
   printf '%s\n' 'has() { [ -n "$(type -t "$1")" ]; }' >"${base}/helpers/has.sh"

   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' 'printf "%s\n" "STUB dialog_wrapper $*"'
   } >"${base}/bin/dialog_wrapper"
   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' 'printf "%s\n" "STUB dialog"'
   } >"${base}/bin/dialog"
   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' 'printf "%s\n" "user1: '"${password_state}"'"'
   } >"${base}/bin/leaprun"
   chmod 0755 -- "${base}/bin/dialog_wrapper" "${base}/bin/dialog" "${base}/bin/leaprun"

   if [ "${marker}" = workstation ]; then
      touch -- "${base}/share-ws/workstation"
   fi
   if [ "${marker}" = gateway ]; then
      touch -- "${base}/share-gw/gateway"
   fi
   if [ "${disclaimer}" = "done" ]; then
      mkdir --parents -- "${base}/var-cache/status-files"
      touch -- "${base}/var-cache/status-files/disclaimer.done"
   fi

   ## tmpfs the PARENT of each stub mount first. bwrap has to create the
   ## mountpoint, and /usr/share and /usr/libexec are read-only -- without this
   ## every run dies in bwrap setup before reaching the script, while still
   ## producing identical output on both sides. That is exactly how this
   ## started life reporting five passing cases over nothing.
   bwrap --dev-bind / / \
      --tmpfs /usr/share \
      --tmpfs /usr/libexec \
      --tmpfs /var/cache \
      --bind "${base}/sd-libexec" /usr/libexec/setup-dist \
      --bind "${base}/helpers" /usr/libexec/helper-scripts \
      --bind "${base}/share-ws" /usr/share/anon-ws-base-files \
      --bind "${base}/share-gw" /usr/share/anon-gw-base-files \
      --bind "${base}/var-cache" /var/cache/setup-dist \
      --bind "${base}/share-sd" /usr/share/setup-dist \
      -- env PATH="${base}/bin:/usr/bin:/bin" \
      timeout 20 bash "${subject}" 2>&1 || true
}

## check <description> <must-contain> <password state> <marker> <disclaimer>
check() {
   local description want output verdict

   description="$1"
   want="$2"
   shift 2
   output="$(run_setup_dist "$@")"

   verdict=PASS
   if printf '%s\n' "${output}" | grep --extended-regexp -- '^bwrap:' >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: the script never ran (bwrap setup failed)"
   elif printf '%s\n' "${output}" | grep --fixed-strings -- 'unbound variable' >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: nounset abort"
   elif ! printf '%s\n' "${output}" | grep --fixed-strings -- "${want}" >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: expected '${want}'"
   fi

   if [ "${verdict}" = PASS ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${description}"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "  output: $(printf '%s' "${output}" | tr '\n' '|' | head -c 200)"
   fi
}

check 'workstation, all passwords set'  'STUB dialog_wrapper' Present workstation none
## The NOTICE line interpolates the colour variables, so it also proves
## get_colors.sh was sourced and the palette reached the message.
check 'workstation, a password ABSENT'  '_Y_NOTICE_N_'        Absent  workstation none
check 'gateway, all passwords set'      'STUB dialog_wrapper' Present gateway     none
## Normal output is otherwise empty here; the source-time sentinel is what
## makes the case assertable at all.
check 'no distro marker at all'         'STUB shared sourced' Present none        none
check 'the disclaimer is already done'  'STUB dialog_wrapper' Present workstation 'done'

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
