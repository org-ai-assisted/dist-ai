#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## tor-config-sane: a failing step must be REPORTED, not swallowed.
##
## THE BUG: the script had no 'set -o errexit', so a failing step left it
## running on to the end, printing its END message and exiting 0 -- and the
## systemd unit went green over a Tor configuration that had not been repaired.
## Each failure case here asserts a NON-ZERO exit; each success case asserts
## zero, so the fix cannot be bought by failing on everything.
##
## One case is deliberately a SUCCESS despite a non-zero step:
## systemd-networkd-wait-online times out on a host without IPv6, which is
## expected and must stay tolerated. That is the case a blanket errexit would
## break, and it is why this is a suite rather than a one-line assertion.
##
## Every helper the script calls is stubbed with a chosen exit code and the
## directories they live in are bind-mounted, so nothing on the host is
## touched and no Tor is started.
##
## No root, no network, no tor.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp
[ -v ANON_GW_ANONYMIZER_CONFIG_REPO ] || ANON_GW_ANONYMIZER_CONFIG_REPO=""

script_rel='usr/libexec/anon-gw-anonymizer-config/tor-config-sane'

if [ -n "${ANON_GW_ANONYMIZER_CONFIG_REPO}" ]; then
   subject="${ANON_GW_ANONYMIZER_CONFIG_REPO}/${script_rel}"
else
   subject="/${script_rel}"
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: tor-config-sane not found at '${subject}'" >&2
   printf '%s\n' "set ANON_GW_ANONYMIZER_CONFIG_REPO to a checkout, or install the package" >&2
   exit 1
fi

## bwrap refuses a bind whose destination does not exist, and it exits 1 doing
## so -- the SAME code a correctly reported failure produces. Without these the
## failure cases pass for the wrong reason while the success cases fail, which
## is exactly what happened.
for mount_target in /usr/libexec/helper-scripts /usr/libexec/anon-gw-anonymizer-config \
   /usr/lib/qubes-whonix /usr/lib/systemd /usr/share/qubes; do
   if [ ! -d "${mount_target}" ]; then
      sudo mkdir --parents -- "${mount_target}"
   fi
done

work_dir="$(mktemp --directory -- "${TMP}/tor-config-sane-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

## make_stub <path> <exit code>
make_stub() {
   local path exit_code

   path="$1"
   exit_code="$2"
   mkdir --parents -- "$(dirname -- "${path}")"
   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' 'printf "%s\n" "STUB ${0} ran"'
      printf '%s\n' "exit ${exit_code}"
   } >"${path}"
   chmod 0755 -- "${path}"
}

## run_tor_config_sane <repair rc> <wait-online rc> <generate rc> <replace-ips rc> <qubes yes|no>
run_tor_config_sane() {
   local repair_rc wait_rc generate_rc replace_rc qubes
   local base helpers agac qubes_lib systemd_dir qubes_share run_dir status

   repair_rc="$1"
   wait_rc="$2"
   generate_rc="$3"
   replace_rc="$4"
   qubes="$5"

   base="${work_dir}/case"
   safe-rm --recursive --force -- "${base}"
   helpers="${base}/helper-scripts"
   agac="${base}/agac"
   qubes_lib="${base}/qubes-whonix"
   systemd_dir="${base}/systemd"
   qubes_share="${base}/qubes-share"
   run_dir="${base}/run"
   mkdir --parents -- "${helpers}" "${agac}" "${qubes_lib}" "${systemd_dir}" \
      "${qubes_share}" "${run_dir}"

   make_stub "${helpers}/repair-torrc" "${repair_rc}"
   make_stub "${systemd_dir}/systemd-networkd-wait-online" "${wait_rc}"
   make_stub "${agac}/generate-tor-service-defaults-torrc-anondist" "${generate_rc}"
   make_stub "${qubes_lib}/replace-ips" "${replace_rc}"

   ## The subject lives in the same directory the stub tree replaces, so it has
   ## to be copied in alongside them or the bind hides it.
   cp -- "${subject}" "${agac}/tor-config-sane"
   chmod 0755 -- "${agac}/tor-config-sane"

   if [ "${qubes}" = yes ]; then
      touch -- "${qubes_share}/marker-vm"
   fi

   status=0
   bwrap --dev-bind / / \
      --bind "${helpers}" /usr/libexec/helper-scripts \
      --bind "${agac}" /usr/libexec/anon-gw-anonymizer-config \
      --bind "${qubes_lib}" /usr/lib/qubes-whonix \
      --bind "${systemd_dir}" /usr/lib/systemd \
      --bind "${qubes_share}" /usr/share/qubes \
      --bind "${run_dir}" /run \
      -- timeout 30 /usr/libexec/anon-gw-anonymizer-config/tor-config-sane \
      >"${base}/out" 2>&1 || status=$?
   printf '%s' "${status}"
}

## check <description> <expect: zero|nonzero> <repair> <wait> <generate> <replace-ips> <qubes>
check() {
   local description expect status verdict

   description="$1"
   expect="$2"
   shift 2
   status="$(run_tor_config_sane "$@")"

   verdict=PASS
   ## A refused bwrap exits 1, the SAME code a correctly reported failure
   ## produces, so the exit status cannot distinguish them. Look at the output.
   if grep --extended-regexp -- '^bwrap:' "${work_dir}/case/out" >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: the script never ran"
   fi
   if [ "${verdict}" = PASS ]; then
      if [ "${expect}" = zero ] && [ ! "${status}" = "0" ]; then
         verdict=FAIL
         printf '%s\n' "FAIL: ${description}: expected success, got exit ${status}"
      elif [ "${expect}" = nonzero ] && [ "${status}" = "0" ]; then
         verdict=FAIL
         printf '%s\n' "FAIL: ${description}: the failure was SWALLOWED -- exit 0"
      fi
   fi

   if [ "${verdict}" = PASS ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${description} (exit ${status})"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "  output: $(tr '\n' '|' <"${work_dir}/case/out" | head -c 300)"
   fi
}

##    description                                      expect   repair wait gen rip qubes
check 'all steps succeed'                              zero     0 0 0 0 no
## Expected on a host without IPv6, and it must stay tolerated: this is the
## case a blanket errexit would have broken.
check 'wait-online times out and is tolerated'         zero     0 1 0 0 no
check 'repair-torrc fails and is reported'             nonzero  1 0 0 0 no
check 'generate-...-anondist fails and is reported'    nonzero  0 0 1 0 no
check 'in Qubes, replace-ips fails and is reported'    nonzero  0 0 0 1 yes
check 'in Qubes, everything succeeds'                  zero     0 0 0 0 yes

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
