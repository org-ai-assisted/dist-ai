#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## onion-grater-add / onion-grater-remove: the error paths, and the profile
## name validation.
##
## THE BUG: both assign their key variable only inside a branch or a nullglob
## loop, so an UNKNOWN or ALREADY-ABSENT profile left it unset and nounset
## aborted -- instead of reaching the script's own "does not exist" / "None
## removed" message. The error path IS the thing under test, so each case
## asserts on that message rather than merely on an exit code.
##
## The traversal cases are a separate, security property: these scripts run as
## root and build a filesystem path from the argument, so a '..' component or a
## path separator must be REFUSED outright, not merely quoted.
##
## No root, no network, no systemd: both absolute directories are repointed at
## a fixture, the systemctl restart is neutralised, and the root check is
## neutralised too -- a case blocked by that check would never reach the code
## and is reported as a failure, not counted as a pass.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v TMP ] || TMP=/tmp
[ -v ANON_GW_ANONYMIZER_CONFIG_REPO ] || ANON_GW_ANONYMIZER_CONFIG_REPO=""

if [ -n "${ANON_GW_ANONYMIZER_CONFIG_REPO}" ]; then
   bin_dir="${ANON_GW_ANONYMIZER_CONFIG_REPO}/usr/bin"
else
   bin_dir='/usr/bin'
fi

if [ ! -r "${bin_dir}/onion-grater-add" ]; then
   printf '%s\n' "SKIP: onion-grater-add not found in '${bin_dir}'" >&2
   printf '%s\n' "set ANON_GW_ANONYMIZER_CONFIG_REPO to a checkout, or install the package" >&2
   exit 77
fi

work_dir="$(mktemp --directory -- "${TMP}/onion-grater-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

## SC2016: the validator stub body is LITERAL code written into a file.
# shellcheck disable=SC2016
run_script() {
   local script arg base examples target_dir strings_stub name

   script="$1"
   arg="$2"
   shift 2

   base="${work_dir}/case"
   safe-rm --recursive --force -- "${base}"
   examples="${base}/examples"
   target_dir="${base}/target"
   mkdir --parents -- "${examples}" "${target_dir}"
   for name in "$@"; do
      if [ -n "${name}" ]; then
         printf '%s\n' '## fixture profile' >"${examples}/${name}"
         printf '%s\n' '## fixture profile' >"${target_dir}/${name}"
      fi
   done

   ## strings.bsh is stubbed as a FILE rather than inline in the sed
   ## replacement: the nested quoting there was unreadable and silently broken.
   ## These are the real validate_safe_filename's rules for the cases below.
   strings_stub="${base}/strings.bsh"
   {
      printf '%s\n' 'validate_safe_filename() {'
      printf '%s\n' '   local v="${!1}"'
      printf '%s\n' '   case "${v}" in'
      printf '%s\n' '      "" | "." | "..") return 1 ;;'
      printf '%s\n' '      */* | *\\* | *..* ) return 1 ;;'
      printf '%s\n' '      -*) return 1 ;;'
      printf '%s\n' '   esac'
      printf '%s\n' '   return 0'
      printf '%s\n' '}'
   } >"${strings_stub}"

   sed -e "s|/usr/share/doc/onion-grater-merger/examples|${examples}|g" \
       -e "s|/usr/local/etc/onion-grater-merger.d|${target_dir}|g" \
       -e 's|^\(\s*\)systemctl |\1true systemctl |' \
       -e 's|"$(id -u)"|"0"|' \
       -e "s|^source /usr/libexec/helper-scripts/strings.bsh$|source ${strings_stub}|" \
       -- "${bin_dir}/${script}" >"${base}/${script}"

   timeout 20 bash "${base}/${script}" ${arg:+"${arg}"} 2>&1 || true
}

## check <description> <must-contain> <script> <arg> <fixture profiles...>
check() {
   local description must_contain output verdict

   description="$1"
   must_contain="$2"
   shift 2

   output="$(run_script "$@")"

   verdict=PASS
   ## Hitting the root guard means the case never reached the code under test.
   ## Before the 'id -u' neutralisation existed, both sides hit it and compared
   ## equal -- a pass that proved nothing.
   if printf '%s\n' "${output}" | grep --fixed-strings -- 'must be run as root' >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: blocked by the root guard, never reached the code"
   elif printf '%s\n' "${output}" | grep --fixed-strings -- 'unbound variable' >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: nounset abort -- this is the bug"
   elif ! printf '%s\n' "${output}" | grep --fixed-strings -- "${must_contain}" >/dev/null; then
      verdict=FAIL
      printf '%s\n' "FAIL: ${description}: expected '${must_contain}'"
   fi

   if [ "${verdict}" = PASS ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${description}"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "  output: $(printf '%s' "${output}" | tr '\n' '|' | head -c 200)"
   fi
}

## The error paths that used to abort instead of reporting.
check 'add: an unknown profile reports its own error' \
   'does not exist' onion-grater-add nosuchthing
check 'remove: an absent profile reports None removed' \
   'None removed' onion-grater-remove nosuchthing

## The success paths, so the fix cannot be bought by making everything fail.
check 'add: an exact match is still found' \
   'OK: Added' onion-grater-add known 'known.yml'
check 'add: a wildcard match is still found' \
   'OK: Added' onion-grater-add onionshare '50_onionshare.yml'
check 'remove: a present profile is still removed' \
   'OK: Removed' onion-grater-remove known 'known.yml'

## Path traversal. These run as root and build a filesystem path from the
## argument, so a '..' component or a separator must be refused outright.
check 'remove: rejects a ../ traversal' \
   'invalid profile name' onion-grater-remove '../../../../etc/target'
check 'add: rejects a ../ traversal' \
   'invalid profile name' onion-grater-add '../../../../etc/target'
check 'remove: rejects a path separator' \
   'invalid profile name' onion-grater-remove 'sub/dir'

printf '%s\n' ""
printf '%s\n' "${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
