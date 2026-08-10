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
## path separator must be REFUSED outright, not merely quoted. That refusal is
## the REAL helper-scripts validate_safe_filename (sourced from strings.bsh by
## the shipped scripts), so the traversal cases drive the real validator through
## the real script -- not a reimplemented copy of its rules. The validator is
## resolved from a wired helper-scripts checkout (HELPER_SCRIPTS_PATH, set by
## dist-ai-tests-all wire()), then an installed /usr/libexec/helper-scripts, and
## only as a last resort a hand-written stub (noted loudly at run time).
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
[ -v HELPER_SCRIPTS_PATH ] || HELPER_SCRIPTS_PATH=""

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

## Resolve the REAL validate_safe_filename the shipped scripts call. Order:
##   1. a wired helper-scripts checkout (HELPER_SCRIPTS_PATH) -- also puts its
##      usr/bin on PATH and dist-packages on PYTHONPATH so the validator's
##      sanitize-echo reporting path runs (its stderr is the anti-vacuous marker
##      the traversal cases assert on).
##   2. an installed /usr/libexec/helper-scripts.
##   3. a hand-written validate_safe_filename stub -- only tests the test's own
##      copy of the rules, so it is announced loudly and the traversal marker
##      assertion is skipped.
validator_mode=""
helper_libexec=""
if [ -n "${HELPER_SCRIPTS_PATH}" ] \
   && [ -r "${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/strings.bsh" ] \
   && [ -r "${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts/has.sh" ]; then
   validator_mode='real-checkout'
   helper_libexec="${HELPER_SCRIPTS_PATH}/usr/libexec/helper-scripts"
   export HELPER_SCRIPTS_PATH
   export PATH="${HELPER_SCRIPTS_PATH}/usr/bin:${PATH}"
   export PYTHONPATH="${HELPER_SCRIPTS_PATH}/usr/lib/python3/dist-packages${PYTHONPATH:+:${PYTHONPATH}}"
elif [ -r '/usr/libexec/helper-scripts/strings.bsh' ] \
   && [ -r '/usr/libexec/helper-scripts/has.sh' ]; then
   validator_mode='real-installed'
   helper_libexec='/usr/libexec/helper-scripts'
else
   validator_mode='stub'
   printf '%s\n' "NOTE: no helper-scripts checkout/installation found; traversal cases" >&2
   printf '%s\n' "      fall back to a validate_safe_filename STUB (they then only cover" >&2
   printf '%s\n' "      the test's copy of the rules). Set HELPER_SCRIPTS_PATH to a" >&2
   printf '%s\n' "      helper-scripts checkout to exercise the real validator." >&2
fi

## Anti-vacuous wiring guard. The traversal property only means anything if the
## shipped script still SOURCES helper-scripts strings.bsh and CALLS
## validate_safe_filename on the name. If either is renamed or dropped, the
## redirect below would source nothing -- an UNDEFINED validate_safe_filename
## makes '! validate_safe_filename' succeed and reject EVERY name, so the
## traversal cases would "pass" while proving nothing. Fail loudly here instead.
for guard_script in onion-grater-add onion-grater-remove; do
   if ! grep --quiet -- '^source /usr/libexec/helper-scripts/strings.bsh$' "${bin_dir}/${guard_script}"; then
      printf '%s\n' "FAIL: ${guard_script} no longer sources helper-scripts strings.bsh -- validator wiring is stale" >&2
      exit 1
   fi
   if ! grep --quiet -- 'validate_safe_filename' "${bin_dir}/${guard_script}"; then
      printf '%s\n' "FAIL: ${guard_script} no longer calls validate_safe_filename" >&2
      exit 1
   fi
done

work_dir="$(mktemp --directory -- "${TMP}/onion-grater-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

## SC2016: the fallback stub bodies are LITERAL code written into files.
# shellcheck disable=SC2016
write_stub_helpers() {
   ## Only used in 'stub' mode: no real helper-scripts available. Reproduces
   ## just enough of validate_safe_filename (path-separator / dot / '..' /
   ## leading-dash rejection) and has() for the scripts to run standalone.
   ## style-ok: no-has -- this generates a has() STUB (its body mirrors the real
   ## helper-scripts has, which is 'command -v'-based); it is not an existence
   ## check in this test's own control flow.
   local strings_stub has_stub
   strings_stub="$1"
   has_stub="$2"
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
   {
      printf '%s\n' 'has() {'
      printf '%s\n' '   local _name'
      printf '%s\n' '   for _name in "$@"; do'
      printf '%s\n' '      command -v -- "${_name}" >/dev/null 2>&1 || return 1'
      printf '%s\n' '   done'
      printf '%s\n' '}'
   } >"${has_stub}"
}

run_script() {
   local script arg base examples target_dir name strings_src has_src

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

   if [ "${validator_mode}" = 'stub' ]; then
      strings_src="${base}/strings.bsh"
      has_src="${base}/has.sh"
      write_stub_helpers "${strings_src}" "${has_src}"
   else
      ## Point the shipped scripts' own 'source' lines at the REAL helper-scripts
      ## strings.bsh / has.sh so validate_safe_filename runs for real.
      strings_src="${helper_libexec}/strings.bsh"
      has_src="${helper_libexec}/has.sh"
   fi

   sed -e "s|/usr/share/doc/onion-grater-merger/examples|${examples}|g" \
       -e "s|/usr/local/etc/onion-grater-merger.d|${target_dir}|g" \
       -e 's|^\(\s*\)systemctl |\1true systemctl |' \
       -e 's|"$(id -u)"|"0"|' \
       -e "s|^source /usr/libexec/helper-scripts/has.sh$|source ${has_src}|" \
       -e "s|^source /usr/libexec/helper-scripts/strings.bsh$|source ${strings_src}|" \
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

   ## Anti-vacuous marker for the traversal property. In a wired real-checkout
   ## the REAL validate_safe_filename announces its rejection reason on stderr
   ## (via sanitize-echo). All three traversal inputs contain '/', so the reason
   ## is deterministically 'Path separator not allowed!'. Requiring it proves the
   ## rejection came from the real validator evaluating the input -- not from an
   ## undefined function (a 'command not found' abort also prints the function
   ## name), an unrelated error, or a stubbed copy of the rules. Asserted only in
   ## real-checkout mode, where PATH/PYTHONPATH make sanitize-echo run.
   if [ "${verdict}" = PASS ] \
      && [ "${must_contain}" = 'invalid profile name' ] \
      && [ "${validator_mode}" = 'real-checkout' ]; then
      if ! printf '%s\n' "${output}" | grep --fixed-strings -- 'validate_safe_filename: Path separator not allowed!' >/dev/null; then
         verdict=FAIL
         printf '%s\n' "FAIL: ${description}: no real validate_safe_filename rejection marker (anti-vacuous)"
      fi
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
