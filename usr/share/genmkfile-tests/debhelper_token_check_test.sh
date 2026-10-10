#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: '#DEBHELPER#' is substituted by a plain text search-and-replace of
## EVERY occurrence in a maintainer script. A token inside a comment or other prose
## is therefore substituted too, injecting the generated snippet (e.g. a
## '.maintscript' rm_conffile block) a SECOND time -- the systemcheck duplicate-block
## bug that tripped lintian maintainer-script-should-not-use-dpkg-maintscript-helper.
##
## genmkfile's make_debhelper_token_check must REJECT any maintainer script where
## '#DEBHELPER#' appears more than once, or as anything other than a standalone token
## line, and ACCEPT a single standalone token (or none).
##
## Hermetic: sources the genmkfile library (its top-level run is was_executed-guarded)
## and calls the function in a subshell against temp fixtures. No root, no build, no
## chroot. Exit: 0 pass | 1 fail | 77 skip (no genmkfile checkout).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_root="$(mktemp -d)"

## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
cleanup_handler() {
   safe-rm -r -f -- "${test_root}"
}
trap cleanup_handler EXIT

locate_lib() {
   local candidate
   for candidate in \
      "${GENMKFILE_MAKE_HELPER_ONE:-}" \
      "${GENMKFILE_SHARE:-}/make-helper-one.bsh" \
      "${HOME}/derivative-maker/packages/kicksecure/genmkfile/usr/share/genmkfile/make-helper-one.bsh" \
      "/usr/share/genmkfile/make-helper-one.bsh"; do
      case "${candidate}" in
         ""|"/make-helper-one.bsh")
            continue
            ;;
      esac
      if [ -r "${candidate}" ]; then
         printf '%s\n' "${candidate}"
         return 0
      fi
   done
   return 1
}

if ! lib="$(locate_lib)"; then
   ## No checkout wired -> the subject is not under review; skip, do not falsely pass.
   printf '%s\n' "SKIP: genmkfile make-helper-one.bsh not found (set GENMKFILE_SHARE)." >&2
   exit 77  ## style-ok: allow-skip: no genmkfile checkout -> subject not under review
fi

## Referenced by make_output_error inside the sourced library; shellcheck cannot
## see that cross-file use.
# shellcheck disable=SC2034
make_source_package_name="debhelper-token-check-test"
# shellcheck disable=SC1090
source "${lib}"

if ! declare -F make_debhelper_token_check >/dev/null; then
   printf '%s\n' "FAIL: make_debhelper_token_check not defined after sourcing ${lib}."
   exit 1
fi

fail=0

## run_case <name> <ok|err> <script-basename> <line...>
run_case() {
   local name="$1" expect="$2" basename="$3"
   shift 3
   local work rc
   work="$(mktemp -d --tmpdir="${test_root}")"
   mkdir -- "${work}/debian"
   printf '%s\n' "$@" > "${work}/debian/${basename}"
   if ( cd -- "${work}" && make_debhelper_token_check ) >/dev/null 2>&1; then
      rc=0
   else
      rc=$?
   fi
   safe-rm -r -f -- "${work}"
   case "${expect}" in
      ok)
         if [ "${rc}" -eq 0 ]; then
            printf '%s\n' "PASS: ${name}"
         else
            printf '%s\n' "FAIL: ${name} (expected accept, got rc=${rc})"
            fail=1
         fi
         ;;
      err)
         if [ "${rc}" -ne 0 ]; then
            printf '%s\n' "PASS: ${name}"
         else
            printf '%s\n' "FAIL: ${name} (expected reject, got rc=0)"
            fail=1
         fi
         ;;
   esac
}

## token in a comment plus the real token -> substituted twice -> duplicate block.
run_case "comment token duplicates block" err systemcheck.preinst \
   '#!/bin/bash' '## note: #DEBHELPER# snippets are not nounset-safe' 'true' '#DEBHELPER#'

## two standalone tokens -> both substituted -> duplicate.
run_case "two standalone tokens" err pkg.postinst \
   '#!/bin/bash' '#DEBHELPER#' 'true' '   #DEBHELPER#'

## token embedded mid-line -> substituted in place, mangling the line.
run_case "inline token" err pkg.postrm \
   '#!/bin/bash' 'echo start #DEBHELPER#'

## a single standalone token is the one legitimate form.
run_case "single standalone token" ok pkg.preinst \
   '#!/bin/bash' 'true' '#DEBHELPER#'

## leading whitespace before a lone token is still standalone.
run_case "indented standalone token" ok pkg.prerm \
   '#!/bin/bash' '   #DEBHELPER#'

## no token at all -> debhelper appends its block; nothing to police.
run_case "no token" ok pkg.postinst \
   '#!/bin/bash' 'true'

## arch-qualified name (debian/<pkg>.<script>.<arch>) -> dh_installdeb selects it.
run_case "arch-qualified comment token" err pkg.postinst.amd64 \
   '#!/bin/bash' '## note: #DEBHELPER# snippets' 'true' '#DEBHELPER#'

## package-less arch-qualified name (debian/<script>.<arch>).
run_case "bare arch-qualified comment token" err postinst.linux \
   '#!/bin/bash' '## #DEBHELPER#' '#DEBHELPER#'

## debhelper's own generated artifact is not a source script -> skipped.
run_case "debhelper artifact skipped" ok pkg.preinst.debhelper \
   '#DEBHELPER#' '#DEBHELPER#'

## a stray NUL byte must not make grep treat the script as binary and miss the
## token (grep -a). The NUL comes from the '%s\0' format: an argument cannot carry one.
nul_work="$(mktemp -d --tmpdir="${test_root}")"
mkdir -- "${nul_work}/debian"
{
   printf '%s\n' '#!/bin/bash' '## note: #DEBHELPER#' '#DEBHELPER#'
   printf '%s\0' ''
   printf '%s\n' 'x'
} > "${nul_work}/debian/postinst"
if ( cd -- "${nul_work}" && make_debhelper_token_check ) >/dev/null 2>&1; then
   printf '%s\n' "FAIL: NUL byte hides duplicate token"
   fail=1
else
   printf '%s\n' "PASS: NUL byte duplicate token rejected"
fi
safe-rm -r -f -- "${nul_work}"

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "RESULT: FAIL"
   exit 1
fi
printf '%s\n' "RESULT: PASS"
exit 0
