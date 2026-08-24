#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## help-steps/variables must SAY SO when an inherited 'dist_build_version'
## describes a commit that is not HEAD.
##
## THE BUG IT GUARDS: dist_build_version is auto-detected only when UNSET, so a
## value inherited from a reused workspace silently wins over the actual tree. A
## provenance record was produced naming TWO different commits --
## 'Source-Commit: 02096cd4...' beside 'Source-Version: ...-ge65ff458...'. Nobody
## noticed, because nothing ever printed the two side by side.
##
## REPORTING, not enforcement, is deliberately what is pinned here. Legitimate
## flows make the two differ: ci/reproducible-build-twice pins the version BEFORE
## sign-and-tag, which then rewrites HEAD with 'commit --amend -S'. An earlier
## attempt to ENFORCE equality (in dm-reproducible-buildinfo) failed every signed
## build and blocked CI on a correct record. So this asserts the diagnostic
## appears on a mismatch AND that a matching value stays quiet -- a message on
## every build would be noise and get filtered out, which is the same as absent.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

subject=""
for candidate in "${DM_VARIABLES:-}" \
   "${DERIVATIVE_MAKER_DIR:-}/help-steps/variables" \
   "${HOME}/derivative-maker/help-steps/variables"; do
   [ -n "${candidate}" ] || continue
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "FATAL: help-steps/variables not found (set DM_VARIABLES)." >&2
   exit 1
fi

pass_count=0
fail_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
fail() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

## Exercise the SHIPPED block, not a restatement of it. A private copy of the
## comparison would keep passing after the real one regressed -- which is the
## failure mode this whole file exists to catch.
block="$( sed -n '/dist_build_version_described="\${dist_build_version##\*-g}"/,/^   fi$/p' -- "${subject}" )"
if [ -z "${block}" ]; then
   fail 'could not extract the mismatch diagnostic from help-steps/variables'
   summary_line="===== inherited dist_build_version: ${pass_count} pass, ${fail_count} fail ====="
   printf '%s\n' "${summary_line}"
   exit 1
fi
pass 'extracted the shipped mismatch diagnostic'

## The diagnostic must not be fatal. Enforcement here would break
## ci/reproducible-build-twice, whose version legitimately predates the amend.
case "${block}" in
   *die*|*exit\ 1*)
      fail 'the diagnostic can terminate the build; it must only report'
      ;;
   *)
      pass 'the diagnostic reports without terminating the build'
      ;;
esac

## Match only lines where the message was actually EXECUTED, i.e. the variables
## are expanded. Under 'set -x' the eval echoes the block's SOURCE too, and that
## source literally contains the message text -- so a naive grep matched a branch
## that never ran, and the two silent cases "passed" as failures.
executed_report() {
   grep --quiet 'but HEAD is' <<< "$(grep -v '[$]{')"
}

run_block() {
   local version="$1" head_sha="$2"
   ## 'true "..."' is this file's logging idiom, so the text only materialises
   ## under xtrace -- capture that, which is also how it reaches a real build log.
   (
      ## No 'set +o errexit' (R-011): the subshell's own '|| true' below already
      ## absorbs a non-zero exit, and the trace is captured either way.
      git_bin=git
      cyan=""
      reset=""
      dist_build_version="${version}"
      # shellcheck disable=SC2034  # consumed by the extracted block
      dist_build_version_head=""
      cd -- "${workdir}" || exit 1
      set -x
      eval "${block}"
   ) 2>&1 || true
}

workdir="$( mktemp --directory )"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

git -c core.hooksPath=/dev/null -c user.name=test -c user.email=test@example.com \
   init --quiet -- "${workdir}"
printf '%s\n' "x" > "${workdir}/f"
git -C "${workdir}" -c core.hooksPath=/dev/null add f
git -C "${workdir}" -c core.hooksPath=/dev/null -c user.name=test \
   -c user.email=test@example.com commit --quiet --message one
head_sha="$( git -C "${workdir}" rev-parse HEAD )"

## --- a value describing a DIFFERENT commit must be reported ----------------
out_mismatch="$( run_block '18.2.2.0-217-ge65ff45812c4de50c8e00aad5b3db16169ec2507' "${head_sha}" )"
if printf '%s\n' "${out_mismatch}" | executed_report; then
   pass 'an inherited version describing another commit is reported'
else
   fail "no report for a version describing a different commit:
${out_mismatch}"
fi

## --- a value describing HEAD must stay SILENT ------------------------------
## A message on every build is noise, gets filtered, and is then as good as absent.
out_match="$( run_block "18.2.2.0-1-g${head_sha}" "${head_sha}" )"
if printf '%s\n' "${out_match}" | executed_report; then
   fail "reported a mismatch for a version that DOES describe HEAD:
${out_match}"
else
   pass 'a version describing HEAD produces no mismatch report'
fi

## --- a tag containing '-g' is not a describe suffix ------------------------
out_tag="$( run_block '18.2.2.0-rc1-gui-release' "${head_sha}" )"
if printf '%s\n' "${out_tag}" | executed_report; then
   fail "treated a non-hex '-g' tag as a describe suffix:
${out_tag}"
else
   pass "a tag containing '-g' with a non-hex tail is not misread as a commit"
fi

summary_line="===== inherited dist_build_version: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
