#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## 3500_install-packages hand-stages 'apt-get-noninteractive' into the image as a
## bootstrap wrapper BEFORE the helper-scripts package is installed (apt must run
## to install packages, and the wrapper provides apt-get). But apt-get-noninteractive
## 'source's helper-scripts LIBRARIES at runtime, so those libraries must be staged
## alongside it or the wrapper aborts ("strings.bsh: No such file or directory") at
## the first apt-get -- which is exactly how the ISO/qcow2 boot-test build died.
##
## This guards the CROSS-REPO COUPLING: whenever apt-get-noninteractive (or a library
## it sources) gains a new '/usr/libexec/helper-scripts/*.bsh|*.sh' dependency, 3500's
## staging list must grow to match. It computes the wrapper's transitive source-closure
## from the helper-scripts checkout and asserts 3500 stages every member.
##
## Checkout: DERIVATIVE_MAKER_DIR, else ~/derivative-maker.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm="${DERIVATIVE_MAKER_DIR}"
else
   dm="${HOME}/derivative-maker"
fi
hs="${dm}/packages/kicksecure/helper-scripts"
step="${dm}/build-steps.d/3500_install-packages"
wrapper="${hs}/usr/bin/apt-get-noninteractive"
libdir="${hs}/usr/libexec/helper-scripts"

for f in "${step}" "${wrapper}" "${libdir}"; do
   if [ ! -e "${f}" ]; then
      printf '%s\n' "SKIP: missing ${f} (set DERIVATIVE_MAKER_DIR)" >&2
      ## style-ok: allow-skip: the derivative-maker checkout is absent in the standard dist-ai-tests CI job
      exit 77
   fi
done

pass=0
fail=0
pass() { pass=$(( pass + 1 )); printf 'PASS  %s\n' "$1"; }
fail() { fail=$(( fail + 1 )); printf 'FAIL  %s\n' "$1" >&2; }

## Transitive closure of helper-scripts library basenames the wrapper sources.
## A library reference is any '/usr/libexec/helper-scripts/<name>.bsh|.sh' token
## (covers both the absolute 'source /usr/libexec/...' form and strings.bsh's
## HELPER_SCRIPTS_PATH-relative form, which still contains that path suffix).
declare -A seen=()
queue=("${wrapper}")
closure=()
while [ "${#queue[@]}" -gt 0 ]; do
   current="${queue[0]}"
   queue=("${queue[@]:1}")
   [ -r "${current}" ] || continue
   while IFS= read -r libname; do
      [ -n "${libname}" ] || continue
      if [ -z "${seen[${libname}]:-}" ]; then
         seen[${libname}]=1
         closure+=("${libname}")
         queue+=("${libdir}/${libname}")
      fi
   done < <(grep -hoE '/usr/libexec/helper-scripts/[a-z0-9_-]+\.(bsh|sh)' "${current}" 2>/dev/null \
               | sed 's#.*/##' | sort -u)
done

if [ "${#closure[@]}" -eq 0 ]; then
   ## Empty closure -> the rest cannot run (closure[0] would be an unbound-var
   ## crash under nounset). Report the real problem and stop cleanly: the wrapper
   ## staged in CI sources no '/usr/libexec/helper-scripts/*.bsh' the grep matched
   ## (a stale helper-scripts checkout, or the wrapper's source syntax changed).
   fail "canary: computed an EMPTY source-closure for apt-get-noninteractive -- the grep matched nothing in ${wrapper}"
   printf '%s\n' "apt_get_wrapper_closure_test: ${pass} pass, ${fail} fail, 0 skip"
   exit 1
fi
pass "canary: wrapper source-closure is non-empty (${closure[*]})"

## What 3500 stages: the wrapper itself (an explicit 'install ... apt-get-noninteractive
## ... CHROOT_FOLDER') plus every basename listed in its staging loop over
## '.../helper-scripts/${var}' installed into CHROOT_FOLDER. Read the loop list.
staged_line="$( grep -E 'for [a-z_]+ in .*\.bsh' -- "${step}" | head -n1 || true )"
staged_libs=" $( printf '%s' "${staged_line}" | sed -E 's/.*for [a-z_]+ in //; s/; *do.*//' ) "

## The wrapper must itself be staged into the image.
if grep --quiet --extended-regexp 'install .*helper-scripts/usr/bin/apt-get-noninteractive.*CHROOT_FOLDER' -- "${step}"; then
   pass "3500 stages the apt-get-noninteractive wrapper into the image"
else
   fail "3500 does not stage apt-get-noninteractive into the image chroot"
fi

## Confirm the staging loop installs into the image's helper-scripts libdir
## (not merely names the files somewhere).
if grep --quiet --extended-regexp 'install .*helper-scripts/\$\{[a-z_]+\}.*CHROOT_FOLDER.*/usr/libexec/helper-scripts/' -- "${step}"; then
   pass "3500 install-loop targets the image's /usr/libexec/helper-scripts"
else
   fail "3500 has no install-loop placing helper-scripts libraries into the image libdir"
fi

## Every library in the closure must appear in the staged list.
missing=""
for libname in "${closure[@]}"; do
   if [[ "${staged_libs}" != *" ${libname} "* ]]; then
      missing="${missing} ${libname}"
   fi
done
if [ -z "${missing}" ]; then
   pass "3500 stages every library apt-get-noninteractive sources (${closure[*]})"
else
   fail "3500 does NOT stage sourced helper-scripts libraries:${missing} -- add them to the staging loop in 3500_install-packages, or the bootstrap apt-get-noninteractive aborts"
fi

## CANARY: the closure-vs-staged check must actually be capable of catching a gap.
## Drop one closure member from a copy of the staged set and confirm it is flagged.
canary_staged=" ${closure[0]} "  ## deliberately incomplete when closure has >1
canary_missing=""
for libname in "${closure[@]}"; do
   if [[ "${canary_staged}" != *" ${libname} "* ]]; then
      canary_missing="${canary_missing} ${libname}"
   fi
done
if [ "${#closure[@]}" -le 1 ] || [ -n "${canary_missing}" ]; then
   pass "canary: an incomplete staging list is detected as missing libraries"
else
   fail "canary: the missing-library check failed to flag an incomplete staging list"
fi

printf '%s\n' "apt_get_wrapper_closure_test: ${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
