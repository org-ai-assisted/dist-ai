#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-stripped-setx-audit: it must actually WALK the packages, and it must fail
## loudly when it walked none.
##
## THE BUG the audit carries a guard against: the package test used to be
## '[ -d "${pkg}/.git" ]'. In a submodule .git is a FILE, so the condition was
## false for every package, the loop body never ran, and the audit reported a
## clean tree while examining nothing.
##
## That guard is only as good as something exercising it, which is what this
## payload is. The fixture is a throwaway packages tree built here with the
## SUBMODULE shape (.git as a file pointing at a separate gitdir) -- the shape
## that was skipped. Pointing the audit at the real ~/derivative-maker would
## make the verdict depend on a shared checkout other sessions are editing, and
## on whatever those sessions happen to have stripped.
##
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v TMP ] || TMP=/tmp
[ -v DIST_AI_REPO ] || DIST_AI_REPO=""

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

## Same resolution as the sibling payloads: an explicit override, else the
## checkout this script lives in (usr/share/<suite>/ -> repo root).
repo="${DIST_AI_REPO}"
if [ -z "${repo}" ]; then
   candidate="${script_dir}/../../.."
   if [ -f "${candidate}/usr/bin/dist-ai-tests-all" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi

if [ -z "${repo}" ] || [ ! -x "${repo}/usr/bin/dm-stripped-setx-audit" ]; then
   printf '%s\n' 'dist-ai-registry-tests: no dist-ai source tree (set DIST_AI_REPO); skipping.' >&2
   exit 77
fi

subject="${repo}/usr/bin/dm-stripped-setx-audit"

## The audit compares each package's 'ai' branch against org-ai-assisted/master
## by that literal name, so the fixture creates that exact remote-tracking ref.
## If the tool ever stops naming it, the fixture stops matching and every case
## below would report an empty diff -- so pin the name here rather than let the
## payload quietly test nothing.
if ! grep --quiet --fixed-strings 'org-ai-assisted/master...ai' -- "${subject}"; then
   printf '%s\n' "FATAL: '${subject}' no longer diffs against org-ai-assisted/master...ai" >&2
   printf '%s\n' "the fixture's base ref would not match and every case would go empty" >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/stripped-setx-audit-test.XXXXXX")"

test_cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}"
}

trap test_cleanup_handler EXIT

pass_count=0
fail_count=0

record() {
   local verdict description

   verdict="$1"
   description="$2"

   if [ "${verdict}" = PASS ]; then
      pass_count=$(( pass_count + 1 ))
      printf '%s\n' "PASS: ${description}"
   else
      fail_count=$(( fail_count + 1 ))
      printf '%s\n' "FAIL: ${description}"
   fi
}

## make_package <vendor/name> <keeps-set-x: yes|no>
##
## Commits a script WITH 'set -x' as the base, then edits it on branch 'ai':
## dropping the line for the case the audit must report, keeping it for the
## case it must stay quiet about.
make_package() {
   local spec keeps pkg gitdir

   spec="$1"
   keeps="$2"

   pkg="${work_dir}/packages/${spec}"
   mkdir --parents -- "${pkg}/usr/bin"

   ## A submodule keeps its gitdir OUTSIDE the work tree and leaves a .git
   ## FILE behind. That is the shape the old '-d' test skipped, so build it.
   gitdir="${work_dir}/gitdirs/${spec//\//-}"
   mkdir --parents -- "${gitdir}"
   git init --quiet --separate-git-dir="${gitdir}" -- "${pkg}"

   printf '%s\n' '#!/bin/bash' 'set -x' 'true' >"${pkg}/usr/bin/tool"
   git -C "${pkg}" -c user.name=test -c user.email=test@example.com add --all
   git -C "${pkg}" -c user.name=test -c user.email=test@example.com \
      commit --quiet --message 'base'
   git -C "${pkg}" update-ref refs/remotes/org-ai-assisted/master HEAD

   git -C "${pkg}" checkout --quiet -b ai
   if [ "${keeps}" = 'yes' ]; then
      printf '%s\n' '#!/bin/bash' 'set -x' 'true' 'true "changed"' >"${pkg}/usr/bin/tool"
   else
      printf '%s\n' '#!/bin/bash' 'true' 'true "changed"' >"${pkg}/usr/bin/tool"
   fi
   git -C "${pkg}" -c user.name=test -c user.email=test@example.com add --all
   git -C "${pkg}" -c user.name=test -c user.email=test@example.com \
      commit --quiet --message 'strict-mode pass'

   if [ ! -f "${pkg}/.git" ]; then
      printf '%s\n' "FATAL: '${pkg}/.git' is not a FILE; the fixture does not have" >&2
      printf '%s\n' "the submodule shape this payload exists to cover" >&2
      exit 1
   fi
}

## The fixture repos commit, so keep the operator's own hooks out: they are not
## what is under test here, and the branch guard would refuse 'ai' anyway.
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0='core.hooksPath'
export GIT_CONFIG_VALUE_0='/dev/null'

make_package 'kicksecure/dropper' no
make_package 'kicksecure/keeper' yes

output=""
rc=0
output="$("${subject}" "${work_dir}/packages" 2>&1)" || rc=$?

if [ "${rc}" -eq 0 ]; then
   record PASS 'a walkable tree exits 0'
else
   record FAIL "exited ${rc} on a walkable tree"
   printf '%s\n' "  output: ${output}"
fi

if printf '%s\n' "${output}" | grep --quiet --extended-regexp 'examined 2 package'; then
   record PASS 'both submodule-shaped packages were examined'
else
   record FAIL 'the package count is not 2 -- the .git FILE shape was skipped'
   printf '%s\n' "  output: ${output}"
fi

if printf '%s\n' "${output}" | grep --quiet --fixed-strings 'kicksecure/dropper/usr/bin/tool'; then
   record PASS 'the file that lost set -x is reported'
else
   record FAIL 'the stripped file was not reported'
   printf '%s\n' "  output: ${output}"
fi

if printf '%s\n' "${output}" | grep --quiet --fixed-strings 'kicksecure/keeper'; then
   record FAIL 'a file that KEPT set -x was reported as stripped'
   printf '%s\n' "  output: ${output}"
else
   record PASS 'the file that kept set -x is not reported'
fi

if printf '%s\n' "${output}" | grep --quiet --extended-regexp '1 stripped'; then
   record PASS 'the stripped count is 1'
else
   record FAIL 'the stripped count is not 1'
   printf '%s\n' "  output: ${output}"
fi

## The property the whole audit rests on: an empty tree must FAIL, not report
## a clean run.
mkdir --parents -- "${work_dir}/empty"
empty_rc=0
empty_output="$("${subject}" "${work_dir}/empty" 2>&1)" || empty_rc=$?
if [ "${empty_rc}" -ne 0 ] \
   && printf '%s\n' "${empty_output}" | grep --quiet --fixed-strings 'testing nothing'; then
   record PASS 'an empty tree fails loudly instead of reporting clean'
else
   record FAIL "an empty tree exited ${empty_rc} without saying it tested nothing"
   printf '%s\n' "  output: ${empty_output}"
fi

printf '%s\n' ""
printf '%s\n' "stripped-setx-audit: ${pass_count} pass, ${fail_count} fail"
[ "${fail_count}" -eq 0 ]
