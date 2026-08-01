#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for ci/dist-ai-tests-ci-config.sh, which resolves the apt
## package set the dist-ai suites are run with in a consumer repo's CI.
##
## WHY this exists: dist-ai's own suites carry dependencies of their own
## (git-meld-tests probes 'safe-rm' to drive the review tools, and
## dist-ai-tests-all's EXIT-trap cleanup calls it). If a value in a consumer
## repo's .github/dm-consumer.yml REPLACES that baseline instead of adding to
## it, every consumer has to remember to restate it -- and the one that does not
## gets a dist-ai suite failing on a dependency it never declared, reported as a
## code failure in the component under test. A requirement each repo must
## remember is a requirement that goes unmet, so the baseline has to survive a
## per-repo list.
##
## Source-tree test: set DIST_AI_REPO, or run it from a checkout. Exits 77
## (SKIP) without one. Needs the apt 'yq', as the resolver itself does. No root,
## no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

[ -v TMP ] || TMP=/tmp

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

repo="${DIST_AI_REPO:-}"
if [ -z "${repo}" ]; then
   candidate="${script_dir}/../../.."
   if [ -f "${candidate}/ci/dist-ai-tests-ci-config.sh" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi

if [ -z "${repo}" ] || [ ! -f "${repo}/ci/dist-ai-tests-ci-config.sh" ]; then
   printf '%s\n' 'ci-config-test: no dist-ai source tree (set DIST_AI_REPO); skipping.' >&2
   exit 77
fi

resolver="${repo}/ci/dist-ai-tests-ci-config.sh"

work_dir="$(mktemp --directory -- "${TMP}/ci-config-test.XXXXXX")"

## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
cleanup_work_dir() {
   ## Our own mktemp directory. An absent safe-rm is tolerated rather than
   ## falling back to rm (never rm): a temp directory left behind must not turn
   ## a passing test red.
   safe-rm --recursive --force -- "${work_dir}" || true
   return 0
}

trap cleanup_work_dir EXIT

failures=0
checks=0
resolver_rc=0

fail() {
   printf '%s\n' "FAIL: $1" >&2
   failures=$(( failures + 1 ))
}

## Run the resolver against a config file and print the apt_packages value it
## emitted. GITHUB_WORKSPACE is read by the resolver for hs_arg, so it has to be
## set even when no helper-scripts checkout is requested.
resolve_apt_packages() {
   local config out_file line value

   config="$1"
   out_file="${work_dir}/github_output"
   printf '%s' '' > "${out_file}"

   resolver_rc=0
   GITHUB_OUTPUT="${out_file}" GITHUB_WORKSPACE="${work_dir}" \
      bash -- "${resolver}" "${config}" >/dev/null || resolver_rc=$?

   value=''
   while IFS= read -r line; do
      case "${line}" in
         'apt_packages='*)
            value="${line#apt_packages=}"
            ;;
      esac
   done < "${out_file}"
   printf '%s' "${value}"
}

## True when the space-separated list contains the package name exactly.
list_has() {
   local list package

   list="$1"
   package="$2"
   case " ${list} " in
      *" ${package} "*)
         return 0
         ;;
   esac
   return 1
}

## ---- no consumer config: the baseline stands alone -----------------------
## Reads no yaml, so this half runs even where the resolver's 'yq' is absent.
checks=$(( checks + 1 ))
baseline="$(resolve_apt_packages "${work_dir}/no-such-dm-consumer.yml")"
if [ "${resolver_rc}" -ne 0 ]; then
   fail "the resolver exited '${resolver_rc}' on a missing config file, which it is supposed to treat as 'no overrides'"
fi
if ! list_has "${baseline}" 'safe-rm'; then
   fail "the default apt package set omits 'safe-rm', which dist-ai's own runner and git-meld-tests both require: '${baseline}'"
fi

## ---- a consumer config ADDS to the baseline, never replaces it -----------
config="${work_dir}/dm-consumer.yml"
{
   printf '%s\n' 'dist-ai-tests:'
   printf '%s\n' '  apt-packages: "python3 python3-pyqt5"'
} > "${config}"

resolved="$(resolve_apt_packages "${config}")"

checks=$(( checks + 1 ))
if [ "${resolver_rc}" -ne 0 ]; then
   fail "the resolver exited '${resolver_rc}' on a consumer config; the apt 'yq' package it needs is most likely not installed"
fi

checks=$(( checks + 1 ))
if ! list_has "${resolved}" 'safe-rm'; then
   fail "a consumer apt-packages list dropped dist-ai's own baseline package 'safe-rm': '${resolved}'"
fi

checks=$(( checks + 1 ))
if ! list_has "${resolved}" 'python3-pyqt5'; then
   fail "the consumer's own apt-packages entry 'python3-pyqt5' was lost: '${resolved}'"
fi

## De-duplication is not cosmetic: a consumer list restating a baseline name
## must not double it on the apt command line.
checks=$(( checks + 1 ))
seen=''
duplicates=''
# shellcheck disable=SC2086
## An intentional word list, so the split is the point.
for package in ${resolved}; do
   if list_has "${seen}" "${package}"; then
      duplicates="${duplicates}${duplicates:+ }${package}"
   fi
   seen="${seen}${seen:+ }${package}"
done
if [ -n "${duplicates}" ]; then
   fail "the resolved apt package list repeats: '${duplicates}' in '${resolved}'"
fi

## ---- the 'submodules' opt-in reaches the workflow -------------------------
## The flag is what makes a suite whose subject lives in a submodule actually
## RUN. If the resolver stopped emitting it, the workflow's
## "steps.cfg.outputs.submodules == 'true'" condition would silently read empty,
## the submodules would not be checked out, and the suite would exit 77 -- an
## unauthorized skip reported as a failed run, with nothing pointing here.
resolve_key() {
   local config key out_file line

   config="$1"
   key="$2"
   ## The resolver APPENDS to $GITHUB_OUTPUT, and both calls below resolve the
   ## same key, so this file must be TRUNCATED rather than merely created --
   ## otherwise the second call reads the first call's value and the canary
   ## passes on stale output. 'printf' rather than ':' (R-130).
   out_file="${work_dir}/out.${key}.$$"
   printf '' > "${out_file}"
   GITHUB_OUTPUT="${out_file}" GITHUB_WORKSPACE="${work_dir}" \
      "${resolver}" "${config}" >/dev/null 2>&1 || return 1
   while IFS= read -r line; do
      case "${line}" in
         "${key}="*)
            printf '%s\n' "${line#*=}"
            return 0
            ;;
      esac
   done < "${out_file}"
   return 0
}

submodules_cfg="${work_dir}/submodules.yml"
printf '%s\n' 'dist-ai-tests:' '  submodules: true' > "${submodules_cfg}"
checks=$(( checks + 1 ))
if [ "$(resolve_key "${submodules_cfg}" submodules)" = 'true' ]; then
   printf '%s\n' "ok: 'submodules: true' is emitted as submodules=true"
else
   fail "'submodules: true' did not reach the workflow as submodules=true"
fi

## CANARY: default OFF. Checking out submodules for every consumer that never
## asked would be a cost with no coverage, so the absence of the key must not
## read as 'true'.
default_cfg="${work_dir}/default.yml"
printf '%s\n' 'dist-ai-tests:' '  apt-packages: "python3"' > "${default_cfg}"
checks=$(( checks + 1 ))
if [ "$(resolve_key "${default_cfg}" submodules)" = 'false' ]; then
   printf '%s\n' 'ok: canary: absent key resolves to submodules=false'
else
   fail "canary: an absent 'submodules' key did not resolve to false"
fi

printf '%s\n' "===== summary: ${checks} checks, ${failures} failure(s) ====="
if [ "${failures}" -ne 0 ]; then
   printf '%s\n' 'FAILED: the CI apt package resolution is wrong' >&2
   exit 1
fi
printf '%s\n' "OK: dist-ai's baseline apt packages survive a per-repo apt-packages list"
exit 0
