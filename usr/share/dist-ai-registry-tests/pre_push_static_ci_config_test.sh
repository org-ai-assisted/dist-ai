#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for ci/pre-push-static-ci-config.sh, which tells the static
## gate whether to check out a helper-scripts sibling (so 'shellcheck -x' follows
## a cross-repo '# shellcheck source=' directive instead of emitting SC1091).
##
## WHY this exists: the answer is read from ONE yq path
## ('.dist-ai-tests.helper-scripts'). A typo there silently emits
## helper_scripts=false, so a consumer that opted in still hits SC1091 -- and,
## once it dropped its inline disable, a red gate for a reason that reads like
## its own code. Pin the path and the true/false/absent/missing-arg behaviour.
##
## Source-tree test: set DIST_AI_REPO, or run it from a checkout. Exits 77
## (SKIP) without one. Needs the apt 'yq', as the resolver does. No root, no
## network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

repo="${DIST_AI_REPO:-}"
if [ -z "${repo}" ]; then
   candidate="${script_dir}/../../.."
   if [ -f "${candidate}/ci/pre-push-static-ci-config.sh" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi

if [ -z "${repo}" ] || [ ! -f "${repo}/ci/pre-push-static-ci-config.sh" ]; then
   printf '%s\n' 'FATAL: pre-push-static-ci-config-test: no dist-ai source tree (set DIST_AI_REPO).' >&2
   exit 1
fi

resolver="${repo}/ci/pre-push-static-ci-config.sh"

## A missing dependency is a hard FAIL naming itself, not four assertion
## failures against the resolver's empty output. 'type -P', not the house 'has':
## the resolver runs before helper-scripts is provided.
if ! type -P yq >/dev/null; then
   printf '%s\n' \
      'FAIL: pre-push-static-ci-config-test: yq not on PATH (apt yq); the resolver cannot run' >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/pre-push-static-ci-config-test.XXXXXX")"

## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
cleanup_work_dir() {
   safe-rm --recursive --force -- "${work_dir}" || true
   return 0
}

trap cleanup_work_dir EXIT

failures=0
resolver_rc=0

fail() {
   printf '%s\n' "FAIL: $1" >&2
   failures=$(( failures + 1 ))
}

## Run the resolver against a config path and print the helper_scripts value it
## emitted to $GITHUB_OUTPUT.
resolve_helper_scripts() {
   local config out_file line value

   config="$1"
   out_file="${work_dir}/github_output"
   printf '%s' '' > "${out_file}"

   resolver_rc=0
   GITHUB_OUTPUT="${out_file}" GITHUB_WORKSPACE="${work_dir}" \
      bash -- "${resolver}" "${config}" >/dev/null 2>&1 || resolver_rc=$?

   value=''
   while IFS= read -r line; do
      case "${line}" in
         'helper_scripts='*)
            value="${line#helper_scripts=}"
            ;;
      esac
   done < "${out_file}"
   printf '%s' "${value}"
}

## ---- opted in: dist-ai-tests.helper-scripts true -> helper_scripts=true ----
config="${work_dir}/opt-in.yml"
printf '%s\n' 'dist-ai-tests:' '  helper-scripts: true' > "${config}"
value="$(resolve_helper_scripts "${config}")"
if [ "${resolver_rc}" -ne 0 ]; then
   fail "resolver exited '${resolver_rc}' on a valid opt-in config"
fi
if [ "${value}" != 'true' ]; then
   fail "helper-scripts: true did not yield helper_scripts=true (got '${value}') -- the yq path is likely wrong"
fi

## ---- opted out: flag false -> helper_scripts=false ------------------------
config="${work_dir}/opt-out.yml"
printf '%s\n' 'dist-ai-tests:' '  helper-scripts: false' > "${config}"
value="$(resolve_helper_scripts "${config}")"
if [ "${value}" != 'false' ]; then
   fail "helper-scripts: false did not yield helper_scripts=false (got '${value}')"
fi

## ---- flag absent -> helper_scripts=false ----------------------------------
config="${work_dir}/absent.yml"
printf '%s\n' 'dist-ai-tests:' '  apt-packages: "python3"' > "${config}"
value="$(resolve_helper_scripts "${config}")"
if [ "${value}" != 'false' ]; then
   fail "an absent helper-scripts flag did not default to false (got '${value}')"
fi

## ---- no config file at all -> helper_scripts=false, rc 0 ------------------
value="$(resolve_helper_scripts "${work_dir}/no-such-file.yml")"
if [ "${resolver_rc}" -ne 0 ]; then
   fail "resolver exited '${resolver_rc}' on a missing config (should treat as opted out)"
fi
if [ "${value}" != 'false' ]; then
   fail "a missing config did not default helper_scripts to false (got '${value}')"
fi

## ---- missing argument -> rc 2 ---------------------------------------------
GITHUB_OUTPUT="${work_dir}/github_output" GITHUB_WORKSPACE="${work_dir}" \
   bash -- "${resolver}" >/dev/null 2>&1 && missing_rc=0 || missing_rc=$?
if [ "${missing_rc}" -ne 2 ]; then
   fail "resolver exited '${missing_rc}' with no argument, expected 2"
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "pre-push-static-ci-config-test: ${failures} check(s) failed" >&2
   exit 1
fi

printf '%s\n' 'pre-push-static-ci-config-test: all checks passed'
