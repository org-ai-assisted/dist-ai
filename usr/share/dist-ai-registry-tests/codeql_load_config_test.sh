#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for ci/codeql-load-config.sh, the CodeQL-specific wrapper over
## ci/dm-consumer-load.sh: when BUILD_MODE=manual (c/cpp consumers), the
## dm-consumer.yml 'build-command' key is REQUIRED; otherwise it is optional.
##
## WHY this exists: the whole point of the wrapper is that manual-mode CodeQL
## cannot run without a build-command, so a missing one must HARD-fail early
## rather than let CodeQL start and fail deep with an opaque error. If manual
## mode stopped requiring it, that failure would move downstream and lose its
## cause. This also exercises the '$(dirname "$0")/dm-consumer-load.sh'
## co-location -- the wrapper is inert if the two are not shipped side by side.
##
## Source-tree test: set DIST_AI_REPO, or run it from a checkout. No source tree
## is FATAL (exit 1), not a skip. Needs the apt 'yq', as the loader does. No
## root, no network.

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
   if [ -f "${candidate}/ci/codeql-load-config.sh" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi

if [ -z "${repo}" ] || [ ! -f "${repo}/ci/codeql-load-config.sh" ]; then
   printf '%s\n' 'FATAL: codeql-load-config-test: no dist-ai source tree (set DIST_AI_REPO).' >&2
   exit 1
fi

loader="${repo}/ci/codeql-load-config.sh"

## The co-located dm-consumer-load.sh must ship alongside; its absence would make
## the wrapper inert. Assert it, then require yq (which that loader needs).
if [ ! -f "${repo}/ci/dm-consumer-load.sh" ]; then
   printf '%s\n' 'FAIL: codeql-load-config-test: co-located ci/dm-consumer-load.sh missing' >&2
   exit 1
fi
if ! type -P yq >/dev/null; then
   printf '%s\n' 'FAIL: codeql-load-config-test: yq not on PATH (apt yq); the loader cannot run' >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/codeql-load-config-test.XXXXXX")"

## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
cleanup_work_dir() {
   safe-rm --recursive --force -- "${work_dir}" || true
   return 0
}

trap cleanup_work_dir EXIT

failures=0
out_file="${work_dir}/github_output"

fail() {
   printf '%s\n' "FAIL: $1" >&2
   failures=$(( failures + 1 ))
}

loader_rc=0

## Run the wrapper in a consumer cwd carrying the given dm-consumer.yml body.
run_codeql_load() {
   local build_mode="$1" section="$2" yml_body="$3"
   local cwd
   cwd="$(mktemp --directory -- "${work_dir}/consumer.XXXXXX")"
   if [ -n "${yml_body}" ]; then
      mkdir -p -- "${cwd}/.github"
      printf '%s' "${yml_body}" > "${cwd}/.github/dm-consumer.yml"
   fi
   printf '%s' '' > "${out_file}"
   loader_rc=0
   ( cd -- "${cwd}" && BUILD_MODE="${build_mode}" DM_SECTION="${section}" \
        GITHUB_OUTPUT="${out_file}" bash -- "${loader}" ) >/dev/null 2>&1 || loader_rc=$?
}

emitted() {
   local name="$1" line value=''
   while IFS= read -r line; do
      case "${line}" in
         "${name}="*)
            value="${line#"${name}"=}"
            ;;
      esac
   done < "${out_file}"
   printf '%s' "${value}"
}

with_build=$'codeql-cpp:\n  build-command: "make"\n  prepare-command: "apt-get install -y build-essential"\n'
without_build=$'codeql-cpp:\n  prepare-command: "true"\n'

## ---- manual + build-command present -> emitted, rc 0 ----------------------
run_codeql_load 'manual' 'codeql-cpp' "${with_build}"
if [ "${loader_rc}" -ne 0 ]; then
   fail "manual mode with build-command present exited '${loader_rc}'"
fi
if [ "$(emitted build_command)" != 'make' ]; then
   fail "manual mode did not emit build_command=make (got '$(emitted build_command)')"
fi

## ---- manual + build-command absent -> hard-fail ---------------------------
run_codeql_load 'manual' 'codeql-cpp' "${without_build}"
if [ "${loader_rc}" -ne 1 ]; then
   fail "manual mode with a MISSING build-command did not hard-fail (rc '${loader_rc}')"
fi

## ---- non-manual + section absent -> soft-skip, empties, rc 0 --------------
run_codeql_load 'none' 'codeql-python' ''
if [ "${loader_rc}" -ne 0 ]; then
   fail "non-manual mode with an absent config did not soft-skip (rc '${loader_rc}')"
fi
if ! grep --quiet --fixed-strings -- 'build_command=' "${out_file}"; then
   fail 'non-manual soft-skip did not emit an empty build_command='
fi
if ! grep --quiet --fixed-strings -- 'prepare_command=' "${out_file}"; then
   fail 'non-manual soft-skip did not emit an empty prepare_command='
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "codeql-load-config-test: ${failures} check(s) failed" >&2
   exit 1
fi

printf '%s\n' 'codeql-load-config-test: all checks passed'
