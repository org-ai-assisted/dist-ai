#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for ci/dm-consumer-load.sh, the shared dm-consumer
## framework loader: it reads a section of the CALLING repo's
## .github/dm-consumer.yml and emits key=value lines to $GITHUB_OUTPUT for the
## reusable workflow's later steps.
##
## WHY this exists: the contract has several silent-failure edges that a
## downstream `if:` reads as intent -- a required key that is missing must
## HARD-fail (not emit empty and let an expensive step run mis-configured); an
## optional key absent must emit an empty value (which downstream reads as "use
## the reusable default"); hyphenated yml keys must underscore in the output
## name (GitHub expression syntax parses outputs.foo-bar as subtraction); an
## embedded newline must be rejected ($GITHUB_OUTPUT format-injection); and the
## soft-skip (no required keys AND file/section absent) must exit 0, not error.
## Each edge, wrong, is a green run that mis-drives the consumer's CI.
##
## Source-tree test: set DIST_AI_REPO, or run it from a checkout. No source
## tree is FATAL (exit 1), not a skip. Needs the apt 'yq', as the loader does.
## No root, no network.

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
   if [ -f "${candidate}/ci/dm-consumer-load.sh" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi

if [ -z "${repo}" ] || [ ! -f "${repo}/ci/dm-consumer-load.sh" ]; then
   printf '%s\n' 'FATAL: dm-consumer-load-test: no dist-ai source tree (set DIST_AI_REPO).' >&2
   exit 1
fi

loader="${repo}/ci/dm-consumer-load.sh"

## A missing dependency is a hard FAIL naming itself, not assertion noise
## against the loader's empty output. 'type -P', not the house 'has': the loader
## runs before helper-scripts is provided in CI.
if ! type -P yq >/dev/null; then
   printf '%s\n' \
      'FAIL: dm-consumer-load-test: yq not on PATH (apt yq); the loader cannot run' >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/dm-consumer-load-test.XXXXXX")"

## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
cleanup_work_dir() {
   safe-rm --recursive --force -- "${work_dir}" || true
   return 0
}

trap cleanup_work_dir EXIT

failures=0

fail() {
   printf '%s\n' "FAIL: $1" >&2
   failures=$(( failures + 1 ))
}

loader_rc=0
out_file="${work_dir}/github_output"

## Run the loader in a clean consumer-cwd with a given dm-consumer.yml body
## (empty string -> no file at all) and the given argv. Captures rc; leaves the
## emitted key=value lines in ${out_file}.
run_load() {
   local yml_body="$1"; shift
   local cwd
   cwd="$(mktemp --directory -- "${work_dir}/consumer.XXXXXX")"
   if [ -n "${yml_body}" ]; then
      mkdir -p -- "${cwd}/.github"
      printf '%s' "${yml_body}" > "${cwd}/.github/dm-consumer.yml"
   fi
   printf '%s' '' > "${out_file}"
   loader_rc=0
   ( cd -- "${cwd}" && GITHUB_OUTPUT="${out_file}" bash -- "${loader}" "$@" ) \
      >/dev/null 2>&1 || loader_rc=$?
}

## Read the value the loader emitted for a given output name (empty if absent).
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

section_yaml=$'codeql-python:\n  build-command: "make build"\n  apt-packages: "python3 python3-yaml"\n'

## ---- required key present -> emitted, hyphen underscored -------------------
run_load "${section_yaml}" 'codeql-python' 'build-command' 'apt-packages'
if [ "${loader_rc}" -ne 0 ]; then
   fail "loader exited '${loader_rc}' on a valid required+optional load"
fi
if [ "$(emitted build_command)" != 'make build' ]; then
   fail "required build-command not emitted as build_command (got '$(emitted build_command)')"
fi
if [ "$(emitted apt_packages)" != 'python3 python3-yaml' ]; then
   fail "hyphenated apt-packages not underscored to apt_packages (got '$(emitted apt_packages)')"
fi

## ---- required key missing (section present, key absent) -> exit 1 ----------
run_load "${section_yaml}" 'codeql-python' 'prepare-command' ''
if [ "${loader_rc}" -ne 1 ]; then
   fail "a missing REQUIRED key did not hard-fail (rc '${loader_rc}', expected 1)"
fi

## ---- optional key absent -> emitted empty, rc 0 ---------------------------
run_load "${section_yaml}" 'codeql-python' '' 'prepare-command'
if [ "${loader_rc}" -ne 0 ]; then
   fail "loader exited '${loader_rc}' with only an absent optional key"
fi
if ! grep --quiet --fixed-strings -- 'prepare_command=' "${out_file}"; then
   fail 'an absent optional key did not emit an empty prepare_command='
fi

## ---- embedded newline in a value -> rejected (format-injection) -----------
inject_yaml=$'codeql-python:\n  build-command: "a\\nb"\n'
run_load "${inject_yaml}" 'codeql-python' 'build-command' ''
if [ "${loader_rc}" -ne 1 ]; then
   fail "a newline-bearing value was not rejected (rc '${loader_rc}', expected 1)"
fi

## ---- wrong argument count -> exit 64 --------------------------------------
run_load "${section_yaml}" 'codeql-python'
if [ "${loader_rc}" -ne 64 ]; then
   fail "wrong argc did not exit 64 (got '${loader_rc}')"
fi

## ---- file absent + zero required -> soft-skip, empty optional, rc 0 --------
run_load '' 'codeql-python' '' 'prepare-command'
if [ "${loader_rc}" -ne 0 ]; then
   fail "absent config with no required keys did not soft-skip (rc '${loader_rc}')"
fi
if ! grep --quiet --fixed-strings -- 'prepare_command=' "${out_file}"; then
   fail 'soft-skip did not emit an empty prepare_command='
fi

## ---- file absent + a required key -> exit 1 -------------------------------
run_load '' 'codeql-python' 'build-command' ''
if [ "${loader_rc}" -ne 1 ]; then
   fail "absent config with a required key did not hard-fail (rc '${loader_rc}')"
fi

## ---- section absent + zero required -> soft-skip, rc 0 --------------------
run_load "${section_yaml}" 'no-such-section' '' 'prepare-command'
if [ "${loader_rc}" -ne 0 ]; then
   fail "absent section with no required keys did not soft-skip (rc '${loader_rc}')"
fi

## ---- section absent + a required key -> exit 1 ----------------------------
run_load "${section_yaml}" 'no-such-section' 'build-command' ''
if [ "${loader_rc}" -ne 1 ]; then
   fail "absent section with a required key did not hard-fail (rc '${loader_rc}')"
fi

## ---- yq expression injection: a crafted section name is DATA, not query ----
## The section arg tries to break out of the yq filter and read an env secret
## (`x" | env.REVIEW_SECRET #`). The loader must treat it as a literal key: no
## secret in the output, and (required) a hard fail because no such section.
inj_cwd="$(mktemp --directory -- "${work_dir}/inject.XXXXXX")"
mkdir -p -- "${inj_cwd}/.github"
printf '%s' "${section_yaml}" > "${inj_cwd}/.github/dm-consumer.yml"
printf '%s' '' > "${out_file}"
inj_rc=0
( cd -- "${inj_cwd}" \
   && REVIEW_SECRET='topsecret-exfil' GITHUB_OUTPUT="${out_file}" \
      bash -- "${loader}" 'x" | env.REVIEW_SECRET #' 'build-command' '' ) \
   >/dev/null 2>&1 || inj_rc=$?
if grep --quiet --fixed-strings -- 'topsecret-exfil' "${out_file}"; then
   fail 'yq expression injection exfiltrated an env secret into GITHUB_OUTPUT'
fi
if [ "${inj_rc}" -ne 1 ]; then
   fail "injection payload as section did not hard-fail a required load (rc '${inj_rc}')"
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "dm-consumer-load-test: ${failures} check(s) failed" >&2
   exit 1
fi

printf '%s\n' 'dm-consumer-load-test: all checks passed'
