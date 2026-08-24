#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for ci/coverity-build-python.sh, the default 'coverity
## capture' invocation for Python-only repos.
##
## WHY this exists: the capture command carries two contracts a downstream
## Coverity project silently depends on -- '--language python' (buildless Python
## capture) and a '--file-exclude-regex' that skips cov-analysis/, cov-int/,
## .git/, and the .github/dmf + .github/dist-ai CI-runtime helper checkouts.
## Dropping the helper-checkout excludes files OTHER repos' defects against the
## consumer's project, where the code does not exist and cannot be fixed. The
## real Coverity CLI is a large closed-source download; it is stubbed here as an
## argv sink (the allowed external-tool stub) so the REAL script's argument
## construction is verified with no network. Also pins the CI guard.
##
## Source-tree test: set DIST_AI_REPO, or run it from a checkout. No source tree
## is FATAL (exit 1), not a skip. No root, no network.

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
   if [ -f "${candidate}/ci/coverity-build-python.sh" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi

if [ -z "${repo}" ] || [ ! -f "${repo}/ci/coverity-build-python.sh" ]; then
   printf '%s\n' 'FATAL: coverity-build-python-test: no dist-ai source tree (set DIST_AI_REPO).' >&2
   exit 1
fi

builder="${repo}/ci/coverity-build-python.sh"

work_dir="$(mktemp --directory -- "${TMP}/coverity-build-python-test.XXXXXX")"

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

## Consumer cwd with the deterministic ./cov-analysis/bin/coverity path the
## script invokes. Stub it as an argv sink.
cwd="${work_dir}/consumer"
mkdir -p -- "${cwd}/cov-analysis/bin"
argv_log="${work_dir}/coverity-argv"

cat > "${cwd}/cov-analysis/bin/coverity" <<COV_STUB
#!/bin/bash
## Stub: record the space-joined argv, then behave like a successful capture.
printf '%s\n' "\$*" > "${argv_log}"
mkdir -p -- cov-int
printf '%s\n' 'stub build log' > cov-int/build-log.txt
COV_STUB
chmod +x -- "${cwd}/cov-analysis/bin/coverity"

## ---- capture invoked with the required language + exclude contract --------
run_rc=0
( cd -- "${cwd}" && ALLOW_LOCAL=true bash -- "${builder}" ) >/dev/null 2>&1 || run_rc=$?
if [ "${run_rc}" -ne 0 ]; then
   fail "builder exited '${run_rc}' on a successful stubbed capture"
fi

argv=''
if [ -f "${argv_log}" ]; then
   argv="$(< "${argv_log}")"
fi
case "${argv}" in
   *'capture'*)
      ;;
   *)
      fail 'coverity was not invoked with the capture subcommand'
      ;;
esac
case "${argv}" in
   *'--language python'*)
      ;;
   *)
      fail 'capture did not pass --language python'
      ;;
esac
for needle in 'cov-analysis/' 'cov-int/' '.github/dmf/' '.github/dist-ai/'; do
   case "${argv}" in
      *"${needle}"*)
         ;;
      *)
         fail "the file-exclude-regex no longer skips '${needle}'"
         ;;
   esac
done

## ---- CI guard: refuses without CI or ALLOW_LOCAL --------------------------
guard_rc=0
( cd -- "${cwd}" && env -u CI -u ALLOW_LOCAL bash -- "${builder}" ) >/dev/null 2>&1 || guard_rc=$?
if [ "${guard_rc}" -ne 1 ]; then
   fail "did not refuse outside CI without ALLOW_LOCAL (rc '${guard_rc}', expected 1)"
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "coverity-build-python-test: ${failures} check(s) failed" >&2
   exit 1
fi

printf '%s\n' 'coverity-build-python-test: all checks passed'
