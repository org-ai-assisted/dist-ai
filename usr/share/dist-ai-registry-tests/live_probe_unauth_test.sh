#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for ci/live-probe-unauth.sh, the unauthenticated GitHub REST
## smoke that exercises github-org-clone's read paths in CI.
##
## WHY this exists: github-org-clone prints its repo-count header via 'log
## notice', so the real line is "[NOTICE]: <n> repos to process under <dir>". An
## ANCHORED '^[0-9]+ repos to process' assertion can never match a log-prefixed
## line -- it turns a healthy probe into a hard FAIL for a reason that reads like
## github-org-clone's own bug. This pins the assertion to the real (log-notice-
## prefixed) output format, consistent with the canonical
## github-org-tools-tests dry-run test. It FAILS against the old anchored regex.
##
## The network preflight (rate_limit) and github-org-clone are stubbed on PATH so
## the REAL script's assertion logic runs against a controlled, real-format
## output with no network. The rate/tool stubs are the allowed kind (network
## action + external subject feeding canned output), not a reimplementation.
##
## Source-tree test: set DIST_AI_REPO, or run it from a checkout. No source tree
## is FATAL (exit 1), not a skip. Needs 'jq' (as the probe does). No root, no
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
   if [ -f "${candidate}/ci/live-probe-unauth.sh" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi

if [ -z "${repo}" ] || [ ! -f "${repo}/ci/live-probe-unauth.sh" ]; then
   printf '%s\n' 'FATAL: live-probe-unauth-test: no dist-ai source tree (set DIST_AI_REPO).' >&2
   exit 1
fi

probe="${repo}/ci/live-probe-unauth.sh"

## A missing dependency is a hard FAIL naming itself. 'type -P', not the house
## 'has': the probe sources has.sh itself; this check runs before that.
if ! type -P jq >/dev/null; then
   printf '%s\n' \
      'FAIL: live-probe-unauth-test: jq not on PATH; the probe cannot run' >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/live-probe-unauth-test.XXXXXX")"

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

## PATH stubs: a curl that answers the rate_limit preflight with a healthy
## bucket, a github-org-clone that emits the REAL log-notice-prefixed dry-run
## header, and a no-op sanitize-string so the tool preflight passes.
stub_bin="${work_dir}/bin"
mkdir -p -- "${stub_bin}"

cat > "${stub_bin}/curl" <<'CURL_STUB'
#!/bin/bash
## Stub: write a healthy rate_limit body to --output and report HTTP 200.
out=''
while [ "$#" -gt 0 ]; do
   if [ "$1" = '--output' ]; then
      out="$2"
      shift 2
   else
      shift
   fi
done
if [ -n "${out}" ]; then
   printf '%s\n' '{"resources":{"core":{"remaining":100}}}' > "${out}"
fi
printf '%s' '200'
CURL_STUB

cat > "${stub_bin}/github-org-clone" <<'GOC_STUB'
#!/bin/bash
## Stub: reproduce github-org-clone's real dry-run output. The header line is
## emitted via 'log notice' -> "[NOTICE]:" prefix, which is exactly what the
## probe's assertion must tolerate.
printf '%s\n' '[NOTICE]: 30 repos to process under /work/live-probe/clone'
printf '%s\n' 'DRY-RUN: clone https://github.com/octokit/rest.js.git'
printf '%s\n' 'DRY-RUN: clone https://github.com/octokit/core.js.git'
GOC_STUB

cat > "${stub_bin}/sanitize-string" <<'SAN_STUB'
#!/bin/bash
cat
SAN_STUB

chmod +x -- "${stub_bin}/curl" "${stub_bin}/github-org-clone" "${stub_bin}/sanitize-string"

## ---- healthy probe against real log-prefixed output -> smoke OK -----------
probe_rc=0
out="$(PATH="${stub_bin}:${PATH}" CI=true bash -- "${probe}" 2>&1)" || probe_rc=$?
if [ "${probe_rc}" -ne 0 ]; then
   fail "probe exited '${probe_rc}' on healthy log-prefixed output (the anchored assertion bug)"
fi
if ! grep --quiet --fixed-strings -- 'live unauth smoke OK' <<< "${out}"; then
   fail "probe did not report success on a healthy run; got: ${out}"
fi

## ---- CI guard: refuses when CI != true ------------------------------------
guard_rc=0
PATH="${stub_bin}:${PATH}" CI=false bash -- "${probe}" >/dev/null 2>&1 || guard_rc=$?
if [ "${guard_rc}" -ne 1 ]; then
   fail "probe did not refuse outside CI (rc '${guard_rc}', expected 1)"
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "live-probe-unauth-test: ${failures} check(s) failed" >&2
   exit 1
fi

printf '%s\n' 'live-probe-unauth-test: all checks passed'
