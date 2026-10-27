#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drives the REAL test-results-deploy to its CONFIRM-PUBLISHED step with PATH stubs
## (sandbox / site-deploy / generate / github-api) and a local file:// origin, so the real
## pull / generator / push / network never run. Guards the regression where a pushed-but-unbuilt
## or stale publish read as success: confirm_published must FAIL LOUD unless the github-pages
## DEPLOYMENT for the pushed commit reports a 'success' status. (Pages is build_type=workflow:
## the legacy /pages/builds API is frozen and must NOT be used -- that was the false-"not
## confirmed"-while-live bug this guards.) Hermetic: no root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
deploy="${script_dir}/../../bin/test-results-deploy"
[ -x "${deploy}" ] || deploy='/usr/bin/test-results-deploy'
if [ ! -x "${deploy}" ]; then
   printf '%s\n' "test-results-deploy not found" >&2
   exit 1
fi

pass=0
fail=0
check() {
   ## $1 description, $2 actual, $3 expected-substring
   if [[ "$2" == *"$3"* ]]; then
      printf '%s\n' "PASS: $1"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: $1" "  expected substring: $3" "  actual: $2" >&2
      fail=$((fail + 1))
   fi
}
check_rc() {
   ## $1 description, $2 actual rc, $3 want: 'zero' | 'nonzero'
   local ok=0
   case "$3" in
      zero)
         [ "$2" -eq 0 ] && ok=1
         ;;
      nonzero)
         [ "$2" -ne 0 ] && ok=1
         ;;
   esac
   if [ "${ok}" -eq 1 ]; then
      printf '%s\n' "PASS: $1"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: $1" "  expected exit: $3" "  actual rc: $2" >&2
      fail=$((fail + 1))
   fi
}

workdir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

## A real pages repo with an initial committed automated-test-results/ tree. Its origin is a
## LOCAL empty bare (file://) so `git ls-remote origin master` returns nothing hermetically ->
## the driver takes the site-deploy branch, then confirms.
pages_repo="${workdir}/pages"
bare="${workdir}/origin.git"
git init --quiet --bare "${bare}"
mkdir --parents -- "${pages_repo}/automated-test-results"
git -C "${pages_repo}" init --quiet
git -C "${pages_repo}" config user.email t@example.invalid
git -C "${pages_repo}" config user.name test
git -C "${pages_repo}" config core.hooksPath /dev/null
printf '%s\n' "seed" > "${pages_repo}/automated-test-results/index.html"
git -C "${pages_repo}" add -A
git -C "${pages_repo}" commit --quiet -m seed
git -C "${pages_repo}" remote add origin "file://${bare}"
head_sha="$(git -C "${pages_repo}" rev-parse HEAD)"

bindir="${workdir}/bin"
mkdir --parents -- "${bindir}"

## sandbox stub: on pull, create the destination results tree so [ -d results ] passes.
cat > "${bindir}/sandbox" <<'STUB'
#!/bin/bash
dst="${!#}"
case "${dst}" in
   */results) mkdir --parents -- "${dst}" ;;
esac
exit 0
STUB
chmod +x "${bindir}/sandbox"

## generate no-op: tree unchanged -> driver skips the commit, reaches confirm via site-deploy.
printf '%s\n' '#!/bin/bash' 'exit 0' > "${bindir}/generate-noop"
chmod +x "${bindir}/generate-noop"
printf '%s\n' '#!/bin/bash' 'exit 0' > "${bindir}/site-deploy-noop"
chmod +x "${bindir}/site-deploy-noop"

## github-api stub for confirm_published's deployment-status checks. Dispatches on the request
## path: a '/deployments/<id>/statuses' request returns the status array (.state); any other
## (the '/deployments?...&sha=...' list) returns the deployment array (.id).
## make_ghapi <deployments-json-array> <statuses-json-array>.
make_ghapi() {
   local deps="$1" statuses="$2"
   cat > "${bindir}/github-api" <<EOF
#!/bin/bash
for a in "\$@"; do
   case "\$a" in
      */statuses*) printf '%s\n' '${statuses}'; exit 0 ;;
   esac
done
printf '%s\n' '${deps}'
exit 0
EOF
   chmod +x "${bindir}/github-api"
}

## Stateful stub: the deployment for our sha exists, but its latest status is a non-terminal
## 'in_progress' on the 1st poll and 'success' on the 2nd. Exercises the poll-continuation path
## -- a transient status must NOT abort the poll before the deploy finishes. Counter in ${bindir}.
make_ghapi_seq() {
   local counter="${bindir}/.ghapi_calls"
   safe-rm --force -- "${counter}"
   ## Unquoted heredoc: ${counter} expands now; \$-escaped refs stay literal for run time.
   cat > "${bindir}/github-api" <<EOF
#!/bin/bash
for a in "\$@"; do
   case "\$a" in
      */statuses*)
         c='${counter}'
         n=0; [ -f "\${c}" ] && n="\$(cat "\${c}")"; n=\$((n + 1)); printf %s "\${n}" > "\${c}"
         if [ "\${n}" -eq 1 ]; then
            printf '%s\n' '[{"state":"in_progress"}]'
         else
            printf '%s\n' '[{"state":"success"}]'
         fi
         exit 0
         ;;
   esac
done
printf '%s\n' '[{"id":104}]'
exit 0
EOF
   chmod +x "${bindir}/github-api"
}

## Returns the real deploy's exit status; caller captures it with `|| rc=$?`. Fast poll so
## the multi-poll case finishes in ~1s.
run_deploy() {
   PATH="${bindir}:${PATH}" \
   TEST_RESULTS_DEPLOY_TARGET=stub \
   TEST_RESULTS_PAGES_REPO="${pages_repo}" \
   TEST_RESULTS_STAGING_DIR="${workdir}/stage" \
   TEST_RESULTS_SITE_GENERATE="${bindir}/generate-noop" \
   TEST_RESULTS_SITE_DEPLOY="${bindir}/site-deploy-noop" \
   TEST_RESULTS_PAGES_OWNER_REPO="org-ai-assisted/org-ai-assisted.github.io" \
   TEST_RESULTS_CONFIRM_TIMEOUT=2 \
   TEST_RESULTS_CONFIRM_POLL_INTERVAL=1 \
      "${deploy}" 2>&1
}

## 1. github-pages deployment for OUR sha reports success -> confirmed live, exit 0.
make_ghapi '[{"id":101}]' '[{"state":"success"}]'
rc=0; out="$(run_deploy)" || rc=$?
check "deployment success at our commit -> confirmed live" "${out}" "confirmed live at ${head_sha}"
check_rc "deployment success -> exit 0" "${rc}" zero

## 2. NO deployment for our sha (another commit deployed, or not registered yet) -> poll times
##    out, publish NOT confirmed (no stale false-green). This is the exact live bug: the legacy
##    build API would have reported an OLD commit "built" and falsely confirmed; keying on OUR
##    sha's deployment cannot.
make_ghapi '[]' '[]'
rc=0; out="$(run_deploy)" || rc=$?
check "no deployment for our commit -> NOT confirmed" "${out}" "publish NOT confirmed"
check_rc "no deployment -> non-zero exit" "${rc}" nonzero

## 3. Deployment for our sha reports failure -> publish NOT confirmed (fail loud).
make_ghapi '[{"id":103}]' '[{"state":"failure"}]'
rc=0; out="$(run_deploy)" || rc=$?
check "deployment failure at our commit -> NOT confirmed" "${out}" "publish NOT confirmed"
check_rc "deployment failure -> non-zero exit" "${rc}" nonzero

## 4. Transient in_progress then success -> confirmed live. Regression: a non-terminal status
##    must not abort the poll before the deploy finishes.
make_ghapi_seq
rc=0; out="$(run_deploy)" || rc=$?
check "deployment in_progress then success -> confirmed live" "${out}" "confirmed live at ${head_sha}"
check_rc "transient then success -> exit 0" "${rc}" zero

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${fail} assertion(s) (${pass} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: test-results-deploy confirm-published (${pass} assertions)."
