#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drives the REAL test-results-deploy to its CONFIRM-PUBLISHED step with PATH stubs
## (sandbox / site-deploy / generate / github-api) and a local file:// origin, so the real
## pull / generator / push / network never run. Guards the regression where a pushed-but-unbuilt
## or stale publish read as success: confirm_published must FAIL LOUD unless GitHub Pages reports
## status=built AT the pushed commit. Hermetic: no root, no network.

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

## github-api stub reports a canned pages/builds/latest. $1 = status, $2 = commit.
make_ghapi() {
   {
      printf '%s\n' '#!/bin/bash'
      printf '%s\n' "printf '%s\n' '{\"status\":\"$1\",\"commit\":\"$2\"}'"
      printf '%s\n' 'exit 0'
   } > "${bindir}/github-api"
   chmod +x "${bindir}/github-api"
}

run_deploy() {
   PATH="${bindir}:${PATH}" \
   TEST_RESULTS_DEPLOY_TARGET=stub \
   TEST_RESULTS_PAGES_REPO="${pages_repo}" \
   TEST_RESULTS_STAGING_DIR="${workdir}/stage" \
   TEST_RESULTS_SITE_GENERATE="${bindir}/generate-noop" \
   TEST_RESULTS_SITE_DEPLOY="${bindir}/site-deploy-noop" \
   TEST_RESULTS_PAGES_OWNER_REPO="org-ai-assisted/org-ai-assisted.github.io" \
   TEST_RESULTS_CONFIRM_TIMEOUT=2 \
      "${deploy}" 2>&1 || true
}

## 1. Pages built OUR commit -> confirmed live.
make_ghapi built "${head_sha}"
out="$(run_deploy)"
check "built at our commit -> confirmed live" "${out}" "confirmed live at ${head_sha}"

## 2. Pages built a DIFFERENT commit -> publish NOT confirmed (fail loud, no stale false-green).
make_ghapi built "0000000000000000000000000000000000000000"
out="$(run_deploy)"
check "built at other commit -> NOT confirmed" "${out}" "publish NOT confirmed"

## 3. Build ERRORED -> publish NOT confirmed.
make_ghapi errored "${head_sha}"
out="$(run_deploy)"
check "errored build -> NOT confirmed" "${out}" "publish NOT confirmed"

if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${fail} assertion(s) (${pass} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: test-results-deploy confirm-published (${pass} assertions)."
