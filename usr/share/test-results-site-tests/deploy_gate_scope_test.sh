#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guards that the results publish gates ONLY org-ai-assisted. test-results-deploy publishes the
## automated-test-results plane via site-deploy, whose website-tests gate otherwise auto-discovers
## and gates ALL FOUR family sites -- so an unrelated sibling-site regression (e.g. a CSR a11y
## violation) blocks the clean results publish. The fix: test-results-deploy sets
## WEBSITE_TESTS_ONLY_SITES=org-ai-assisted.github.io on its site-deploy invocation, which
## site-deploy forwards to website-tests, scoping the gate to the one site being published.
##
## Drives the REAL test-results-deploy (no copy): sandbox + generator stubbed so the pull/generate
## succeed with no network, a real one-commit git repo so the commit step no-ops, and site-deploy
## stubbed via TEST_RESULTS_SITE_DEPLOY to RECORD the WEBSITE_TESTS_ONLY_SITES it receives, then
## exit non-zero so the driver dies at the publish `|| die` before the network confirm step.
## CANARY: the recorder must have run (else the assertion is vacuous); and the pre-fix driver did
## NOT set the var, so it recorded "unset" -- this fails on old code.

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
   # shellcheck disable=SC2317  ## invoked via the EXIT trap
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

## A real git repo at the Pages-repo basename site-deploy would resolve, with one commit that
## already carries automated-test-results/ -- so the driver's private-index add finds no change
## and the commit step no-ops (no git identity / gate interaction needed to reach publish).
pages_repo="${workdir}/org-ai-assisted.github.io"
mkdir --parents -- "${pages_repo}/automated-test-results"
printf '%s\n' '<!doctype html><title>results</title>' > "${pages_repo}/automated-test-results/index.html"
git -C "${pages_repo}" init --quiet
git -C "${pages_repo}" add -A
git -C "${pages_repo}" -c user.email='test@example.com' -c user.name='test' commit --quiet -m 'seed'

bin="${workdir}/bin"
mkdir --parents -- "${bin}"
only_file="${workdir}/site-deploy.only"

## sandbox stub: on `pull`, create the destination results tree (last arg) and succeed; the real
## transport/network is never touched.
cat > "${bin}/sandbox" <<'STUB'
#!/bin/bash
mode=''
for a in "$@"; do
   [ "$a" = 'pull' ] && mode='pull'
   dest="$a"
done
if [ "${mode}" = 'pull' ]; then
   mkdir --parents -- "${dest}"
   printf '%s\n' 'placeholder' > "${dest}/placeholder.txt"
fi
exit 0
STUB
chmod +x -- "${bin}/sandbox"

## Generator stub: no-op (the seed commit already has the plane, so nothing changes to commit).
generate="${bin}/test-results-site-generate"
cat > "${generate}" <<'STUB'
#!/bin/bash
exit 0
STUB
chmod +x -- "${generate}"

## site-deploy stub (via the TEST_RESULTS_SITE_DEPLOY seam): record the gate-scope var it was
## handed, then exit non-zero so the driver dies here, before the network confirm step.
site_deploy_stub="${bin}/site-deploy-stub"
cat > "${site_deploy_stub}" <<STUB
#!/bin/bash
printf '%s\n' "\${WEBSITE_TESTS_ONLY_SITES:-unset}" > "${only_file}"
exit 1
STUB
chmod +x -- "${site_deploy_stub}"

## Run the real driver. It is EXPECTED to fail (the site-deploy stub exits 1 -> die), AFTER the
## recorder has captured the scope var. git ls-remote finds no origin, so the driver publishes.
rc=0
PATH="${bin}:${PATH}" HOME="${workdir}" \
   TEST_RESULTS_PAGES_REPO="${pages_repo}" \
   TEST_RESULTS_REMOTE=/var/www/results \
   TEST_RESULTS_SITE_GENERATE="${generate}" \
   TEST_RESULTS_SITE_DEPLOY="${site_deploy_stub}" \
   "${deploy}" >/dev/null 2>&1 || rc=$?

## CANARY: the recorder must have been reached, or the assertion below is vacuous.
if [ ! -s "${only_file}" ]; then
   printf '%s\n' "FAIL: site-deploy stub was never invoked (driver died before publish; rc=${rc})" >&2
   exit 1
fi

check "test-results-deploy scopes the gate to org-ai-assisted.github.io (WEBSITE_TESTS_ONLY_SITES)" \
   "$(cat -- "${only_file}")" "org-ai-assisted.github.io"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
