#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drives the REAL test-results-deploy driver with `sandbox` stubbed to record its
## argv and fail at the pull step (so the real generator / site-deploy never run,
## keeping this pure logic -- no root, no network). Guards the regression where the
## pull of the /var/www/results plane omitted --allow-system-path: sandbox refuses a
## system path without it, so every unattended deploy failed and the Pages results
## site froze.

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

## Pages repo the driver insists on (checked before the pull).
pages_repo="${workdir}/pages"
mkdir --parents -- "${pages_repo}/.git" "${pages_repo}/automated-test-results"

## Stubs on PATH: sandbox records its argv then fails (exit 7) so the driver dies at
## the pull `|| die` and never reaches the real generator / site-deploy.
stubdir="${workdir}/stub-bin"
mkdir --parents -- "${stubdir}"
argv_file="${workdir}/sandbox.argv"

cat > "${stubdir}/sandbox" <<EOF
#!/bin/bash
printf '%s\n' "\$@" > "${argv_file}"
exit 7
EOF
chmod +x -- "${stubdir}/sandbox"

for stub in site-deploy test-results-site-generate; do
   cat > "${stubdir}/${stub}" <<'EOF'
#!/bin/bash
exit 0
EOF
   chmod +x -- "${stubdir}/${stub}"
done

## Run the real driver; it is EXPECTED to fail (stub pull exits 7 -> die).
## Pin TEST_RESULTS_REMOTE so an ambient value cannot leak in and make the
## "/var/www/results" assertion below non-hermetic (spurious pass/fail by env).
rc=0
PATH="${stubdir}:${PATH}" HOME="${workdir}" TEST_RESULTS_PAGES_REPO="${pages_repo}" \
   TEST_RESULTS_REMOTE=/var/www/results \
   "${deploy}" >/dev/null 2>&1 || rc=$?

## CANARY: the stub must actually have been reached, or the assertions below are vacuous.
if [ ! -s "${argv_file}" ]; then
   printf '%s\n' "FAIL: sandbox stub was never invoked (driver died before the pull; rc=${rc})" >&2
   exit 1
fi

argv="$(cat -- "${argv_file}")"
check "pull invoked" "${argv}" "pull"
check "pull carries --allow-system-path (the regression guard)" "${argv}" "--allow-system-path"
check "pull targets the results plane" "${argv}" "/var/www/results"

printf '%s\n' "===== deploy_test: ${pass} pass, ${fail} fail ====="
[ "${fail}" -eq 0 ]
