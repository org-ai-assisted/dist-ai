#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drives the REAL test-results-deploy driver with `rsync` stubbed to record its argv and fail
## (so the real generator / site-deploy never run, keeping this pure logic -- no root, no network).
## Guards the plane-sync mechanism: a RESUMABLE, INCREMENTAL rsync mirror into a PERSISTENT local
## cache. The prior tar-over-ssh whole-tree re-pull was non-resumable -- it restarted the whole
## 100M+ plane from zero on every retry over a degraded link and never finished, wedging every
## publish. This locks the properties that fix it: --partial (resumable), --delete (exact delta
## mirror), and a STABLE mirror dest reused across runs (not a per-run throwaway).

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
check_eq() {
   ## $1 description, $2 actual, $3 expected (exact)
   if [ "$2" = "$3" ]; then
      printf '%s\n' "PASS: $1"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: $1" "  expected: $3" "  actual: $2" >&2
      fail=$((fail + 1))
   fi
}
check_absent() {
   ## $1 description, $2 actual, $3 substring that must NOT appear
   if [[ "$2" != *"$3"* ]]; then
      printf '%s\n' "PASS: $1"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: $1" "  must NOT contain: $3" "  actual: $2" >&2
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

## Stubs on PATH: rsync records its argv + the ambient TMPDIR then fails (exit 7) so the driver
## dies at the sync `|| die` and never reaches the real generator / site-deploy.
stubdir="${workdir}/stub-bin"
mkdir --parents -- "${stubdir}"
argv_file="${workdir}/rsync.argv"
tmpdir_file="${workdir}/rsync.tmpdir"

cat > "${stubdir}/rsync" <<EOF
#!/bin/bash
printf '%s\n' "\$@" > "${argv_file}"
printf '%s\n' "\${TMPDIR:-unset}" > "${tmpdir_file}"
exit 7
EOF
chmod +x -- "${stubdir}/rsync"

for stub in site-deploy test-results-site-generate; do
   cat > "${stubdir}/${stub}" <<'EOF'
#!/bin/bash
exit 0
EOF
   chmod +x -- "${stubdir}/${stub}"
done

run_deploy() {
   ## $1 extra env assignments (space-separated KEY=VAL), rest ignored. Returns driver rc.
   local rc=0
   PATH="${stubdir}:${PATH}" HOME="${workdir}" TEST_RESULTS_PAGES_REPO="${pages_repo}" \
      TEST_RESULTS_DEPLOY_TARGET=server-admin TEST_RESULTS_REMOTE=/var/www/results \
      "${deploy}" >/dev/null 2>&1 || rc=$?
   return "${rc}"
}

rc=0
run_deploy || rc=$?

## CANARY: the stub must actually have been reached, or the assertions below are vacuous.
if [ ! -s "${argv_file}" ]; then
   printf '%s\n' "FAIL: rsync stub was never invoked (driver died before the sync; rc=${rc})" >&2
   exit 1
fi

argv="$(cat -- "${argv_file}")"
check "rsync remote targets the results plane"                 "${argv}" "server-admin:/var/www/results"
check "rsync is RESUMABLE (--partial -- the wedge fix)"         "${argv}" "--partial"
check "rsync verifies by content (--checksum -- persistent mirror, no stale/partial keep)" \
   "${argv}" "--checksum"
check "rsync is an exact delta mirror (--delete)"              "${argv}" "--delete"
check "rsync excludes .git"                                    "${argv}" "--exclude=.git"
check "rsync neutralizes symlinks + clears stale (--munge-links, not --safe-links)" \
   "${argv}" "--munge-links"
check_absent "rsync omits --perms so umask governs the owner-only mirror (F1)" "${argv}" "--perms"
check "rsync recurses"                                         "${argv}" "--recursive"

## The destination is a PERSISTENT mirror on the disk cache base, NOT a per-run throwaway staging
## tree. CANARY: the pre-fix driver passed a fresh `deploy.XXXXXX/results` sandbox dest each run;
## '/mirror/results' + the absence of a 'deploy.' prefix in the dest both fail on that old code.
mirror_dest="$(printf '%s\n' "${argv}" | tail -1)"
check "rsync dest is the PERSISTENT mirror on the disk cache base" \
   "${mirror_dest}" "/.cache/test-results-deploy/mirror/results"

## TMPDIR scratch (private git index / commit message) still lands on the disk base, not the small
## /tmp tmpfs. Canary: the pre-fix driver left TMPDIR at the ambient /tmp.
check "driver sets TMPDIR to the disk scratch, not the tmpfs" \
   "$(cat -- "${tmpdir_file}" 2>/dev/null || true)" "/.cache/test-results-deploy/deploy."

if [ -d "${workdir}/.cache/test-results-deploy/mirror/results" ]; then
   printf '%s\n' "PASS: persistent mirror dir created on disk"
   pass=$((pass + 1))
else
   printf '%s\n' "FAIL: persistent mirror dir not created (${workdir}/.cache/test-results-deploy/mirror/results)" >&2
   fail=$((fail + 1))
fi

## F1: the persistent mirror holds the raw plane (screenshots + pre-redaction OCR), so it must be
## owner-only -- not world-readable at rest. The driver chmods the mirror root 0700. Canary: the
## pre-fix driver created it under the inherited umask (0755), so this fails on old code.
check_eq "persistent mirror dir is owner-only 0700 (F1 -- raw plane not world-readable)" \
   "$(stat -c '%a' "${workdir}/.cache/test-results-deploy/mirror/results" 2>/dev/null || true)" "700"

## INCREMENTAL regression: a SECOND run must reuse the SAME mirror dest -- the whole point of the
## fix (transfer only the delta into a kept tree). The pre-fix per-run mktemp dest differed every
## run, so this exact-match check fails on the old code.
dest_run1="${mirror_dest}"
run_deploy || true
dest_run2="$(tail -1 -- "${argv_file}")"
check_eq "second run reuses the SAME persistent mirror dest (incremental, not re-pulled)" \
   "${dest_run2}" "${dest_run1}"

## TEST_RESULTS_STAGING_DIR relocates the mirror base (safe default, overridable).
override_base="${workdir}/custom-stage"
PATH="${stubdir}:${PATH}" HOME="${workdir}" TEST_RESULTS_PAGES_REPO="${pages_repo}" \
   TEST_RESULTS_DEPLOY_TARGET=server-admin TEST_RESULTS_REMOTE=/var/www/results \
   TEST_RESULTS_STAGING_DIR="${override_base}" \
   "${deploy}" >/dev/null 2>&1 || true
check "TEST_RESULTS_STAGING_DIR relocates the mirror base" \
   "$(tail -1 -- "${argv_file}" 2>/dev/null || true)" "${override_base}/mirror/results"

## TEST_RESULTS_MIRROR_DIR overrides the mirror location directly.
override_mirror="${workdir}/custom-mirror"
PATH="${stubdir}:${PATH}" HOME="${workdir}" TEST_RESULTS_PAGES_REPO="${pages_repo}" \
   TEST_RESULTS_DEPLOY_TARGET=server-admin TEST_RESULTS_REMOTE=/var/www/results \
   TEST_RESULTS_MIRROR_DIR="${override_mirror}" \
   "${deploy}" >/dev/null 2>&1 || true
check "TEST_RESULTS_MIRROR_DIR overrides the mirror location" \
   "$(tail -1 -- "${argv_file}" 2>/dev/null || true)" "${override_mirror}/results"

## F3: a RELATIVE TEST_RESULTS_STAGING_DIR must absolutize cleanly even with CDPATH set. Without
## `CDPATH= cd`, a CDPATH hit makes cd echo the resolved dir, doubling staging_base into a two-line
## value that corrupts every derived path. Run with cwd + CDPATH pointing at the dir that holds the
## relative staging name, so a bare `cd <rel>` would resolve via CDPATH and print. CANARY: on the
## pre-fix `cd ... && pwd`, the clean mirror dir below is never created (the path gains a newline).
rel_base='relcdstage'
mkdir --parents -- "${workdir}/${rel_base}"
(
   cd -- "${workdir}" || exit 0
   CDPATH="${workdir}" PATH="${stubdir}:${PATH}" HOME="${workdir}" \
      TEST_RESULTS_PAGES_REPO="${pages_repo}" TEST_RESULTS_DEPLOY_TARGET=server-admin \
      TEST_RESULTS_REMOTE=/var/www/results TEST_RESULTS_STAGING_DIR="${rel_base}" \
      "${deploy}" >/dev/null 2>&1 || true
)
if [ -d "${workdir}/${rel_base}/mirror/results" ]; then
   printf '%s\n' "PASS: relative staging dir + CDPATH absolutizes cleanly (F3)"
   pass=$((pass + 1))
else
   printf '%s\n' "FAIL: relative staging dir + CDPATH corrupted the mirror path (F3)" >&2
   fail=$((fail + 1))
fi

printf '%s\n' "===== deploy_test: ${pass} pass, ${fail} fail ====="
[ "${fail}" -eq 0 ]
