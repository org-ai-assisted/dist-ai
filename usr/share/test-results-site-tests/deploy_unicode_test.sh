#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guards test-results-deploy's results-tree commit against the ASCII-only commit gate.
## The published site carries OCR sidecars (.ocr.txt), generated DATA that legitimately
## reproduces on-screen non-ASCII (registered sign, copyright sign, typographic quotes read
## off the installer UI). The commit must therefore carry ALLOW_UNICODE_COMMIT=1, or the gate
## blocks it and NO run with an OCR sidecar can ever publish -- the exact wedge seen live.
##
## Drives the REAL driver + commit path (no copy). The generator is stubbed to emit one unicode
## OCR sidecar (its own job is tested elsewhere); sandbox/site-deploy/github-api are stubbed so
## the pull/publish/confirm steps are hermetic (no root, no network). core.hooksPath points at a
## pre-commit that models the gate's OBSERVABLE override contract -- a staged tree with non-ASCII
## is BLOCKED unless ALLOW_UNICODE_COMMIT=1. The real gate (unicode-show based) lives in
## private-ai-config/claude/git-hooks/pre-commit and is tested there (git-hooks-unicode-test.sh);
## this models only the one property the driver must satisfy, so there is no detector to drift.
##
## CANARY: a direct unicode commit WITHOUT the override is asserted to be blocked (non-vacuous --
## else the main assertion would pass even on the pre-fix driver), and the pre-fix driver, lacking
## ALLOW_UNICODE_COMMIT=1, dies at "commit failed" so HEAD never leaves the init commit.
##
## SAFETY: the only non-ASCII payload is U+00AE REGISTERED SIGN, emitted at runtime via an
## ANSI-C \x escape (never a literal in this file, which is itself ASCII-gated). No secret/PII.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
## <root>/usr/share/test-results-site-tests -> <root> is three levels up.
repo_root="$(cd -- "${script_dir}/../../.." && pwd)"
deploy="${repo_root}/usr/bin/test-results-deploy"
[ -x "${deploy}" ] || deploy='/usr/bin/test-results-deploy'
if [ ! -x "${deploy}" ]; then
   printf '%s\n' "test-results-deploy not found" >&2
   exit 1
fi

pass=0
fail=0
check() {
   if [[ "$2" == *"$3"* ]]; then
      printf '%s\n' "PASS: $1"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: $1" "  expected substring: $3" "  actual: $2" >&2
      fail=$((fail + 1))
   fi
}

work="$(mktemp --directory)"
cleanup() {
   # shellcheck disable=SC2317  ## invoked via the EXIT trap
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

## U+00AE REGISTERED SIGN -- the on-screen character the live OCR sidecar carried.
reg=$'\xc2\xae'

## Modeled ASCII-only commit gate: block a staged tree carrying non-ASCII unless the override
## is set. Models only the observable override contract, not unicode-show's full detector.
hooks_dir="${work}/hooks"
mkdir --parents -- "${hooks_dir}"
cat > "${hooks_dir}/pre-commit" <<'HOOK'
#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
if [ "${ALLOW_UNICODE_COMMIT:-}" = '1' ]; then
   exit 0
fi
staged="$(git diff --cached --no-color)"
hits="$(printf '%s' "${staged}" | LC_ALL=C grep -caP '[\x80-\xff]' || true)"
if [ "${hits}" != '0' ]; then
   printf '%s\n' 'pre-commit BLOCKED: non-ASCII in staged content. Remove, or ALLOW_UNICODE_COMMIT=1' >&2
   exit 1
fi
exit 0
HOOK
chmod +x -- "${hooks_dir}/pre-commit"

## Pages repo + an EMPTY bare origin (ls-remote returns no master tip -> the publish branch runs).
pages="${work}/pages"
mkdir --parents -- "${pages}/automated-test-results"
git -c init.defaultBranch=master -C "${pages}" init --quiet
git -C "${pages}" config user.email 'test@example.com'
git -C "${pages}" config user.name 'Test'
git -C "${pages}" config core.hooksPath "${hooks_dir}"
printf '%s\n' 'placeholder' > "${pages}/README"
git -C "${pages}" add -- README
git -C "${pages}" commit --quiet -m 'init'
git -c init.defaultBranch=master -C "${work}" init --quiet --bare origin.git
git -C "${pages}" remote add origin "${work}/origin.git"

## Non-vacuous: the modeled gate MUST block a unicode commit without the override. Otherwise the
## main assertion (commit landed) would pass even on the pre-fix driver that never set it.
printf '%s\n' "x ${reg} y" > "${pages}/automated-test-results/canary.txt"
git -C "${pages}" add -- automated-test-results/canary.txt
canary_rc=0
git -C "${pages}" commit --quiet -m 'canary' >/dev/null 2>&1 || canary_rc=$?
git -C "${pages}" reset --quiet -- automated-test-results/canary.txt >/dev/null 2>&1 || true
safe-rm --force -- "${pages}/automated-test-results/canary.txt"
if [ "${canary_rc}" -ne 0 ]; then
   printf '%s\n' "PASS: modeled ASCII gate blocks a unicode commit without the override (non-vacuous)"
   pass=$((pass + 1))
else
   printf '%s\n' "FAIL: modeled gate did NOT block unicode -> the main assertion would be vacuous" >&2
   fail=$((fail + 1))
fi

## Stubs. sandbox pull creates the (empty) staging tree then succeeds.
bin="${work}/bin"
mkdir --parents -- "${bin}"
cat > "${bin}/sandbox" <<'STUB'
#!/bin/bash
ispull=0
for a in "$@"; do [ "${a}" = 'pull' ] && ispull=1; done
if [ "${ispull}" = '1' ]; then
   mkdir --parents -- "${@: -1}"
fi
exit 0
STUB
chmod +x -- "${bin}/sandbox"

## site-deploy: a no-op publish (off PATH, reached via the sibling-resolution seam the driver honors).
seam_dir="${work}/seam"
mkdir --parents -- "${seam_dir}"
cat > "${seam_dir}/site-deploy" <<'STUB'
#!/bin/bash
exit 0
STUB
chmod +x -- "${seam_dir}/site-deploy"

## github-api: confirm-published polls the github-pages DEPLOYMENT for the pushed sha; report one
## deployment whose latest status is success so confirm passes fast (this test is about the COMMIT).
cat > "${bin}/github-api" <<'STUB'
#!/bin/bash
case "$2" in
   *'/deployments?'*) printf '%s\n' '[{"id":1}]' ;;
   *'/deployments/'*'/statuses'*) printf '%s\n' '[{"state":"success"}]' ;;
   *) printf '%s\n' '[]' ;;
esac
exit 0
STUB
chmod +x -- "${bin}/github-api"

## Generator stub: emit one unicode OCR sidecar into the Pages results tree (the published DATA
## that trips the ASCII gate). Writes the byte at runtime so this suite stays ASCII.
gen="${work}/gen/test-results-site-generate"
mkdir --parents -- "${work}/gen"
cat > "${gen}" <<'STUB'
#!/bin/bash
set -o errexit
set -o nounset
site_out=""
while [ "$#" -gt 0 ]; do
   case "$1" in
      --site-out) site_out="$2"; shift 2 ;;
      *) shift ;;
   esac
done
mkdir --parents -- "${site_out}/automated-test-results/run-1"
reg=$'\xc2\xae'
printf '%s\n' "Kicksecure ${reg} Welcome" \
   > "${site_out}/automated-test-results/run-1/welcome.ocr.txt"
printf '%s\n' '<html></html>' > "${site_out}/automated-test-results/index.html"
exit 0
STUB
chmod +x -- "${gen}"

out="$( \
   PATH="${bin}:${PATH}" HOME="${work}" SOURCE_DATE_EPOCH=1700000000 \
   TEST_RESULTS_SITE_GENERATE="${gen}" TEST_RESULTS_SITE_DEPLOY="${seam_dir}/site-deploy" \
   TEST_RESULTS_DEPLOY_TARGET='stub' TEST_RESULTS_PAGES_REPO="${pages}" \
   TEST_RESULTS_REMOTE='/var/www/results' \
   TEST_RESULTS_PAGES_OWNER_REPO='org-ai-assisted/org-ai-assisted.github.io' \
   TEST_RESULTS_CONFIRM_TIMEOUT=5 TEST_RESULTS_CONFIRM_POLL_INTERVAL=1 \
   "${deploy}" 2>&1 || true )"

## The commit must have LANDED despite the unicode sidecar (pre-fix driver dies here).
subject="$(git -C "${pages}" log -1 --format=%s 2>/dev/null || true)"
check "results commit landed despite the unicode OCR sidecar" "${subject}" "Deploy image-test results"
intree="$(git -C "${pages}" ls-tree -r --name-only HEAD 2>/dev/null || true)"
check "the unicode OCR sidecar is in the committed tree" \
   "${intree}" "automated-test-results/run-1/welcome.ocr.txt"
## The pre-fix failure mode, asserted ABSENT.
if [[ "${out}" == *"commit failed"* ]]; then
   printf '%s\n' "FAIL: driver reported 'commit failed' (the ASCII gate blocked the results commit)" >&2
   fail=$((fail + 1))
else
   printf '%s\n' "PASS: driver did not hit the 'commit failed' gate rejection"
   pass=$((pass + 1))
fi

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
