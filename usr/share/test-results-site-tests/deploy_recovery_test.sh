#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guards test-results-deploy's unpushed-backlog RECOVERY: when the local Pages branch is AHEAD
## of the published tip, the driver must publish (via site-deploy) even on a run that regenerates
## NO new change -- otherwise a commit stranded by a prior failed push (the exact wedge seen: a
## dozen commits ahead, site frozen) is never sent. Drives the REAL driver + REAL generator (no
## copy) with `sandbox` and `site-deploy` stubbed, SOURCE_DATE_EPOCH pinned so a re-generate is
## byte-identical (the no-change branch), and an EMPTY origin so the published tip is unknown.
## The plane is empty, so the generator does no image work -- Pillow is not needed.
##
## CANARY: the second run must report "no results changes" (it exercises the recovery branch, not
## the ordinary commit+publish path) AND still invoke site-deploy. The pre-fix driver skipped the
## publish when the remote tip could not be read -> stranded -> this fails on old code.

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

## Pages repo + an EMPTY bare origin (nothing pushed -> ls-remote returns no master tip).
pages="${work}/pages"
mkdir --parents -- "${pages}/automated-test-results"
git -c init.defaultBranch=master -C "${pages}" init --quiet
git -C "${pages}" config user.email 'test@example.com'
git -C "${pages}" config user.name 'Test'
## Neutralize the global core.hooksPath (style gate / commit guards) for this throwaway repo.
mkdir --parents -- "${work}/nohooks"
git -C "${pages}" config core.hooksPath "${work}/nohooks"
printf '%s\n' 'placeholder' > "${pages}/README"
git -C "${pages}" add -- README
git -C "${pages}" commit --quiet -m 'init'
origin="${work}/origin.git"
git -c init.defaultBranch=master -C "${work}" init --quiet --bare origin.git
git -C "${pages}" remote add origin "${origin}"

## Stubs: sandbox `pull` creates the (empty) staging results tree then succeeds; site-deploy
## records each call. The REAL generator then renders an empty overview into the Pages repo.
bin="${work}/bin"
mkdir --parents -- "${bin}"
site_marker="${work}/site-deploy.calls"
cat > "${bin}/sandbox" <<STUB
#!/bin/bash
ispull=0
for a in "\$@"; do [ "\$a" = 'pull' ] && ispull=1; done
if [ "\${ispull}" = '1' ]; then
   mkdir --parents -- "\${@: -1}"
fi
exit 0
STUB
chmod +x -- "${bin}/sandbox"
## The REAL site-deploy stub lives OFF PATH, reached only via the sibling-resolution seam. A
## TRIPWIRE site-deploy sits ON PATH: the driver must sibling-resolve (via the seam here), never
## fall through to a PATH copy -- that was the live bug (a stale /usr/bin site-deploy, PATH-found
## under systemd, double-gated the push). If the tripwire fires, resolution regressed to PATH.
seam_dir="${work}/seam"
mkdir --parents -- "${seam_dir}"
path_tripwire="${work}/path-site-deploy.called"
cat > "${seam_dir}/site-deploy" <<STUB
#!/bin/bash
printf '%s\n' "called" >> "${site_marker}"
exit 0
STUB
chmod +x -- "${seam_dir}/site-deploy"
cat > "${bin}/site-deploy" <<STUB
#!/bin/bash
printf '%s\n' "PATH-RESOLVED" >> "${path_tripwire}"
exit 0
STUB
chmod +x -- "${bin}/site-deploy"

## github-api stub: confirm-published polls pages/builds/latest. Report status=built at the
## repo's CURRENT HEAD (the stub runs in the driver's cwd = the pages repo) so confirm passes
## fast -- this test is about the PUBLISH/recovery path, not the live Pages build.
cat > "${bin}/github-api" <<'STUB'
#!/bin/bash
printf '{"status":"built","commit":"%s"}\n' "$(git rev-parse HEAD 2>/dev/null)"
exit 0
STUB
chmod +x -- "${bin}/github-api"

run_driver() {
   ## TEST_RESULTS_SITE_DEPLOY points the driver at the seam stub (off PATH); the driver
   ## sibling-resolves site-deploy and honors this override, never a stale PATH copy.
   PATH="${bin}:${PATH}" HOME="${work}" SOURCE_DATE_EPOCH=1700000000 \
   TEST_RESULTS_SITE_DEPLOY="${seam_dir}/site-deploy" \
   TEST_RESULTS_DEPLOY_TARGET='stub' TEST_RESULTS_PAGES_REPO="${pages}" \
   TEST_RESULTS_REMOTE='/var/www/results' \
   TEST_RESULTS_PAGES_OWNER_REPO='org-ai-assisted/org-ai-assisted.github.io' \
   TEST_RESULTS_CONFIRM_TIMEOUT=5 \
      "${deploy}" 2>&1 || true
}

## Run 1: generator writes automated-test-results/index.html -> a change -> commit + publish.
## HEAD now carries the generated commit; origin is still empty (site-deploy is a stub, no push).
out1="$(run_driver)"
safe-rm --force -- "${site_marker}"

## Run 2: identical generate (pinned epoch) -> NO change -> the no-change branch. Origin is empty,
## so the published tip is unknown -> the driver must publish the stranded commit anyway.
out2="$(run_driver)"
site_calls="$(cat -- "${site_marker}" 2>/dev/null || true)"

check "run 1 committed + published the generated site" "${out1}" "deployed"
check "run 2 hit the no-change branch (recovery, not commit path)" "${out2}" "no results changes"
check "run 2 PUBLISHED the unpushed backlog via site-deploy" "${site_calls}" "called"
if [ -e "${path_tripwire}" ]; then
   printf '%s\n' "FAIL: driver resolved site-deploy via PATH (stale-copy regression), not the sibling/seam" >&2
   fail=$((fail + 1))
else
   printf '%s\n' "PASS: driver did NOT fall through to a PATH site-deploy (sibling-resolved)"
   pass=$((pass + 1))
fi

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
