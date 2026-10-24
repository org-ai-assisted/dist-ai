#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guards site-deploy's operator override (--record-and-publish, a FLAG only -- no env form):
##  - a FAILED gate WITHOUT the override REFUSES and does not push -- the safe default;
##  - a COMPLETE red (exit 1 WITH website-tests' suite-complete marker) WITH the override prints a
##    loud WARNING naming the failed check(s) and publishes, the push carrying SITE_DEPLOY_SKIP=1
##    so the pre-push hook does not re-gate;
##  - an EARLY exit 1 (no marker -- aborted before the site checks), a SKIP (77) or env-unmet (78)
##    STILL refuses even WITH the override: nothing was verified to completion, only a KNOWN
##    complete red is overridable;
##  - an ambient SITE_DEPLOY_RECORD=1 env does NOT enable it (flag-only, so it cannot leak into
##    the automated test-results-deploy path).
##
## Drives the REAL site-deploy (no copy): the gate is stubbed via SITE_DEPLOY_WEBSITE_TESTS and
## git via PATH so a push is observable without a real repo/remote. Canary: on code lacking the
## override, the WITH-override failing case REFUSES and never pushes, so "pushed:yes" FAILS.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
repo_root="$(cd -- "${script_dir}/../../.." && pwd)"
site_deploy="${repo_root}/usr/bin/site-deploy"
[ -x "${site_deploy}" ] || site_deploy='/usr/bin/site-deploy'
if [ ! -x "${site_deploy}" ]; then
   printf '%s\n' "site-deploy not found" >&2
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

## A known Pages-site basename so site-deploy resolves its per-site env var; git is stubbed, so
## the dir only has to exist (never a real repo).
repo_dir="${work}/org-ai-assisted.github.io"
mkdir --parents -- "${repo_dir}"

bin="${work}/bin"
mkdir --parents -- "${bin}"
push_env="${work}/push.env"

## git stub: on push, record SITE_DEPLOY_SKIP (presence of the file = a push happened); answer the
## branch query; succeed on the is-inside-work-tree probe.
cat > "${bin}/git" <<STUB
#!/bin/bash
for a in "\$@"; do
   if [ "\$a" = 'push' ]; then
      printf '%s\n' "SITE_DEPLOY_SKIP=\${SITE_DEPLOY_SKIP:-unset}" > "${push_env}"
      exit 0
   fi
done
case "\$*" in
   *--abbrev-ref*) printf '%s\n' 'master' ;;
esac
exit 0
STUB
chmod +x -- "${bin}/git"

gate="${work}/gate-stub"
make_gate() {
   ## $1 = exit code. Pass 'marker' as $2 to also emit website-tests' suite-complete signal (the
   ## suite ran every lane to its end); omit it to model an EARLY abort (a missing/failing required
   ## unit test exits 1 before the site checks run, and never prints the marker). The FAIL line
   ## lets the override WARNING name the check.
   cat > "${gate}" <<'STUB'
#!/bin/bash
printf '%s\n' 'FAIL org-ai-assisted.github.io: demo consistency check' >&2
STUB
   if [ "${2:-}" = 'marker' ]; then
      printf '%s\n' "printf '%s\\n' 'website-tests: suite-complete' >&2" >> "${gate}"
   fi
   printf '%s\n' "exit $1" >> "${gate}"
   chmod +x -- "${gate}"
}

out=''
rc=0
run_deploy() {
   ## Drive the real site-deploy with the stubs; capture combined output in `out`, exit in `rc`.
   safe-rm --force -- "${push_env}"
   out="$(PATH="${bin}:${PATH}" SITE_DEPLOY_WEBSITE_TESTS="${gate}" \
      "${site_deploy}" --repo "${repo_dir}" "$@" 2>&1)" && rc=0 || rc="$?"
}

pushed() { [ -f "${push_env}" ] && printf '%s' 'pushed:yes' || printf '%s' 'pushed:no'; }
refused() { [ "${rc}" -ne 0 ] && printf '%s' 'refused:yes' || printf '%s' 'refused:no'; }

## 1. Failed gate, NO override -> refuse, no push (unchanged default).
make_gate 1
run_deploy
check "failed gate without override refuses" "$(refused)" "refused:yes"
check "failed gate without override does not push" "$(pushed)" "pushed:no"

## 2. A COMPLETE red (exit 1 WITH the suite-complete marker), WITH --record-and-publish ->
## loud WARNING names the check, and it publishes.
make_gate 1 marker
run_deploy --record-and-publish
check "override publishes past a complete failed gate" "$(pushed)" "pushed:yes"
check "override push carries SITE_DEPLOY_SKIP=1" \
   "$(cat -- "${push_env}" 2>/dev/null || true)" "SITE_DEPLOY_SKIP=1"
check "override exits 0 (published)" "rc:${rc}" "rc:0"
check "override WARNING is loud" "${out}" "publishing PAST a FAILED gate"
check "override WARNING names the failed check" "${out}" "demo consistency check"

## 3. An EARLY exit 1 -- WITHOUT the suite-complete marker (website-tests aborted before the site
## checks ran, e.g. a missing/failing required unit test) -- is NOT overridable: the site was not
## verified, so publishing it is the false green the gate prevents. Refuse even WITH the flag.
make_gate 1
run_deploy --record-and-publish
check "exit 1 without the completion marker still refuses" "$(refused)" "refused:yes"
check "exit 1 without the completion marker does not push" "$(pushed)" "pushed:no"

## 3b. The marker is matched as a WHOLE LINE: a line that merely CONTAINS the marker text as a
## substring (an early-FATAL message echoing a checkout path like .../website-tests: suite-complete/)
## must NOT be taken for completion. Exit 1 with such a line but no standalone marker -> refuse.
cat > "${gate}" <<'STUB'
#!/bin/bash
printf '%s\n' "website-tests: FATAL: site override '/checkout/website-tests: suite-complete/x' has no index.html" >&2
exit 1
STUB
chmod +x -- "${gate}"
run_deploy --record-and-publish
check "a marker substring inside another line does not forge completion" "$(refused)" "refused:yes"
check "forged-marker-substring run does not push" "$(pushed)" "pushed:no"

## 4. An INCOMPLETE result (nothing fully verified) is NEVER overridable: 77 (SKIP target-absent,
## no marker) and 78 (SKIP env-unmet -- which DOES reach the marker) both still refuse, because the
## override waives only a COMPLETE RED (exit 1 with marker), never a skip. Keyed on the true suite
## exit, so a marker-bearing 78 is still refused.
make_gate 77
run_deploy --record-and-publish
check "exit 77 still refuses even with the override" "$(refused)" "refused:yes"
check "exit 77 with the override does not push" "$(pushed)" "pushed:no"
make_gate 78 marker
run_deploy --record-and-publish
check "exit 78 (marker present) still refuses even with the override" "$(refused)" "refused:yes"
check "exit 78 with the override does not push" "$(pushed)" "pushed:no"

## 5. --check-only must reflect the true result even WITH the override flag: a complete failing
## gate refuses (non-zero) and does not push, so a gate caller (the pre-push hook runs `site-deploy
## --check-only`) never gets a green from a red suite.
make_gate 1 marker
run_deploy --check-only --record-and-publish
check "check-only + override + failure still refuses (non-zero)" "$(refused)" "refused:yes"
check "check-only + override never pushes" "$(pushed)" "pushed:no"

## 6. The override is FLAG-ONLY: an ambient SITE_DEPLOY_RECORD=1 env must NOT enable it (so it
## cannot leak into the automated test-results-deploy path, which calls site-deploy with no flag).
## A complete failing gate with only the env set still REFUSES and does not push.
make_gate 1 marker
safe-rm --force -- "${push_env}"
out="$(PATH="${bin}:${PATH}" SITE_DEPLOY_WEBSITE_TESTS="${gate}" SITE_DEPLOY_RECORD=1 \
   "${site_deploy}" --repo "${repo_dir}" 2>&1)" && rc=0 || rc="$?"
check "ambient SITE_DEPLOY_RECORD env does NOT enable the override" "$(refused)" "refused:yes"
check "ambient SITE_DEPLOY_RECORD env does not push" "$(pushed)" "pushed:no"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
