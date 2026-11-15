#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guards that site-deploy's "published" means the commit is actually LIVE on GitHub Pages, not
## merely pushed. A push only QUEUES the async Pages build; a build that fails (e.g. the server-side
## re-gate going red) or never runs leaves the PRIOR commit served while site-deploy already
## declared success -- the silent stale publish an operator hit on CSR. site-deploy now confirms the
## github-pages DEPLOYMENT for the pushed sha reaches 'success', else FAILS LOUD.
##
## Drives the REAL site-deploy (no copy): the browser gate is stubbed via SITE_DEPLOY_WEBSITE_TESTS,
## `git` is stubbed (push succeeds, rev-parse/remote answered), and `github-api` is stubbed to a
## chosen deployment status. CANARY: case 2 -- a FAILED deployment must make site-deploy exit
## non-zero; the pre-fix code printed "published" and exited 0, so it fails on old code. Hermetic.

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

work="$(mktemp --directory)"
cleanup() {
   # shellcheck disable=SC2317  ## invoked via the EXIT trap
   safe-rm --recursive --force -- "${work}"
}
trap cleanup EXIT

## A known Pages-site basename so site-deploy resolves its per-site env var; git is stubbed, so the
## dir only has to exist (never a real repo).
repo_dir="${work}/org-ai-assisted.github.io"
mkdir --parents -- "${repo_dir}"

bin="${work}/bin"
mkdir --parents -- "${bin}"

## Gate stub (via the seam): pass, so site-deploy reaches the push + confirm.
gate="${work}/gate-stub"
cat > "${gate}" <<'STUB'
#!/bin/bash
exit 0
STUB
chmod +x -- "${gate}"

## git stub: push RECORDS its argv (so a test can assert the pushed refspec) then succeeds; answers
## the branch query, the pushed HEAD sha, and the remote URL (so owner/repo derivation runs); the
## is-inside-work-tree probe falls through to exit 0.
## The PUSH url and FETCH url resolve to DIFFERENT owner/repo so the test can prove the confirm
## keys on the repo we PUSHED to (`remote get-url --push`), not the fetch url (agy finding).
push_argv="${work}/push.argv"
cat > "${bin}/git" <<STUB
#!/bin/bash
for a in "\$@"; do
   if [ "\$a" = 'push' ]; then
      printf '%s\n' "\$*" > "${push_argv}"
      exit 0
   fi
done
case "\$*" in
   *--abbrev-ref*) printf '%s\n' 'master' ;;
   *'rev-parse HEAD'*) printf '%s\n' 'cafe1234cafe1234cafe1234cafe1234cafe1234' ;;
   *'remote get-url --push'*) printf '%s\n' 'git@github.com:org-ai-assisted/org-ai-assisted.github.io.git' ;;
   *'remote get-url'*) printf '%s\n' 'git@github.com:fetch-mirror/wrong-fetch-repo.git' ;;
esac
exit 0
STUB
chmod +x -- "${bin}/git"

## Write a github-api stub that reports the given github-pages deployment state for our sha.
## STATE='' with an empty deployment list exercises the no-deployment (timeout) path.
ghapi_log="${work}/ghapi.calls"
make_ghapi() {
   ## $1 deployments-json, $2 statuses-json
   cat > "${bin}/github-api" <<EOF
#!/bin/bash
## Log the full API path so a test can assert WHICH owner/repo was queried.
printf '%s\n' "\$2" >> "${ghapi_log}"
case "\$2" in
   */deployments/*/statuses*) printf '%s\n' '$2' ;;
   */deployments?environment=github-pages*) printf '%s\n' '$1' ;;
   *) printf '%s\n' '[]' ;;
esac
EOF
   chmod +x -- "${bin}/github-api"
}

run_deploy() {
   ## $1 extra env assignment ('' or 'SITE_DEPLOY_NO_CONFIRM=1'); sets globals out, rc.
   local extra="${1:-}"
   true > "${ghapi_log}"
   if env PATH="${bin}:${PATH}" \
      SITE_DEPLOY_WEBSITE_TESTS="${gate}" \
      SITE_DEPLOY_CONFIRM_TIMEOUT=2 \
      SITE_DEPLOY_CONFIRM_POLL_INTERVAL=1 \
      ${extra:+"${extra}"} \
      "${site_deploy}" --repo "${repo_dir}" > "${work}/out" 2>&1
   then
      rc=0
   else
      rc=$?
   fi
   out="$(cat -- "${work}/out")"
}

## 1. github-pages deployment for our sha reports success -> published, exit 0.
make_ghapi '[{"id":101}]' '[{"state":"success"}]'
run_deploy ''
check "deployment success -> published (live deploy confirmed)" "${out}" "live deploy confirmed"
check_rc "deployment success -> exit 0" "${rc}" zero
## The push must pin the EXACT captured sha (<sha>:refs/heads/<branch>), not the bare branch name,
## so a concurrent ref move cannot publish a commit different from the one confirmed.
check "push pins the captured sha, not the bare branch" \
   "$(cat -- "${push_argv}" 2>/dev/null || true)" "cafe1234cafe1234cafe1234cafe1234cafe1234:refs/heads/master"

## 2. CANARY: deployment for our sha reports failure -> FAIL LOUD, non-zero (pre-fix printed
##    "published" and exited 0).
make_ghapi '[{"id":102}]' '[{"state":"failure"}]'
run_deploy ''
check "deployment failure -> live site NOT updated" "${out}" "live site is NOT updated"
check_rc "deployment failure -> non-zero exit" "${rc}" nonzero

## 3. No deployment ever registers -> timeout -> FAIL LOUD, non-zero.
make_ghapi '[]' '[]'
run_deploy ''
check_rc "no deployment -> non-zero exit (timeout)" "${rc}" nonzero
check "no deployment -> NOT updated message" "${out}" "NOT updated"

## 4. SITE_DEPLOY_NO_CONFIRM=1 -> pushed, UNVERIFIED, exit 0, and the confirm API is NOT called.
make_ghapi '[{"id":104}]' '[{"state":"failure"}]'
run_deploy 'SITE_DEPLOY_NO_CONFIRM=1'
check "NO_CONFIRM -> UNVERIFIED notice" "${out}" "UNVERIFIED"
check_rc "NO_CONFIRM -> exit 0 (push succeeded)" "${rc}" zero
check "NO_CONFIRM -> confirm API not called" "$([ -s "${ghapi_log}" ] && printf '%s' called || printf '%s' none)" "none"

## 5. The confirm keys on the PUSH url's owner/repo, not the fetch url's. The git stub resolves push
##    -> org-ai-assisted/org-ai-assisted.github.io but fetch -> fetch-mirror/wrong-fetch-repo; the
##    github-api path must carry the PUSH repo. CANARY: pre-`--push` code queried the fetch repo.
make_ghapi '[{"id":105}]' '[{"state":"success"}]'
run_deploy ''
check "confirm queries the PUSH url's owner/repo" "$(cat -- "${ghapi_log}")" "org-ai-assisted/org-ai-assisted.github.io/deployments"
check "confirm does NOT query the fetch url's owner/repo" \
   "$(grep -c 'fetch-mirror/wrong-fetch-repo' -- "${ghapi_log}" || true)" "0"

## 6. CANARY: HEAD moves DURING the gate -> site-deploy must refuse to publish an ungated commit.
##    The stub answers `rev-parse HEAD` with a DIFFERENT sha before vs after the gate (a concurrent
##    ref move); the pre-fix code captured the sha only AFTER the gate and pushed it, shipping an
##    ungated commit. So on old code this pushes + exits 0 with no "HEAD moved" message.
safe-rm --force -- "${push_argv}"
head_calls="${work}/head.calls"
true > "${head_calls}"
cat > "${bin}/git" <<STUB
#!/bin/bash
for a in "\$@"; do
   if [ "\$a" = 'push' ]; then
      printf '%s\n' "\$*" > "${push_argv}"
      exit 0
   fi
done
case "\$*" in
   *--abbrev-ref*) printf '%s\n' 'master' ;;
   *'rev-parse HEAD'*)
      n="\$(cat "${head_calls}" 2>/dev/null || printf '%s' 0)"
      n=\$(( n + 1 ))
      printf '%s\n' "\$n" > "${head_calls}"
      if [ "\$n" -eq 1 ]; then
         printf '%s\n' 'aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111'
      else
         printf '%s\n' 'bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222'
      fi
      ;;
   *'remote get-url --push'*) printf '%s\n' 'git@github.com:org-ai-assisted/org-ai-assisted.github.io.git' ;;
   *'remote get-url'*) printf '%s\n' 'git@github.com:fetch-mirror/wrong-fetch-repo.git' ;;
esac
exit 0
STUB
chmod +x -- "${bin}/git"
make_ghapi '[{"id":106}]' '[{"state":"success"}]'
run_deploy ''
check_rc "HEAD moved during gate -> non-zero exit" "${rc}" nonzero
check "HEAD moved during gate -> refused with reason" "${out}" "HEAD moved during the gate"
check "HEAD moved during gate -> did NOT push" \
   "$([ -e "${push_argv}" ] && printf '%s' pushed || printf '%s' none)" "none"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
