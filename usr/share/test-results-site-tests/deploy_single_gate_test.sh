#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guards that site-deploy runs the website-tests gate ONCE, not twice. site-deploy runs the
## suite in-process, then pushes; the push fires each site repo's pre-push hook, which re-runs
## the SAME suite via `site-deploy --check-only`. Doubling a ~15-20min browser suite is the
## deploy's dominant cost. The fix: site-deploy's own push carries SITE_DEPLOY_SKIP=1 (the
## identical gate just ran green on this checkout, in this process), so the hook does NOT re-run
## it; a bare `git push` by anyone else is unaffected.
##
## Drives the REAL site-deploy (no copy) with the gate stubbed via SITE_DEPLOY_WEBSITE_TESTS and
## `git` stubbed to record the push environment. CANARY: the push must see SITE_DEPLOY_SKIP=1 --
## the pre-fix push did not set it, so this fails on old code.

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
gate_calls="${work}/gate.calls"
push_env="${work}/push.env"

## Gate stub (via the seam): record each invocation, pass.
gate="${work}/gate-stub"
cat > "${gate}" <<STUB
#!/bin/bash
printf '%s\n' "ran" >> "${gate_calls}"
exit 0
STUB
chmod +x -- "${gate}"

## git stub: record the push environment; answer the branch query; succeed otherwise (the
## is-inside-work-tree probe). A real git/remote/hook is not needed to observe the push env.
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

PATH="${bin}:${PATH}" SITE_DEPLOY_WEBSITE_TESTS="${gate}" \
   "${site_deploy}" --repo "${repo_dir}" >/dev/null 2>&1 || true

gate_count="$(wc -l < "${gate_calls}" 2>/dev/null || printf '%s' 0)"
if [ "${gate_count}" -eq 1 ]; then
   printf '%s\n' "PASS: website-tests gate ran exactly once in-process"
   pass=$((pass + 1))
else
   printf '%s\n' "FAIL: website-tests gate ran ${gate_count} time(s), expected 1" >&2
   fail=$((fail + 1))
fi

check "site-deploy's own push suppresses the pre-push gate re-run (SITE_DEPLOY_SKIP=1)" \
   "$(cat -- "${push_env}" 2>/dev/null || true)" "SITE_DEPLOY_SKIP=1"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
