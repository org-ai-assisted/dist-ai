#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guards site-deploy's operator override (--record-and-publish / SITE_DEPLOY_RECORD=1):
##  - a FAILED gate WITHOUT the override REFUSES and does not push -- the safe default;
##  - a FAILED gate WITH the override prints a loud WARNING naming the failed check(s) and
##    publishes anyway, the push carrying SITE_DEPLOY_SKIP=1 so the pre-push hook does not re-gate;
##  - a SKIP (exit 77) STILL refuses even WITH the override -- nothing verified is never
##    overridable, only a KNOWN red is.
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
   ## $1 = exit code. Emit a FAIL line (so the override WARNING can name the check) then exit.
   cat > "${gate}" <<STUB
#!/bin/bash
printf '%s\n' 'FAIL org-ai-assisted.github.io: demo consistency check' >&2
exit $1
STUB
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

## 2. Failed gate, WITH --record-and-publish -> loud WARNING names the check, and it publishes.
make_gate 1
run_deploy --record-and-publish
check "override publishes past a failed gate" "$(pushed)" "pushed:yes"
check "override push carries SITE_DEPLOY_SKIP=1" \
   "$(cat -- "${push_env}" 2>/dev/null || true)" "SITE_DEPLOY_SKIP=1"
check "override exits 0 (published)" "rc:${rc}" "rc:0"
check "override WARNING is loud" "${out}" "publishing PAST a failed gate"
check "override WARNING names the failed check" "${out}" "demo consistency check"

## 3. SKIP (exit 77), WITH the override -> STILL refuses, no push.
make_gate 77
run_deploy --record-and-publish
check "exit 77 still refuses even with the override" "$(refused)" "refused:yes"
check "exit 77 with the override does not push" "$(pushed)" "pushed:no"

## 4. The SITE_DEPLOY_RECORD=1 env is equivalent to the flag.
make_gate 1
safe-rm --force -- "${push_env}"
out="$(PATH="${bin}:${PATH}" SITE_DEPLOY_WEBSITE_TESTS="${gate}" SITE_DEPLOY_RECORD=1 \
   "${site_deploy}" --repo "${repo_dir}" 2>&1)" && rc=0 || rc="$?"
check "SITE_DEPLOY_RECORD=1 env enables the override" "$(pushed)" "pushed:yes"

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
