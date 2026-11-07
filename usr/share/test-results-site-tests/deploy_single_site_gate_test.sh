#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guards that site-deploy gates ONLY the site it publishes. site-deploy publishes exactly one
## Pages site; it must run the single-site gate for that one site, NOT the full family -- else an
## unrelated regression on a sibling site (e.g. a CSR a11y violation) blocks the clean publish.
## Two pins:
##   1. site-deploy passes the publish target's site name to the gate (website-tests-single <site>).
##   2. site-deploy resolves website-tests-single by default (not the full-family website-tests).
##
## Drives the REAL site-deploy (no copy) with the gate stubbed via SITE_DEPLOY_WEBSITE_TESTS (it
## records its argv) and `git` stubbed. CANARY: pre-change site-deploy ran the gate with NO site
## argument, so the recorded argv was empty -- this fails on old code.

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

## A known Pages-site basename so site-deploy resolves its per-site env var; git is stubbed, so the
## dir only has to exist (never a real repo).
repo_dir="${work}/org-ai-assisted.github.io"
mkdir --parents -- "${repo_dir}"

bin="${work}/bin"
mkdir --parents -- "${bin}"
gate_argv="${work}/gate.argv"

## Gate stub (via the seam): record its argv, pass. This stands in for website-tests-single.
gate="${work}/gate-stub"
cat > "${gate}" <<STUB
#!/bin/bash
printf '%s\n' "\$@" > "${gate_argv}"
exit 0
STUB
chmod +x -- "${gate}"

## git stub: answer the branch query; succeed otherwise (incl. push).
cat > "${bin}/git" <<'STUB'
#!/bin/bash
case "$*" in
   *--abbrev-ref*) printf '%s\n' 'master' ;;
esac
exit 0
STUB
chmod +x -- "${bin}/git"

PATH="${bin}:${PATH}" SITE_DEPLOY_WEBSITE_TESTS="${gate}" \
   "${site_deploy}" --repo "${repo_dir}" >/dev/null 2>&1 || true

## CANARY: the gate stub must have been reached, or the assertion below is vacuous.
if [ ! -s "${gate_argv}" ]; then
   printf '%s\n' "FAIL: gate stub was never invoked with any argument (site-deploy passed no site name)" >&2
   fail=$((fail + 1))
else
   check "site-deploy passes the publish target's site name to the gate" \
      "$(cat -- "${gate_argv}")" "org-ai-assisted.github.io"
fi

## site-deploy resolves the single-site front by default (not the full-family website-tests).
if grep --quiet --fixed-strings 'website-tests-single' "${site_deploy}"; then
   printf '%s\n' "PASS: site-deploy resolves website-tests-single (single-site gate), not the full family"
   pass=$((pass + 1))
else
   printf '%s\n' "FAIL: site-deploy does not resolve website-tests-single -- it would gate the full family" >&2
   fail=$((fail + 1))
fi

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
