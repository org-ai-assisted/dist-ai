#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## Pins the jscov lane wiring + its env-unmet contract in usr/bin/webcheck-jscov-sandbox and
## usr/bin/website-tests:
##   1. When the gate can run neither locally (node+c8 absent) NOR in a usable sandbox, the
##      driver must exit 77 (env-unmet SKIP) so delegate_sandbox_lane maps it to SKIP -- NOT
##      die 1, which the launcher turns into a FAIL (a lane that merely lacks its runtime must
##      not read as a red). Pre-fix the driver was sandbox-only and died 1 here -> this FAILs.
##   2. website-tests must delegate the jscov lane, else the 100% JS coverage gate runs nowhere.
##
## Drives the REAL shipped driver (no synthetic copy). WEBCHECK_NO_LOCAL=1 forces the non-local
## branch and WEBSITE_TESTS_NO_SANDBOX=1 trips the env-unmet short-circuit BEFORE any sandbox
## probe or staging, so the 77 path is reached deterministically with no sandbox needed. Pre-fix
## (sandbox-only) the driver died 1 instead -> the first assertion FAILs on old code.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*" >&2; }

test_dir="$(cd -- "$(dirname -- "$(readlink --canonicalize -- "$0")")" && pwd)"
driver="${test_dir}/../../bin/webcheck-jscov-sandbox"
[ -r "${driver}" ] || driver='/usr/bin/webcheck-jscov-sandbox'
runner="${test_dir}/../../bin/website-tests"
[ -r "${runner}" ] || runner='/usr/bin/website-tests'
for f in "${driver}" "${runner}"; do
   if [ ! -r "${f}" ]; then
      printf '%s\n' "FATAL: not found: ${f}" >&2
      exit 1
   fi
done

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## --- 1. env-unmet -> exit 77 (SKIP), never die 1 ---

## A valid site root (the 77 short-circuit precedes root validation, but keep it realistic).
site="${work}/site"
mkdir --parents -- "${site}"
touch -- "${site}/index.html"

skip_rc=0
skip_err="$(WEBCHECK_NO_LOCAL=1 WEBSITE_TESTS_NO_SANDBOX=1 \
   "${driver}" "${site}" 2>&1 1>/dev/null)" || skip_rc=$?
if [ "${skip_rc}" -eq 77 ] && [[ "${skip_err}" == *'SKIP (77)'* ]]; then
   pass 'webcheck-jscov-sandbox: env-unmet (no local node+c8, no usable sandbox) exits 77 SKIP, not die 1'
else
   fail "webcheck-jscov-sandbox: env-unmet did not exit 77 (rc=${skip_rc}, err='${skip_err}')"
fi

## --- 2. the jscov lane is wired into website-tests ---

if grep --quiet --extended-regexp 'delegate_sandbox_lane .*webcheck-jscov-sandbox' -- "${runner}"; then
   pass 'website-tests: delegates the jscov lane (webcheck-jscov-sandbox)'
else
   fail 'website-tests: jscov lane not wired (no delegate_sandbox_lane for webcheck-jscov-sandbox)'
fi

printf '%s\n' "" "test_website_jscov_lane: ${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
