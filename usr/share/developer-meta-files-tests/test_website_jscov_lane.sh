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

## --- 2. the jscov lane is wired into website-tests AND fed CANONICAL identities ---

## The lane must delegate to webcheck-jscov-sandbox AND pass canonical <site>=<path> pairs
## (jscov_roots built from root_sites) -- NOT bare "${roots[@]}", whose basename would mis-key
## covered.txt for a non-canonical _REPO override and silently drop that site's coverage. This is
## the WIRING pin for the add_site fix: a revert of the lane to bare roots, or dropping the
## root_sites build, fails here (closing the "website-tests stops passing identity" gap that the
## isolated add_site unit test in case 6 cannot see).
if grep --quiet --extended-regexp 'delegate_sandbox_lane .*webcheck-jscov-sandbox .*jscov_roots' -- "${runner}" \
   && grep --quiet --fixed-strings 'root_sites[' -- "${runner}"; then
   pass 'website-tests: jscov lane passes canonical <site>=<path> identities (jscov_roots from root_sites), not bare roots'
else
   fail 'website-tests: jscov lane not fed identity-tagged roots (would key covered.txt on basename -> silent coverage drop)'
fi

## --- 3. every real-site test file self-skips an absent site (partial-checkout safety) ---

## website-tests resolves site roots dynamically, so a partial covered-site set is supported.
## run.sh runs EVERY jscov/*.test.js; a test file whose site was not passed must self-skip (an
## existsSync guard, like app.test.js), else its loadScript/require throws ENOENT -> false RED.
## This pins the guard across all 13 real-site files; pre-fix none had it.
jscov_dir="${test_dir}/../../share/website-tests/jscov"
[ -d "${jscov_dir}" ] || jscov_dir='/usr/share/website-tests/jscov'
site_tests='analyzer sandbox ui xray hero mockup pastejack playback quiz st-copy st-share ol-copy share'
missing_guard=''
for t in ${site_tests}; do
   if ! grep --quiet --fixed-strings 'existsSync' -- "${jscov_dir}/${t}.test.js"; then
      missing_guard="${missing_guard} ${t}"
   fi
done
if [ -z "${missing_guard}" ]; then
   pass 'jscov: every real-site test file self-skips an absent site (existsSync guard present)'
else
   fail "jscov: test file(s) missing an absent-site self-skip guard:${missing_guard}"
fi

## --- 4. a non-covered-site root exits 77 SKIP, never a FATAL / die 1 ---

## A single root carrying NO covered.txt site (here a computer-security-research checkout) must
## never FATAL the lane. Where a runtime is reachable (a sandbox -- the dev VM case -- or a full
## local node+c8+npm+jsdom) the driver reaches the covered.txt-scoping block, finds nothing to
## gate, and exits 77; where none is reachable it exits 77 at the earlier env-unmet gate. EITHER
## way 77, never a FATAL. Pre-fix the driver died 1 (sandbox-only) or run.sh FATAL'd 1 on the
## absent covered files -- so this FAILs on old code.
csr="${work}/computer-security-research.github.io"
mkdir --parents -- "${csr}"
touch -- "${csr}/index.html"
empty_rc=0
empty_err="$("${driver}" "${csr}" 2>&1 1>/dev/null)" || empty_rc=$?
if [ "${empty_rc}" -eq 77 ]; then
   pass 'webcheck-jscov-sandbox: a non-covered-site root exits 77 SKIP, never a FATAL/die 1'
else
   fail "webcheck-jscov-sandbox: non-covered-site root did not exit 77 (rc=${empty_rc}, err='${empty_err}')"
fi

## --- 5. local-first requires GLOBAL jsdom, not a cwd-resolvable project-local copy ---

## run.sh runs from the STAGING cwd (NODE_PATH=global only), so local-first must gate on jsdom
## in the GLOBAL npm root -- a checkout's project-local ./node_modules/jsdom must NOT engage it
## (run.sh could not resolve jsdom there -> every test throws -> false RED). Pre-fix the probe was
## `node -e require.resolve("jsdom")`, which resolves from the probe's OWN cwd first, so a project-
## local jsdom satisfied it -> run_local=1. Stub node(v22)+c8+npm(global root WITHOUT jsdom); run
## FROM a dir that HAS ./node_modules/jsdom; WEBSITE_TESTS_NO_SANDBOX=1 so a correct run_local=0
## settles as env-unmet 77. The root is a COVERED site (output-lies.github.io) so a WRONG
## run_local=1 does NOT also land on the no-covered-site 77 -- it proceeds to the local gate and
## FATALs (exit 1) on the stub toolchain. New probe -> 77; pre-fix (node -e) -> run_local=1 -> 1.
stub2="${work}/stub2"
mkdir --parents -- "${stub2}"
printf '%s\n' '#!/bin/sh' 'echo v22.99.0' 'exit 0' > "${stub2}/node"
printf '%s\n' '#!/bin/sh' 'exit 0' > "${stub2}/c8"
fakeglobal="${work}/fake-global"            # a global npm root with NO jsdom
mkdir --parents -- "${fakeglobal}"
printf '%s\n' '#!/bin/sh' "echo ${fakeglobal}" 'exit 0' > "${stub2}/npm"
chmod +x -- "${stub2}/node" "${stub2}/c8" "${stub2}/npm"
proj="${work}/proj"                         # launch cwd WITH a shadowing project-local jsdom
mkdir --parents -- "${proj}/node_modules/jsdom"
printf '%s\n' '{"name":"jsdom","main":"index.js"}' > "${proj}/node_modules/jsdom/package.json"
site3="${work}/output-lies.github.io"       # a covered-site basename (so run_local=1 reaches the gate)
mkdir --parents -- "${site3}"
touch -- "${site3}/index.html"
shadow_rc=0
shadow_err="$(cd -- "${proj}" && PATH="${stub2}:${PATH}" WEBSITE_TESTS_NO_SANDBOX=1 \
   "${driver}" "${site3}" 2>&1 1>/dev/null)" || shadow_rc=$?
if [ "${shadow_rc}" -eq 77 ]; then
   pass 'webcheck-jscov-sandbox: project-local jsdom does not engage local-first (global-root probe) -> 77'
else
   fail "webcheck-jscov-sandbox: project-local jsdom wrongly engaged local-first (rc=${shadow_rc}, err='${shadow_err}')"
fi

## --- 6. website-tests records a non-canonical override under its CANONICAL site identity ---

## The jscov lane keys covered.txt on the site identity; an _REPO override at a non-canonically-
## named path (a CI workspace) must still be recorded as its canonical site (root_sites), else
## that site's covered entries key on the wrong name and its JS coverage SILENTLY DROPS (vacuous
## pass). Extract add_root + add_site from the real runner and drive them. Pre-fix: no add_site.
wt_fns="${work}/wt_fns.bash"
sed -n '/^add_root(){/,/^}/p' -- "${runner}" >  "${wt_fns}"
sed -n '/^add_site(){/,/^}/p' -- "${runner}" >> "${wt_fns}"
if ! grep --quiet --fixed-strings 'add_site(){' "${wt_fns}"; then
   fail 'website-tests: no add_site canonical-identity wrapper -- jscov keys covered.txt on the override basename (silent coverage drop)'
else
   nonc="${work}/ci-workspace-xyz"          # a NON-canonical basename for an output-lies override
   mkdir --parents -- "${nonc}"
   touch -- "${nonc}/index.html"
   ident_rc=0
   (
      declare -a roots=()
      declare -a root_sites=()
      # shellcheck disable=SC1090 # dynamic path: add_root/add_site extracted at runtime
      source "${wt_fns}"
      add_site output-lies.github.io "${nonc}" '/does/not/exist'
      [ "${#roots[@]}" -eq 1 ] && [ "${roots[0]}" = "${nonc}" ] \
         && [ "${#root_sites[@]}" -eq 1 ] && [ "${root_sites[0]}" = 'output-lies.github.io' ]
   ) || ident_rc=$?
   if [ "${ident_rc}" -eq 0 ]; then
      pass 'website-tests: non-canonical override recorded under canonical identity (output-lies.github.io)'
   else
      fail 'website-tests: override NOT mapped to its canonical site identity (jscov would key on basename)'
   fi
fi

## --- 7. the driver keys covered-site selection on the explicit <site>=<path> identity ---

## run_local engaged via stubs (node v22 + c8 + npm whose GLOBAL root has jsdom). POSITIVE test
## by contrast: a COVERED identity (output-lies.github.io=<non-canonical path>) is parsed AND
## selected as covered -> reaches the gate (rc != 77); a NON-covered identity (madeup.example=
## <same path>) is parsed but scoped out -> exit 77. The two outcomes together prove the driver
## parses <site>=<path> and keys covered.txt on the explicit identity (not the path basename).
## Pre-fix (no <site>= parsing) the driver die'd 1 on BOTH args, so the non-covered case (want 77)
## FAILs. rc is captured, never swallowed.
stub3="${work}/stub3"
mkdir --parents -- "${stub3}"
printf '%s\n' '#!/bin/sh' 'echo v22.99.0' 'exit 0' > "${stub3}/node"
printf '%s\n' '#!/bin/sh' 'exit 0' > "${stub3}/c8"
fakeg="${work}/fake-global-with-jsdom"
mkdir --parents -- "${fakeg}/jsdom"
printf '%s\n' '{"name":"jsdom"}' > "${fakeg}/jsdom/package.json"
printf '%s\n' '#!/bin/sh' "echo ${fakeg}" 'exit 0' > "${stub3}/npm"
chmod +x -- "${stub3}/node" "${stub3}/c8" "${stub3}/npm"
id_root="${work}/ci-ws-7"
mkdir --parents -- "${id_root}"
touch -- "${id_root}/index.html"
cov_rc=0
PATH="${stub3}:${PATH}" "${driver}" "output-lies.github.io=${id_root}" >/dev/null 2>&1 || cov_rc=$?
noncov_rc=0
PATH="${stub3}:${PATH}" "${driver}" "madeup.example=${id_root}" >/dev/null 2>&1 || noncov_rc=$?
if [ "${cov_rc}" -ne 77 ] && [ "${noncov_rc}" -eq 77 ]; then
   pass 'webcheck-jscov-sandbox: covered-selection keyed on <site>=<path> identity (covered reaches gate, non-covered -> 77)'
else
   fail "webcheck-jscov-sandbox: identity not honored (covered rc=${cov_rc} want !=77; non-covered rc=${noncov_rc} want 77)"
fi

printf '%s\n' "" "test_website_jscov_lane: ${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
