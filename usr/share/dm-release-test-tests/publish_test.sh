#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit-tests the shared results-plane publisher (results-publish.bsh), used by
## both image-test-run and dm-release-test. Runs as a normal user into a temp
## results root (owner = the running user, so the chown is a no-op), no network.
## Drives the REAL publisher, which shells out to the REAL image-test-result-emit
## (resolved as its in-tree sibling) -- no synthetic JSON.
##
## Canary (fails on the pre-schema code): the result is dm-test-result/v1 with a
## steps[] array carrying a per-step status and a summary that agrees with it; the
## shot is stored step-named (calamares-install.png), not the old generic
## screenshot.png; and rc 2 maps to step status 'broken' (an INCONCLUSIVE setup
## gap), not the old binary pass/fail. A reverted flat-schema / screenshot.png /
## binary-pass writer would fail these.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

lib="${RESULTS_PUBLISH_LIB:-}"
if [ -z "${lib}" ]; then
   if [ -f "${test_dir}/../../libexec/image-test/results-publish.bsh" ]; then
      lib="${test_dir}/../../libexec/image-test/results-publish.bsh"
   else
      lib='/usr/libexec/image-test/results-publish.bsh'
   fi
fi
[ -r "${lib}" ] || { printf 'FATAL: results-publish.bsh not found at %s\n' "${lib}" >&2; exit 1; }
# shellcheck disable=SC1090
source "${lib}"

failures=0
work=""

publish_test_cleanup() {
   [ -n "${work}" ] || return 0
   safe-rm --recursive --force -- "${work}"
}

work="$(mktemp --directory --tmpdir dm-release-test-publish.XXXXXX)"
trap publish_test_cleanup EXIT

shot="${work}/shot.png"
printf 'PNGDATA\n' > "${shot}"
results_root="${work}/results"
owner="$(id --user --name)"

outdir="$(image_test_results_publish "${results_root}" "${owner}" \
   "kicksecure-18-2-3-5" "eph-run-kicksecure-18-2-3-5" "calamares-install" \
   0 "${shot}" \
   --lane kicksecure-lxqt --version 18.2.3.5 --builder dm-release-test \
   --origin downloaded --expect Kicksecure)"

check() {
   local label cond
   label="$1"
   cond="$2"
   if [ "${cond}" = 'true' ]; then
      printf 'ok: %s\n' "${label}"
   else
      printf 'FAIL: %s\n' "${label}" >&2
      failures=$((failures + 1))
   fi
}

json="${outdir}/result.json"
check "outdir created" "$([ -d "${outdir}" ] && printf true || printf false)"
check "result.json written" "$([ -f "${json}" ] && printf true || printf false)"
## Shot stored step-named (canary: old code wrote the generic screenshot.png).
check "shot stored step-named" "$([ -f "${outdir}/calamares-install.png" ] && printf true || printf false)"
check "no legacy screenshot.png" "$([ ! -f "${outdir}/screenshot.png" ] && printf true || printf false)"
## Schema envelope (canary: the old flat {name,test_user,pass,timestamp} schema
## carried none of these).
check "json has schema tag" "$(grep --quiet '"schema": "dm-test-result/v1"' -- "${json}" && printf true || printf false)"
check "json has stage finished" "$(grep --quiet '"stage": "finished"' -- "${json}" && printf true || printf false)"
check "json has lane" "$(grep --quiet '"lane": "kicksecure-lxqt"' -- "${json}" && printf true || printf false)"
check "json has version" "$(grep --quiet '"version": "18.2.3.5"' -- "${json}" && printf true || printf false)"
check "json has mode" "$(grep --quiet '"mode": "calamares-install"' -- "${json}" && printf true || printf false)"
check "json has test_user" "$(grep --quiet '"test_user": "eph-run-kicksecure-18-2-3-5"' -- "${json}" && printf true || printf false)"
check "json has origin downloaded" "$(grep --quiet '"origin": "downloaded"' -- "${json}" && printf true || printf false)"
check "json has verdict PASS" "$(grep --quiet '"verdict": "PASS"' -- "${json}" && printf true || printf false)"
check "json has expect token" "$(grep --quiet '"Kicksecure"' -- "${json}" && printf true || printf false)"
## steps[] + per-step status + summary agreement (canary: old schema had no steps).
check "step status passed" "$(grep --quiet '"status": "passed"' -- "${json}" && printf true || printf false)"
check "summary passed 1" "$(grep --quiet '"passed": 1' -- "${json}" && printf true || printf false)"
check "summary total 1" "$(grep --quiet '"total": 1' -- "${json}" && printf true || printf false)"
## Attachment references the stored shot by name + mediaType.
check "attachment path" "$(grep --quiet '"path": "calamares-install.png"' -- "${json}" && printf true || printf false)"
check "attachment mediaType png" "$(grep --quiet '"mediaType": "image/png"' -- "${json}" && printf true || printf false)"

## latest must point at the run's timestamp dir (basename of outdir).
latest="${results_root}/kicksecure-18-2-3-5/latest"
link_target="$(readlink -- "${latest}" 2>/dev/null || true)"
check "latest symlink points at run" "$([ "${link_target}" = "$(basename -- "${outdir}")" ] && printf true || printf false)"

## Multi-shot "full story": shot_src is a DIRECTORY of NN-<milestone>.png files. Each is
## published as its own attachment NAMED by the milestone (the NN- prefix stripped), stored
## step-named so basenames never collide, in filename (capture) order. Canary for the
## multi-screenshot extension: the pre-extension publisher only forwarded a single shot file.
story="${work}/story"
mkdir --parents -- "${story}"
printf 'WELCOME\n'    > "${story}/01-welcome.png"
printf 'PARTITIONS\n' > "${story}/02-partitions.png"
printf 'FAILURE\n'    > "${story}/99-failure.png"
story_out="$(image_test_results_publish "${results_root}" "${owner}" \
   "kicksecure-story-18-2-3-5" "eph-run-kicksecure-story" "calamares-install" \
   0 "${story}" \
   --lane kicksecure-lxqt --version 18.2.3.5 --builder dm-release-test \
   --origin built --expect Kicksecure)"
story_json="${story_out}/result.json"
check "full story: welcome attachment named" "$(grep --quiet '"name": "welcome"' -- "${story_json}" && printf true || printf false)"
check "full story: partitions attachment named" "$(grep --quiet '"name": "partitions"' -- "${story_json}" && printf true || printf false)"
check "full story: failure attachment named" "$(grep --quiet '"name": "failure"' -- "${story_json}" && printf true || printf false)"
check "full story: welcome shot stored step-named" "$([ -f "${story_out}/calamares-install-01-welcome.png" ] && printf true || printf false)"
check "full story: partitions shot stored step-named" "$([ -f "${story_out}/calamares-install-02-partitions.png" ] && printf true || printf false)"
check "full story: failure shot stored step-named" "$([ -f "${story_out}/calamares-install-99-failure.png" ] && printf true || printf false)"
## Order in result.json is capture order (NN-sorted), not alphabetical by milestone name.
w_pos="$(grep --byte-offset --only-matching '"name": "welcome"' -- "${story_json}" | head -1 | cut -d: -f1)"
p_pos="$(grep --byte-offset --only-matching '"name": "partitions"' -- "${story_json}" | head -1 | cut -d: -f1)"
f_pos="$(grep --byte-offset --only-matching '"name": "failure"' -- "${story_json}" | head -1 | cut -d: -f1)"
check "full story: milestones in capture order" "$([ "${w_pos}" -lt "${p_pos}" ] && [ "${p_pos}" -lt "${f_pos}" ] && printf true || printf false)"

## Full story is ROBUST to a stray/odd file in the account-owned dir: a 0-byte shot and
## an argparse-hostile name (milestone '-x') are SKIPPED, the good milestones still publish,
## and result.json IS written -- the account cannot suppress its own result with junk.
hardstory="${work}/hardstory"
mkdir --parents -- "${hardstory}"
printf 'WELCOME\n' > "${hardstory}/01-welcome.png"
touch -- "${hardstory}/02-empty.png"        ## 0-byte -> skipped
printf 'X\n' > "${hardstory}/03--x.png"     ## milestone '-x' (leading dash) -> skipped
hard_out="$(image_test_results_publish "${results_root}" "${owner}" \
   "kicksecure-hardstory-18-2-3-5" "eph-run-kicksecure-hardstory" "calamares-install" \
   0 "${hardstory}" \
   --lane kicksecure-lxqt --version 18.2.3.5 --builder dm-release-test \
   --origin built --expect Kicksecure)"
hard_json="${hard_out}/result.json"
check "junk-in-dir: result.json still written" "$([ -f "${hard_json}" ] && printf true || printf false)"
check "junk-in-dir: good milestone kept" "$(grep --quiet '"name": "welcome"' -- "${hard_json}" && printf true || printf false)"
check "junk-in-dir: 0-byte shot skipped" "$([ ! -f "${hard_out}/calamares-install-02-empty.png" ] && printf true || printf false)"
check "junk-in-dir: latest advanced to this run" "$([ -L "${results_root}/kicksecure-hardstory-18-2-3-5/latest" ] && printf true || printf false)"

## rc 2 = SETUP/inconclusive: run verdict INCONCLUSIVE AND step status 'broken'
## (an infra/setup error, distinct from a FAIL). Canary: the old binary pass/fail
## schema published rc 2 as FAIL and had no step status at all. No shot here (the
## packet-based whonix lane), so attachments must be empty.
inc_out="$(image_test_results_publish "${results_root}" "${owner}" \
   "whonix-18-2-3-5" "persist-leak-whonix" "whonix-pair" \
   2 "" --lane whonix-gw-ws --version 18.2.3.5 --builder dm-release-test \
   --origin downloaded --expect tor-confirm)"
inc_json="${inc_out}/result.json"
check "rc 2 verdict INCONCLUSIVE" "$(grep --quiet '"verdict": "INCONCLUSIVE"' -- "${inc_json}" && printf true || printf false)"
check "rc 2 step status broken" "$(grep --quiet '"status": "broken"' -- "${inc_json}" && printf true || printf false)"
check "rc 2 summary broken 1" "$(grep --quiet '"broken": 1' -- "${inc_json}" && printf true || printf false)"
check "rc 2 no attachment" "$(grep --quiet '"attachments": \[\]' -- "${inc_json}" && printf true || printf false)"

fail_out="$(image_test_results_publish "${results_root}" "${owner}" \
   "whonix-18-2-3-6" "persist-leak-whonix" "whonix-pair" \
   5 "" --lane whonix-gw-ws --version 18.2.3.6 --builder dm-release-test \
   --origin downloaded --expect tor-confirm)"
fail_json="${fail_out}/result.json"
check "rc 5 verdict FAIL" "$(grep --quiet '"verdict": "FAIL"' -- "${fail_json}" && printf true || printf false)"
check "rc 5 step status failed" "$(grep --quiet '"status": "failed"' -- "${fail_json}" && printf true || printf false)"

## Canary: a step name with a path-traversal component is rejected BEFORE any
## root write; nothing is created and no latest is published. (The publisher
## writes as root, so this guards a latent escape of the run dir.)
## '../../evil' from the ts run dir resolves to ${results_root}/evil.png on the
## OLD (unvalidated) publisher -- outside the run dir. The fix rejects it.
trav_rc=0
image_test_results_publish "${results_root}" "${owner}" \
   "trav-run" "acct" "calamares-install" 0 "${shot}" \
   --lane l --version v --builder b --origin built --step-name "../../evil" >/dev/null 2>&1 || trav_rc=$?
check "unsafe step name rejected (nonzero)" "$([ "${trav_rc}" -ne 0 ] && printf true || printf false)"
check "no traversal file written outside run dir" "$([ ! -e "${results_root}/evil.png" ] && printf true || printf false)"
check "no latest for a rejected run" "$([ ! -e "${results_root}/trav-run/latest" ] && printf true || printf false)"

## Canary: an emitter failure (an empty --expect token the schema rejects) FAILS
## the publish and does NOT repoint latest -- a run with no result.json must never
## become the published 'latest' (that would be a NO-DATA dir reading as current).
emitfail_rc=0
image_test_results_publish "${results_root}" "${owner}" \
   "emitfail-run" "acct" "calamares-install" 0 "${shot}" \
   --lane l --version v --builder b --origin built --expect "" >/dev/null 2>&1 || emitfail_rc=$?
check "emitter failure fails the publish (nonzero)" "$([ "${emitfail_rc}" -ne 0 ] && printf true || printf false)"
check "no latest when result.json was not written" "$([ ! -e "${results_root}/emitfail-run/latest" ] && printf true || printf false)"
check "no result.json for the failed emit" "$([ -z "$(find "${results_root}/emitfail-run" -name result.json 2>/dev/null)" ] && printf true || printf false)"

if [ "${failures}" -ne 0 ]; then
   printf '\n%s publish assertion(s) failed\n' "${failures}" >&2
   exit 1
fi
printf '\nall publish assertions passed\n'
