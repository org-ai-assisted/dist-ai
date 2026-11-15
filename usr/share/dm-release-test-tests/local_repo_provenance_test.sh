#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Pins dm-release-test's --local-repo wiring for the whonix cli INST lane (closing the
## build->test loop):
##   - rt_lane_whonix_inst THREADS --local-repo <deriv> to dm-whonix-pair (so the pair enables the
##     fast local repo for check 3), only when --local-repo was set; byte-unchanged otherwise.
##   - it records an HONEST localRepo provenance block (derivative, host repoPath, build sourceSha,
##     the Packages name=version list) and forwards it to the publisher as --provenance-local-repo.
## Drives the REAL rt_lane_whonix_inst (sourced define-only) with: rt_whonix_pair_require stubbed
## (skips the VBox marker dance), a sudo function that drops `-u <acct> --` and runs the rest, a
## dm-whonix-pair RECORDER, a dm-shared-apt-repo repo-path stub pointing at a fixture repo, and an
## image_test_results_publish stub that captures the --provenance-local-repo JSON. No VM, no root.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

subject="${DM_RELEASE_TEST_BIN:-}"
if [ -z "${subject}" ]; then
   if [ -f "${test_dir}/../../bin/dm-release-test" ]; then
      subject="${test_dir}/../../bin/dm-release-test"
   else
      subject='/usr/bin/dm-release-test'
   fi
fi
[ -r "${subject}" ] || { printf '%s\n' "FATAL: dm-release-test not found at ${subject}" >&2; exit 1; }
# shellcheck disable=SC1090
source "${subject}"

work="$(mktemp --directory --tmpdir dm-release-test-localrepo.XXXXXX)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

pass=0
fail=0
check() {
   if [ "$2" = "true" ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1 (got '${3:-}')"; fi
}

## --- fixtures ---
## Whonix is a Kicksecure DERIVATIVE: a whonix guest installs from BOTH the kicksecure base repo AND
## the whonix repo, so the local-repo CHAIN for a whonix run is "kicksecure whonix" and the provenance
## is a LIST with one object per resident member. Two 'local' reprepro repos, each with an epoch'd
## dpkg-shaped Packages index (to prove the extractor is not naive).
repo_dir="${work}/aptrepo_local/whonix"
pkgs_dir="${repo_dir}/dists/local/main/binary-amd64"
mkdir --parents -- "${pkgs_dir}"
cat > "${pkgs_dir}/Packages" <<'EOF'
Package: anon-apps-config
Version: 7:18.1-1
Architecture: all

Package: whonix-gw-network-conf
Version: 3:18.2-1
Architecture: all
EOF
ks_repo_dir="${work}/aptrepo_local/kicksecure"
ks_pkgs_dir="${ks_repo_dir}/dists/local/main/binary-amd64"
mkdir --parents -- "${ks_pkgs_dir}"
cat > "${ks_pkgs_dir}/Packages" <<'EOF'
Package: security-misc
Version: 3:18.3-1
Architecture: all
EOF

## Build/admin source home: a dm-source-state file (no git repo) -> sourceSha = its first line.
src_home="${work}/srchome"
mkdir --parents -- "${src_home}/derivative-binary"
printf '%s\n' 'Source-Commit: deadbeefcafe1234' > "${src_home}/derivative-binary/dm-source-state"

## Recorders.
pair_argv="${work}/pair.argv"
prov_file="${work}/provenance.json"
true > "${pair_argv}"
true > "${prov_file}"

pair_stub="${work}/dm-whonix-pair"
cat > "${pair_stub}" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" >> "${PAIR_ARGV}"
exit 0
EOF
## Member-aware repo-path: rt_local_repo_chain / rt_build_local_repo_snapshot call `repo-path <member>`,
## so the stub maps each member to its own fixture repo (<work>/aptrepo_local/<member>). A member with
## no fixture dir still prints a path, but its Packages index is unreadable -> omitted from the chain.
shared_stub="${work}/dm-shared-apt-repo"
cat > "${shared_stub}" <<EOF
#!/bin/bash
[ "\$1" = 'repo-path' ] && printf '%s\n' "${work}/aptrepo_local/\$2"
exit 0
EOF
chmod +x "${pair_stub}" "${shared_stub}"

export PAIR_ARGV="${pair_argv}"
## Read as globals by the sourced rt_lane_whonix_inst / rt_build_local_repo_snapshot (invisible
## to shellcheck here).
# shellcheck disable=SC2034
DM_WHONIX_PAIR="${pair_stub}"
# shellcheck disable=SC2034
DM_SHARED_APT_REPO="${shared_stub}"
# shellcheck disable=SC2034
DM_SOURCE_HOME="${src_home}"

## sudo: drop `-u <acct> --`, run the rest as this user (so `sudo -u acct -- env ... dm-whonix-pair`
## reaches the recorder, and `sudo -u acct -- mktemp/safe-rm` are real).
# shellcheck disable=SC2317  ## invoked indirectly by the lane
sudo() {
   while [ "$#" -gt 0 ]; do
      case "$1" in
         -u)
            shift 2
            ;;
         --)
            shift
            break
            ;;
         *)
            break
            ;;
      esac
   done
   "$@"
}
## rt_whonix_pair_require: skip the VBox version-marker verification (not under test here).
# shellcheck disable=SC2317  ## invoked indirectly by the lane
rt_whonix_pair_require() { return 0; }
## image_test_results_publish: capture the --provenance-local-repo JSON, print a fake outdir.
# shellcheck disable=SC2317  ## invoked indirectly by rt_publish_result
image_test_results_publish() {
   local prev=""
   local a
   for a in "$@"; do
      [ "${prev}" = "--provenance-local-repo" ] && printf '%s' "${a}" > "${prov_file}"
      prev="${a}"
   done
   printf '%s\n' "${work}/fake-outdir"
}

## Globals the lane + publisher read.
# shellcheck disable=SC2034
interface='cli'
# shellcheck disable=SC2034
desktop='CLI'
# shellcheck disable=SC2034
firmware='bios'
# shellcheck disable=SC2034
rt_origin='downloaded'

## --- run the inst lane WITH --local-repo whonix ---
true > "${pair_argv}"
true > "${prov_file}"
# shellcheck disable=SC2034  ## read as a global by the sourced rt_lane_whonix_inst
local_repo='whonix'
lane_rc=0
( rt_lane_whonix_inst persist-inst-whonix 18.2.3.5 ) >/dev/null 2>&1 || lane_rc=$?
check "inst lane returns 0" "$([ "${lane_rc}" = '0' ] && printf '%s' true || printf '%s' false)" "${lane_rc}"
check "threads --local-repo whonix to dm-whonix-pair" \
   "$(grep --quiet -- '--local-repo whonix' "${pair_argv}" && printf '%s' true || printf '%s' false)"
## The whole resident derivative chain is threaded down so the pair delivers a 'local' source per
## member (whonix WS needs the kicksecure base repo AND the whonix repo).
check "threads --local-repo-chain \"kicksecure whonix\" to dm-whonix-pair" \
   "$(grep --quiet -- '--local-repo-chain kicksecure whonix' "${pair_argv}" && printf '%s' true || printf '%s' false)"
## The resolved SHARE HOST PATH (repo-path stripped of /aptrepo_local/<deriv>) is passed down so the
## account-run attach pins it rather than re-deriving a slot-less path. repo_dir=<work>/aptrepo_local/
## whonix, so the base is <work>.
check "threads --local-repo-base (resolved share host path) to dm-whonix-pair" \
   "$(grep --quiet -- "--local-repo-base ${work}" "${pair_argv}" && printf '%s' true || printf '%s' false)"
check "still runs --mode functional --interface cli" \
   "$(grep --quiet -- '--mode functional --interface cli' "${pair_argv}" && printf '%s' true || printf '%s' false)"
check "forwards a --provenance-local-repo block to the publisher" \
   "$([ -s "${prov_file}" ] && printf '%s' true || printf '%s' false)"

## localRepo provenance is a LIST (one object per resident chain member; single-source repoPath from
## dm-shared-apt-repo repo-path). base-first order: kicksecure before whonix.
check "localRepo is a 2-element list (kicksecure base + whonix)" \
   "$([ "$(jq -r 'length' -- "${prov_file}" 2>/dev/null)" = '2' ] && printf '%s' true || printf '%s' false)"
check "localRepo[0].derivative = kicksecure (base first)" \
   "$([ "$(jq -r '.[0].derivative' -- "${prov_file}" 2>/dev/null)" = 'kicksecure' ] && printf '%s' true || printf '%s' false)"
check "localRepo[1].derivative = whonix" \
   "$([ "$(jq -r '.[1].derivative' -- "${prov_file}" 2>/dev/null)" = 'whonix' ] && printf '%s' true || printf '%s' false)"
check "localRepo whonix repoPath = the dm-shared-apt-repo repo dir" \
   "$([ "$(jq -r '.[] | select(.derivative=="whonix") | .repoPath' -- "${prov_file}" 2>/dev/null)" = "${repo_dir}" ] && printf '%s' true || printf '%s' false)"
check "localRepo kicksecure repoPath = the kicksecure fixture repo dir" \
   "$([ "$(jq -r '.[] | select(.derivative=="kicksecure") | .repoPath' -- "${prov_file}" 2>/dev/null)" = "${ks_repo_dir}" ] && printf '%s' true || printf '%s' false)"
check "localRepo sourceSha = dm-source-state first line (both members)" \
   "$([ "$(jq -r '[.[].sourceSha] | unique | .[0]' -- "${prov_file}" 2>/dev/null)" = 'deadbeefcafe1234' ] && printf '%s' true || printf '%s' false)"
check "localRepo whonix packages carry anon-apps-config=7:18.1-1" \
   "$(jq -e '.[] | select(.derivative=="whonix") | .packages | index("anon-apps-config=7:18.1-1")' -- "${prov_file}" >/dev/null 2>&1 && printf '%s' true || printf '%s' false)"
check "localRepo whonix packages carry whonix-gw-network-conf=3:18.2-1" \
   "$(jq -e '.[] | select(.derivative=="whonix") | .packages | index("whonix-gw-network-conf=3:18.2-1")' -- "${prov_file}" >/dev/null 2>&1 && printf '%s' true || printf '%s' false)"
check "localRepo kicksecure packages carry security-misc=3:18.3-1 (the base build is recorded too)" \
   "$(jq -e '.[] | select(.derivative=="kicksecure") | .packages | index("security-misc=3:18.3-1")' -- "${prov_file}" >/dev/null 2>&1 && printf '%s' true || printf '%s' false)"

## --- include-if-present: a whonix rebuild with NO resident kicksecure local repo stays testable --
## the chain degrades to just whonix (delivered + recorded honestly), never a hard failure. Hide the
## kicksecure fixture, re-run, expect a 1-element provenance + a whonix-only chain thread. ---
mv -- "${ks_repo_dir}" "${work}/aptrepo_local/kicksecure.hidden"
true > "${pair_argv}"
true > "${prov_file}"
# shellcheck disable=SC2034
local_repo='whonix'
inc_rc=0
( rt_lane_whonix_inst persist-inst-whonix 18.2.3.5 ) >/dev/null 2>&1 || inc_rc=$?
check "include-if-present: lane returns 0 with no resident kicksecure repo" \
   "$([ "${inc_rc}" = '0' ] && printf '%s' true || printf '%s' false)" "${inc_rc}"
check "include-if-present: chain degrades to --local-repo-chain whonix (no kicksecure)" \
   "$(grep --quiet -- '--local-repo-chain whonix' "${pair_argv}" && ! grep --quiet -- '--local-repo-chain kicksecure' "${pair_argv}" && printf '%s' true || printf '%s' false)"
check "include-if-present: provenance is a 1-element whonix-only list" \
   "$([ "$(jq -r 'length' -- "${prov_file}" 2>/dev/null)" = '1' ] && [ "$(jq -r '.[0].derivative' -- "${prov_file}" 2>/dev/null)" = 'whonix' ] && printf '%s' true || printf '%s' false)"
mv -- "${work}/aptrepo_local/kicksecure.hidden" "${ks_repo_dir}"

## --- run WITHOUT --local-repo: no thread, no provenance block (byte-unchanged path) ---
true > "${pair_argv}"
true > "${prov_file}"
# shellcheck disable=SC2034  ## read as a global by the sourced rt_lane_whonix_inst
local_repo=''
nolr_rc=0
( rt_lane_whonix_inst persist-inst-whonix 18.2.3.5 ) >/dev/null 2>&1 || nolr_rc=$?
check "no --local-repo: lane returns 0" "$([ "${nolr_rc}" = '0' ] && printf '%s' true || printf '%s' false)" "${nolr_rc}"
check "no --local-repo: dm-whonix-pair NOT handed --local-repo" \
   "$(grep --quiet -- '--local-repo' "${pair_argv}" && printf '%s' false || printf '%s' true)"
check "no --local-repo: NO provenance block forwarded" \
   "$([ ! -s "${prov_file}" ] && printf '%s' true || printf '%s' false)"

## --- G: sourceSha is the BUILD-TIME dm-source-state, never the live checkout HEAD ---
## A source home whose git HEAD DIFFERS from the build-time dm-source-state: the sha must come from
## dm-source-state (the commit the packages were BUILT at), not the advanced HEAD -- a checkout that
## moved after the build no longer matches the packages in the local repo.
g_home="${work}/ghome"
mkdir --parents -- "${g_home}/derivative-binary" "${g_home}/derivative-maker"
printf '%s\n' 'Source-Commit: buildtimesha0000' > "${g_home}/derivative-binary/dm-source-state"
git -C "${g_home}/derivative-maker" init --quiet
git -C "${g_home}/derivative-maker" -c user.email=t@t -c user.name=t commit --quiet --allow-empty -m x
# shellcheck disable=SC2034  ## read as a global by the sourced rt_source_home
DM_SOURCE_HOME="${g_home}"
g_sha="$(rt_local_repo_source_sha)"
check "G: sourceSha is the build-time dm-source-state value, not the live git HEAD or the label line" \
   "$([ "${g_sha}" = 'buildtimesha0000' ] && printf '%s' true || printf '%s' false)" "${g_sha}"
## 'Source-Commit: unrecorded' -> honest empty sha (never the sentinel label).
printf '%s\n' 'Source-Commit: unrecorded' > "${g_home}/derivative-binary/dm-source-state"
unrec_sha="$(rt_local_repo_source_sha)"
check "G: an unrecorded source commit yields an empty sha" \
   "$([ -z "${unrec_sha}" ] && printf '%s' true || printf '%s' false)" "${unrec_sha}"
# shellcheck disable=SC2034
DM_SOURCE_HOME="${src_home}"

## --- #3: a rebuild landing DURING the test window (the repo's Packages changes between the
## pre-upgrade generation capture and the provenance read) must OMIT provenance -- never bind the
## verdict to a generation the guest did not test. Simulate with a dm-whonix-pair that rewrites the
## Packages index (as a concurrent rebuild would) while the "guest upgrade" runs. ---
true > "${pair_argv}"
true > "${prov_file}"
mutating_pair="${work}/dm-whonix-pair-mutate"
cat > "${mutating_pair}" <<EOF
#!/bin/bash
printf '%s\n' "\$*" >> "\${PAIR_ARGV}"
printf '%s\n' 'Package: anon-apps-config' 'Version: 9:99.9-9' 'Architecture: all' > "${pkgs_dir}/Packages"
exit 0
EOF
chmod +x "${mutating_pair}"
# shellcheck disable=SC2034  ## read as a global by the sourced rt_lane_whonix_inst
DM_WHONIX_PAIR="${mutating_pair}"
# shellcheck disable=SC2034
local_repo='whonix'
mut_rc=0
( rt_lane_whonix_inst persist-inst-whonix 18.2.3.5 ) >/dev/null 2>&1 || mut_rc=$?
check "#3: lane still returns 0 when the generation changed mid-test" \
   "$([ "${mut_rc}" = '0' ] && printf '%s' true || printf '%s' false)" "${mut_rc}"
check "#3: provenance OMITTED when the repo generation changed mid-test" \
   "$([ ! -s "${prov_file}" ] && printf '%s' true || printf '%s' false)"
# shellcheck disable=SC2034
DM_WHONIX_PAIR="${pair_stub}"

## --- 1565: the root-side repo-path lookup FAILS (empty) -> the lane is INCONCLUSIVE (SETUP_RC)
## BEFORE invoking dm-whonix-pair, never attaching a slot-less repo that disagrees with provenance. ---
true > "${pair_argv}"
true > "${prov_file}"
empty_shared="${work}/dm-shared-apt-repo-empty"
cat > "${empty_shared}" <<'EOF'
#!/bin/bash
## repo-path prints nothing (lookup failed); every subcommand no-ops.
exit 0
EOF
chmod +x "${empty_shared}"
# shellcheck disable=SC2034
DM_SHARED_APT_REPO="${empty_shared}"
# shellcheck disable=SC2034
local_repo='whonix'
lf_rc=0
( rt_lane_whonix_inst persist-inst-whonix 18.2.3.5 ) >/dev/null 2>&1 || lf_rc=$?
check "1565: lane is SETUP_RC (2) when the repo-path lookup fails" \
   "$([ "${lf_rc}" = '2' ] && printf '%s' true || printf '%s' false)" "${lf_rc}"
check "1565: dm-whonix-pair NOT invoked on a failed repo-path lookup" \
   "$([ ! -s "${pair_argv}" ] && printf '%s' true || printf '%s' false)"
# shellcheck disable=SC2034
DM_SHARED_APT_REPO="${shared_stub}"

## --- finding 6: an UNEXPECTED provenance TOOL failure on a --local-repo run must publish
## INCONCLUSIVE (SETUP_RC), NEVER a published-repo masquerade -- a local-repo run recorded with NO
## localRepo block (or a block with a silently-empty packages list) is indistinguishable from one
## that tested the published repos. Distinct from the benign generation-change omit above (which
## stays rc 0): a provenance tool failure is an environment bug, not a benign race. The caller runs
## the builder on the LHS of `||`, which DISABLES errexit inside it, so each tool step needs an
## explicit `|| return 1` / status capture -- these cases canary every such path. Each uses its OWN
## clean stub dir on PATH; the generation is UNCHANGED (non-mutating pair). ---
## 'type -P' not R-090's 'has': what is wanted is the real tool's PATH (to exec from a stub that
## shadows it on PATH), not a presence check.
real_awk="$(type -P awk || true)"
real_sha="$(type -P sha256sum || true)"

## build jq failure, BOTH error codes -- exit 2 especially (an earlier design reused 2 as the
## "generation omit" sentinel, so a real jq error, which also exits 2, masqueraded as the benign omit).
for jq_rc in 1 2; do
   sdir="${work}/stub-jq-${jq_rc}"
   mkdir --parents -- "${sdir}"
   printf '%s\n' '#!/bin/sh' "exit ${jq_rc}" > "${sdir}/jq"
   chmod +x -- "${sdir}/jq"
   true > "${pair_argv}"
   true > "${prov_file}"
   # shellcheck disable=SC2034  ## read as a global by the sourced rt_lane_whonix_inst
   local_repo='whonix'
   tf_rc=0
   # shellcheck disable=SC2030,SC2031  # PATH scoped to this subshell on purpose (stub shadows one call)
   ( export PATH="${sdir}:${PATH}"; rt_lane_whonix_inst persist-inst-whonix 18.2.3.5 ) >/dev/null 2>&1 || tf_rc=$?
   check "finding 6 (build jq exit ${jq_rc}): dm-whonix-pair WAS invoked (lane reached the provenance build)" \
      "$(grep --quiet -- '--local-repo whonix' "${pair_argv}" && printf '%s' true || printf '%s' false)"
   check "finding 6 (build jq exit ${jq_rc}): publishes INCONCLUSIVE (SETUP_RC 2), not a published-repo masquerade" \
      "$([ "${tf_rc}" = '2' ] && printf '%s' true || printf '%s' false)" "${tf_rc}"
done

## build AWK failure: awk fails ONLY for the package-extraction program (the gen-id awk still works,
## so the generation verifies and the lane reaches the build). An uncaught awk error would yield a
## block with a silently-EMPTY packages list and rc 0 -- the explicit `|| return 1` must make it
## INCONCLUSIVE. jq is left real so the failure is unambiguously the awk step.
sdir="${work}/stub-build-awk"
mkdir --parents -- "${sdir}"
cat > "${sdir}/awk" <<EOF
#!/bin/sh
case "\$*" in
  *Package*) exit 2 ;;
  *) exec ${real_awk} "\$@" ;;
esac
EOF
chmod +x -- "${sdir}/awk"
true > "${pair_argv}"
true > "${prov_file}"
# shellcheck disable=SC2034
local_repo='whonix'
tf_rc=0
# shellcheck disable=SC2030,SC2031  # PATH scoped to this subshell on purpose (stub shadows one call)
( export PATH="${sdir}:${PATH}"; rt_lane_whonix_inst persist-inst-whonix 18.2.3.5 ) >/dev/null 2>&1 || tf_rc=$?
check "finding 6 (build awk failure): INCONCLUSIVE, not a block with a silently-empty packages list" \
   "$([ "${tf_rc}" = '2' ] && printf '%s' true || printf '%s' false)" "${tf_rc}"

## gen-id tool failure: a failing sha256sum makes rt_build_local_repo_snapshot fail -> INCONCLUSIVE, not the
## benign unverifiable-generation omit (which is only for an UNREADABLE index, a 0-with-empty return).
sdir="${work}/stub-gen-sha"
mkdir --parents -- "${sdir}"
printf '%s\n' '#!/bin/sh' 'exit 1' > "${sdir}/sha256sum"
chmod +x -- "${sdir}/sha256sum"
true > "${pair_argv}"
true > "${prov_file}"
# shellcheck disable=SC2034
local_repo='whonix'
tf_rc=0
# shellcheck disable=SC2030,SC2031  # PATH scoped to this subshell on purpose (stub shadows one call)
( export PATH="${sdir}:${PATH}"; rt_lane_whonix_inst persist-inst-whonix 18.2.3.5 ) >/dev/null 2>&1 || tf_rc=$?
check "finding 6 (gen-id sha256sum failure): INCONCLUSIVE, not the benign omit" \
   "$([ "${tf_rc}" = '2' ] && printf '%s' true || printf '%s' false)" "${tf_rc}"

## PRE-upgrade gen-id failure, POST succeeds: the pre-upgrade capture's exit status must be checked
## (not discarded by the `&&` form), else a pre-upgrade tool failure collapses to an empty gen and is
## swallowed as the benign omit. Stateful stub: sha256sum fails only its FIRST (pre-upgrade) call.
sdir="${work}/stub-pre-sha"
mkdir --parents -- "${sdir}"
sha_count="${work}/sha-count"
cat > "${sdir}/sha256sum" <<EOF
#!/bin/sh
c="${sha_count}"
n="\$(cat "\$c" 2>/dev/null || echo 0)"
echo "\$((n + 1))" > "\$c"
[ "\$n" = 0 ] && exit 1
exec ${real_sha} "\$@"
EOF
chmod +x -- "${sdir}/sha256sum"
true > "${pair_argv}"
true > "${prov_file}"
# shellcheck disable=SC2034
local_repo='whonix'
tf_rc=0
# shellcheck disable=SC2030,SC2031  # PATH scoped to this subshell on purpose (stub shadows one call)
( export PATH="${sdir}:${PATH}"; rt_lane_whonix_inst persist-inst-whonix 18.2.3.5 ) >/dev/null 2>&1 || tf_rc=$?
check "finding 6 (pre-upgrade gen-id failure, post OK): INCONCLUSIVE, pre-upgrade status not discarded" \
   "$([ "${tf_rc}" = '2' ] && printf '%s' true || printf '%s' false)" "${tf_rc}"

## --- single-read contract (closes the provenance-vs-generation TOCTOU): rt_build_local_repo_snapshot
## derives BOTH the generation id AND the provenance from ONE read of each Packages index, so a rebuild
## mutating an index cannot split the generation from the published package list (not even a mutate-
## then-restore race a separate gen re-read would miss). Assert the generation equals an INDEPENDENT
## sha of the SAME bytes the provenance lists -- a second read would break this equality. Fresh
## fixtures: earlier tests mutate the shared Packages indices. ---
cat > "${ks_pkgs_dir}/Packages" <<'EOF'
Package: security-misc
Version: 3:18.3-1
Architecture: all
EOF
cat > "${pkgs_dir}/Packages" <<'EOF'
Package: whonix-gw-network-conf
Version: 3:18.2-1
Architecture: all
EOF
sr_expected_gen="$(printf '%s' "$(cat -- "${ks_pkgs_dir}/Packages")" | sha256sum | awk '{print $1}')$(printf '%s' "$(cat -- "${pkgs_dir}/Packages")" | sha256sum | awk '{print $1}')"
rt_build_local_repo_snapshot whonix 'kicksecure whonix'
# shellcheck disable=SC2154  ## set as a global by the sourced rt_build_local_repo_snapshot
sr_gen="${rt_lr_snapshot_gen}"
# shellcheck disable=SC2154  ## set as a global by the sourced rt_build_local_repo_snapshot
sr_json="${rt_lr_snapshot_json}"
check "single-read: generation id is the concatenated per-member sha of the SAME bytes parsed for provenance" \
   "$([ "${sr_gen}" = "${sr_expected_gen}" ] && printf '%s' true || printf '%s' false)" "${sr_gen}"
check "single-read: provenance lists the kicksecure version from that one read" \
   "$(grep --quiet --fixed-strings -- 'security-misc=3:18.3-1' <<< "${sr_json}" && printf '%s' true || printf '%s' false)"
check "single-read: provenance lists the whonix version from that one read" \
   "$(grep --quiet --fixed-strings -- 'whonix-gw-network-conf=3:18.2-1' <<< "${sr_json}" && printf '%s' true || printf '%s' false)"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ] || exit 1
exit 0
