#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-local-repro-build BOTH launches a build and reads its artifact from the shared binary_mnt.
## Once builds are laned (dist_build_slot), an UN-laned read rooted at the flat binary_mnt would
## descend into a CONCURRENT build's lane and cat a FOREIGN artifact's sha512 as the comparison
## key -- a wrong verdict. So this tool must lane its own build and scope every find to that lane.
## The real assignments are extracted + eval'd (no copy to drift) regardless of any leading
## `if !`/indent or trailing `; then`; the finds are checked structurally.
## Canary: fails on the pre-lane tool (flat binary_mnt root, no slot on the build).

## File-wide: dist_build_slot / build_slot / binary_lane are set + read by `eval` of lines
## extracted from the subject script, which shellcheck cannot follow statically.
# shellcheck disable=SC2034,SC2154
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DIST_AI_REPO:-}" ]; then
   subject="${DIST_AI_REPO}/usr/bin/dm-local-repro-build"
else
   here="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" && pwd )"
   subject="${here}/../../bin/dm-local-repro-build"
   [ -f "${subject}" ] || subject='/usr/bin/dm-local-repro-build'
fi
[ -f "${subject}" ] || { printf '%s\n' "FATAL: dm-local-repro-build not found" >&2; exit 1; }

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: $*"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: $*"; }

## A stub sandbox-session-slug on PATH so the slug-fallback branch is deterministic + offline.
stub_dir="$(mktemp --directory)"
# shellcheck disable=SC2317  # EXIT trap
cleanup() { safe-rm --recursive --force -- "${stub_dir}"; }
trap cleanup EXIT
printf '#!/bin/bash\nprintf %%s stub-slug\n' > "${stub_dir}/sandbox-session-slug"
chmod +x "${stub_dir}/sandbox-session-slug"
PATH="${stub_dir}:${PATH}"

## Extract a `NAME="..."` assignment from the subject, LINE-START-anchored: only leading
## indentation + an optional `if ! ` wrapper may precede the name, so the test evals the REAL
## resolution RHS without coupling to the assignment's source-line SHAPE. Anchoring (no `.*`
## before the capture) is load-bearing: it keeps a COMMENT mentioning the name, a trailing
## `# NAME=...` comment, and a `dist_build_slot=` prefix from being picked up, and takes the
## FIRST real assignment. Both RHS values contain no embedded double quote. An unmatched form
## yields empty -> the loud `[ -z ]` fail below, never a vacuous pass.
extract_assignment() { sed -nE "s/^[[:space:]]*(if[[:space:]]+!?[[:space:]]*)?($1=\"[^\"]*\").*/\2/p" -- "$2" | head -1; }

## Guard the extractor against comment-shadowing (an earlier unanchored pattern grabbed a
## `NAME="..."` from a comment, or the LAST match on a line, so a commented/trailing-comment
## assignment could shadow the real one -> a vacuous pass). Fixture inside stub_dir so the EXIT
## trap already cleans it.
printf '%s\n' '## build_slot="commented-shadow"' \
   'build_slot="real-first" # build_slot="trailing-shadow"' > "${stub_dir}/subject-fixture"
if [ "$(extract_assignment build_slot "${stub_dir}/subject-fixture")" = 'build_slot="real-first"' ]; then
   pass "extractor ignores commented/trailing-comment assignments (not shadowed)"
else
   fail "extractor shadowed by a comment: got [$(extract_assignment build_slot "${stub_dir}/subject-fixture")]"
fi

slot_line="$(extract_assignment build_slot "${subject}")"
lane_line="$(extract_assignment binary_lane "${subject}")"
if [ -z "${slot_line}" ] || [ -z "${lane_line}" ]; then
   fail "dm-local-repro-build has no build_slot/binary_lane resolution (not lane-aware)"
   printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
   exit 1
fi

## A forwarded/explicit slot must resolve to the exact per-lane path.
dist_build_slot="forwarded"; eval "${slot_line}"; eval "${lane_line}"
if [ "${build_slot}" = "forwarded" ] && [ "${binary_lane}" = "/home/user/binary_mnt/forwarded" ]; then
   pass "forwarded dist_build_slot -> lane /home/user/binary_mnt/forwarded"
else
   fail "forwarded slot mis-resolved (slot='${build_slot}' lane='${binary_lane}')"
fi

## Else the session slug (sandbox-session-slug).
unset dist_build_slot; eval "${slot_line}"; eval "${lane_line}"
if [ "${build_slot}" = "stub-slug" ] && [ "${binary_lane}" = "/home/user/binary_mnt/stub-slug" ]; then
   pass "no forwarded slot -> session slug keys the lane"
else
   fail "session-slug fallback mis-resolved (slot='${build_slot}' lane='${binary_lane}')"
fi

## Structural: no find is rooted at the BARE shared binary_mnt anymore; all use the lane.
if grep -E "find[[:space:]]+/home/user/binary_mnt[[:space:]]" -- "${subject}" >/dev/null; then
   fail "a find is still rooted at the flat /home/user/binary_mnt (would match a foreign lane)"
else
   pass "every artifact find is rooted at the per-lane binary_lane"
fi

## Structural: the launched build carries the lane so its output lands in this lane.
if grep -E "dist_build_slot='?\\\$\\{?build_slot" -- "${subject}" >/dev/null; then
   pass "the launched build is given dist_build_slot=<lane>"
else
   fail "the launched build does not set dist_build_slot (output would not be laned)"
fi

## Structural: the lane is EXPORTED before signing, so signing-key-create / sign-and-tag write
## under the same lane dm-build-official reads (else the buildinfo records the post-amend HEAD).
export_ln="$(grep -n 'export dist_build_slot' -- "${subject}" | head -1 | cut -d: -f1)"
signtag_ln="$(grep -n 'help-steps/sign-and-tag' -- "${subject}" | head -1 | cut -d: -f1)"
if [ -n "${export_ln}" ] && [ -n "${signtag_ln}" ] && [ "${export_ln}" -lt "${signtag_ln}" ]; then
   pass "dist_build_slot is exported before sign-and-tag (all container steps laned)"
else
   fail "dist_build_slot is not exported before sign-and-tag -> signing writes the un-laned tree"
fi

printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
