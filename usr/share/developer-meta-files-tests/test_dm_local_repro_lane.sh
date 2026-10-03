#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## dm-local-repro-build BOTH launches a build and reads its artifact from the shared binary_mnt.
## Once builds are laned (dist_build_slot), an UN-laned read rooted at the flat binary_mnt would
## descend into a CONCURRENT build's lane and cat a FOREIGN artifact's sha512 as the comparison
## key -- a wrong verdict. So this tool must lane its own build and scope every find to that lane.
## The real lines are extracted + eval'd (no copy to drift); the finds are checked structurally.
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

## Extract the two real resolution lines and eval them.
slot_line="$(grep -E '^build_slot=' -- "${subject}")"
lane_line="$(grep -E '^binary_lane=' -- "${subject}")"
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

## Structural: the slot is VALIDATED (reused check_is_alpha_numeric) before it is spliced
## into the heredoc / find roots. CANARY: fails on the pre-validation version.
if grep -E 'check_is_alpha_numeric[[:space:]]+build_slot' -- "${subject}" >/dev/null; then
   pass "build_slot is validated with check_is_alpha_numeric before use"
else
   fail "build_slot is NOT validated -- a '..'/quote/space slot would break out of the heredoc or lane"
fi

## Behavioral: the chosen validator rejects exactly the dangerous inputs the finding named
## (injection, path traversal, glob, empty) and accepts a real session slug (UUID has '-').
# shellcheck disable=SC1091
if source "${HELPER_SCRIPTS_PATH:-}"/usr/libexec/helper-scripts/strings.bsh 2>/dev/null; then
   v_ok=0
   for bad in "x'; echo pwn; echo '" 'a;b' 'a b' '..' '../x' 'a/b' '*' ''; do
      probe="${bad}"
      if check_is_alpha_numeric probe 2>/dev/null; then v_ok=1; printf '%s\n' "  rejected-expected but ACCEPTED: '${bad}'"; fi
   done
   for good in 277f00ff-57c2-47bf-ac87-5e120a5fe030 stub-slug lane_1; do
      probe="${good}"
      if ! check_is_alpha_numeric probe 2>/dev/null; then v_ok=1; printf '%s\n' "  accepted-expected but REJECTED: '${good}'"; fi
   done
   if [ "${v_ok}" -eq 0 ]; then pass "check_is_alpha_numeric rejects injection/traversal/glob/empty, accepts a UUID slug"; else fail "check_is_alpha_numeric verdict unexpected (see above)"; fi
else
   fail "cannot source helper-scripts strings.bsh to verify the validator (set HELPER_SCRIPTS_PATH)"
fi

printf '%s\n' "" "${pass_count} pass, ${fail_count} fail, 0 skip"
[ "${fail_count}" -eq 0 ]
