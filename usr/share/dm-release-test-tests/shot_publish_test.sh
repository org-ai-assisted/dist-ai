#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Canary: rt_publish_result must FORWARD its shot arg (6th positional) to
## image_test_results_publish's shot_src (7th arg), and forward an empty shot as
## empty. A reverted change that hardcoded "" would silently drop every screenshot
## from the results plane. Sources the REAL dm-release-test (guarded main) and
## stubs image_test_results_publish to capture the forwarded shot_src.

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

failures=0
## rt_publish_result calls the publisher inside a command substitution (a subshell), so
## a global set by the stub would not escape -- capture via a FILE instead.
capture_file="$(mktemp --tmpdir dm-release-test-shotcap.XXXXXX)"
argv_file="$(mktemp --tmpdir dm-release-test-argvcap.XXXXXX)"
rc_file="$(mktemp --tmpdir dm-release-test-rccap.XXXXXX)"
shot_cap_cleanup() { safe-rm --force -- "${capture_file}" "${argv_file}" "${rc_file}"; }
trap shot_cap_cleanup EXIT
captured_shot='UNSET'

## Stub the publisher: record the 7th positional (shot_src) the lane forwards, the 6th (rc, so a
## test can assert the blank gate flipped a passing run to FAIL) AND the whole argv (to assert
## option passthrough), and print an outdir so rt_publish_result's summary line does not choke.
# shellcheck disable=SC2329  ## invoked indirectly by rt_publish_result
image_test_results_publish() {
   printf '%s' "$7" > "${capture_file}"
   printf '%s' "$6" > "${rc_file}"
   printf '%s\n' "$*" > "${argv_file}"
   printf '%s' "/nonexistent/outdir"
}

## Globals rt_publish_result reads (interface is part of the results subtree name).
# shellcheck disable=SC2034
RESULTS_ROOT='/nonexistent/results'
# shellcheck disable=SC2034
RESULTS_OWNER='nobody'
# shellcheck disable=SC2034
interface='lxqt'
## Firmware axis: rt_publish_result reads it to disambiguate both the Calamares-install lane
## (bios vs efi are separate goldens) AND, since #28, the whonix lanes (the imported pair has the
## requested firmware applied at provision, so bios vs efi are separate cells there too).
# shellcheck disable=SC2034
firmware='efi'

assert_shot() {
   local label="$1" expected="$2"
   if [ "${captured_shot}" = "${expected}" ]; then
      printf '%s\n' "ok: ${label}"
   else
      printf '%s\n' "FAIL: ${label}: got '${captured_shot}', expected '${expected}'" >&2
      failures=$((failures + 1))
   fi
}

## A real shot path must reach shot_src.
rt_publish_result kicksecure 18.2.3.5 acct calamares-install 0 /nonexistent/shot.png Kicksecure >/dev/null
captured_shot="$(cat -- "${capture_file}")"
assert_shot "rt_publish_result forwards a shot path" '/nonexistent/shot.png'

## An empty shot (download failure / packet-based lane) must forward as empty.
rt_publish_result whonix 18.2.3.5 acct whonix-pair 0 '' tor-confirm >/dev/null
captured_shot="$(cat -- "${capture_file}")"
assert_shot "rt_publish_result forwards an empty shot" ''

## A non-empty rt_check_log (a FAILED check's output) threads as --step-stderr-file,
## so the run record explains WHY it failed.
clog="$(mktemp --tmpdir dm-release-test-clog.XXXXXX)"
printf '%s\n' "check 8 (systemcheck) FAILED:" "systemcheck unknown option: --ci" > "${clog}"
# shellcheck disable=SC2034  ## read by the sourced rt_publish_result (dynamic scope)
rt_check_log="${clog}"
rt_publish_result kicksecure 18.2.3.5 acct calamares-install 5 '' Kicksecure >/dev/null
if grep --quiet -- "--step-stderr-file ${clog}" "${argv_file}"; then
   printf '%s\n' "ok: rt_publish_result threads rt_check_log as --step-stderr-file"
else
   printf '%s\n' "FAIL: --step-stderr-file not forwarded: $(cat -- "${argv_file}")" >&2
   failures=$((failures + 1))
fi

## Canary: rt_check_log is consumed ONCE -- the next publish (no failed check) must
## NOT re-forward the stale path.
rt_publish_result kicksecure 18.2.3.5 acct calamares-install 0 '' Kicksecure >/dev/null
if grep --quiet -- '--step-stderr-file' "${argv_file}"; then
   printf '%s\n' "FAIL: rt_check_log leaked to the next publish" >&2
   failures=$((failures + 1))
else
   printf '%s\n' "ok: rt_check_log consumed once (reset after use)"
fi
safe-rm --force -- "${clog}"

## A non-empty rt_stdout_log (the step's FULL successful output) threads as --step-stdout-file,
## so a PASS carries EVIDENCE (the per-check lines + proof the battery ran) -- not a black box.
slog="$(mktemp --tmpdir dm-release-test-slog.XXXXXX)"
printf '%s\n' "check 8 PASS" "check 3 PASS (apt-get full-upgrade from local repo)" > "${slog}"
# shellcheck disable=SC2034  ## read by the sourced rt_publish_result (dynamic scope)
rt_stdout_log="${slog}"
rt_publish_result whonix 18.2.3.5 acct whonix-func 0 '' release-checks >/dev/null
if grep --quiet -- "--step-stdout-file ${slog}" "${argv_file}"; then
   printf '%s\n' "ok: rt_publish_result threads rt_stdout_log as --step-stdout-file (PASS evidence)"
else
   printf '%s\n' "FAIL: --step-stdout-file not forwarded: $(cat -- "${argv_file}")" >&2
   failures=$((failures + 1))
fi

## Canary: rt_stdout_log is consumed ONCE -- the next publish must NOT re-forward the stale path.
rt_publish_result whonix 18.2.3.5 acct whonix-func 0 '' release-checks >/dev/null
if grep --quiet -- '--step-stdout-file' "${argv_file}"; then
   printf '%s\n' "FAIL: rt_stdout_log leaked to the next publish" >&2
   failures=$((failures + 1))
else
   printf '%s\n' "ok: rt_stdout_log consumed once (reset after use)"
fi
safe-rm --force -- "${slog}"

## Firmware is part of the Calamares-install lane identity: bios and efi installs produce
## DIFFERENT screenshots (firmware menu, boot chrome), so they must land in separate
## subtrees / sids / goldens and separate overview rows -- never collide. Assert the
## firmware suffix reaches BOTH the results subtree name (3rd positional) and --lane.
# shellcheck disable=SC2034  ## read by the sourced rt_publish_result (dynamic scope)
firmware='bios'
rt_publish_result kicksecure 18.2.3.6 acct calamares-install 0 '' Kicksecure >/dev/null
if grep --quiet -- '--lane kicksecure-lxqt-bios ' "${argv_file}"; then
   printf '%s\n' "ok: calamares-install --lane carries firmware (kicksecure-lxqt-bios)"
else
   printf '%s\n' "FAIL: calamares-install --lane missing firmware: $(cat -- "${argv_file}")" >&2
   failures=$((failures + 1))
fi
if grep --quiet -- 'kicksecure-lxqt-bios-18-2-3-6' "${argv_file}"; then
   printf '%s\n' "ok: calamares-install subtree name carries firmware"
else
   printf '%s\n' "FAIL: calamares-install subtree name missing firmware: $(cat -- "${argv_file}")" >&2
   failures=$((failures + 1))
fi

## #28: a whonix lane carries the firmware axis -- whonix is BIOS-only (dm-vbox-firmware applies
## bios to the imported pair at provision), so the suffix is -bios. (rt_lane_key unset here, so no
## inst/leak component -- just guest-interface-firmware.)
rt_publish_result whonix 18.2.3.6 acct whonix-pair 0 '' tor-confirm >/dev/null
if grep --quiet -- '--lane whonix-lxqt-bios ' "${argv_file}" \
   && grep --quiet -- 'whonix-lxqt-bios-18-2-3-6' "${argv_file}"; then
   printf '%s\n' "ok: whonix-pair lane carries the firmware suffix (whonix-lxqt-bios)"
else
   printf '%s\n' "FAIL: whonix-pair lane missing firmware suffix: $(cat -- "${argv_file}")" >&2
   failures=$((failures + 1))
fi

## Lane key (inst|leak) AND firmware are folded into BOTH the subtree and --lane so the whonix
## lanes never collide: lane = guest-interface-[inst|leak]-firmware.
## Canary: without the lane component the inst/leak runs publish to the same cell.
# shellcheck disable=SC2034  ## read by the sourced rt_publish_result (dynamic scope)
rt_lane_key='leak'
rt_publish_result whonix 18.2.3.6 acct whonix-pair 0 '' tor-confirm >/dev/null
if grep --quiet -- '--lane whonix-lxqt-leak-bios ' "${argv_file}" \
   && grep --quiet -- 'whonix-lxqt-leak-bios-18-2-3-6' "${argv_file}"; then
   printf '%s\n' "ok: leak lane key + firmware reach --lane + subtree (whonix-lxqt-leak-bios)"
else
   printf '%s\n' "FAIL: leak lane key missing: $(cat -- "${argv_file}")" >&2
   failures=$((failures + 1))
fi
# shellcheck disable=SC2034  ## read by the sourced rt_publish_result (dynamic scope)
rt_lane_key='inst'
rt_publish_result whonix 18.2.3.6 acct whonix-func 0 '' release-checks >/dev/null
if grep --quiet -- '--lane whonix-lxqt-inst-bios ' "${argv_file}" \
   && grep --quiet -- 'whonix-lxqt-inst-bios-18-2-3-6' "${argv_file}"; then
   printf '%s\n' "ok: inst lane key + firmware reach --lane + subtree (whonix-lxqt-inst-bios)"
else
   printf '%s\n' "FAIL: inst lane key missing: $(cat -- "${argv_file}")" >&2
   failures=$((failures + 1))
fi
## Canary: rt_lane_key is consumed ONCE -- the next publish has no inst/leak key (the firmware
## axis stays), so the lane is the bare guest-interface-firmware again.
rt_publish_result whonix 18.2.3.6 acct whonix-pair 0 '' tor-confirm >/dev/null
if grep --quiet -- '--lane whonix-lxqt-bios ' "${argv_file}"; then
   printf '%s\n' "ok: rt_lane_key consumed once (no inst/leak key after; firmware stays)"
else
   printf '%s\n' "FAIL: rt_lane_key leaked to the next publish: $(cat -- "${argv_file}")" >&2
   failures=$((failures + 1))
fi

## efi-secureboot is the DEFAULT firmware and the value most real install runs publish
## under; its longer, hyphenated token must survive intact in the lane (no truncation at
## the inner '-').
# shellcheck disable=SC2034  ## read by the sourced rt_publish_result (dynamic scope)
firmware='efi-secureboot'
rt_publish_result kicksecure 18.2.3.6 acct calamares-install 0 '' Kicksecure >/dev/null
if grep --quiet -- '--lane kicksecure-lxqt-efi-secureboot ' "${argv_file}" \
   && grep --quiet -- 'kicksecure-lxqt-efi-secureboot-18-2-3-6' "${argv_file}"; then
   printf '%s\n' "ok: calamares-install lane carries efi-secureboot intact"
else
   printf '%s\n' "FAIL: efi-secureboot lane wrong: $(cat -- "${argv_file}")" >&2
   failures=$((failures + 1))
fi

## Parse-time guard: an unknown --firmware must be REJECTED (SETUP_RC) before it can flow
## into a lane/subtree name. Drive the REAL binary as a subprocess; the die fires in the
## arg loop, before any root/preflight, so it is safe to run unprivileged.
fw_reject="$("${subject}" kicksecure lxqt --firmware bogus --dry-run 2>&1 || true)"
if [[ "${fw_reject}" == *"--firmware must be bios|efi|efi-secureboot, got 'bogus'"* ]]; then
   printf '%s\n' "ok: unknown --firmware rejected at parse time"
else
   printf '%s\n' "FAIL: unknown --firmware not rejected: ${fw_reject}" >&2
   failures=$((failures + 1))
fi

## -------------------------------------------------------------------------------------------------
## BLANK-SCREENSHOT GATE (rt_publish_result): a whonix milestone story dir holding a fully-black
## must-render frame (gateway-booted etc.) must FAIL an otherwise-passing run -- never publish a
## black rectangle as a pass. Regression for the real bug: a 1023984-black + 16-grey-px frame that
## --uniform-only missed. Drives the REAL rt_publish_result with a synthetic blank fixture dir.
magick_bin='convert'
if type -P magick >/dev/null 2>&1; then
   magick_bin='magick'
fi
type -P "${magick_bin}" >/dev/null 2>&1 \
   || { printf '%s\n' "FATAL: ImageMagick (${magick_bin}) required for the blank-gate fixtures" >&2; exit 1; }

## Point the sourced gate at the checkout's image-blank-check (not installed in the test env).
if [ -f "${test_dir}/../../bin/image-blank-check" ]; then
   # shellcheck disable=SC2034  ## read by the sourced rt_publish_result (dynamic scope)
   IMAGE_BLANK_CHECK="${test_dir}/../../bin/image-blank-check"
fi

blank_dir="$(mktemp --directory --tmpdir dm-release-test-blankshots.XXXXXX)"
content_dir="$(mktemp --directory --tmpdir dm-release-test-contentshots.XXXXXX)"
all_cleanup() { shot_cap_cleanup; safe-rm --recursive --force -- "${blank_dir}" "${content_dir}"; }
trap all_cleanup EXIT
## The exact bug shape: ~100% black with a tiny 4x4 grey mark (16 lit px over 1023984 black,
## ~0.002% lit, 2 colours) -- a broken/too-early capture that --uniform-only (single-colour) does
## NOT flag, which is precisely the frame that shipped undetected.
"${magick_bin}" -size 1280x800 xc:black -fill '#aaaaaa' -draw 'rectangle 0,0 3,3' "${blank_dir}/20-gateway-booted.png"
## A real, content-rich desktop frame (plasma = thousands of colours) must NOT be flagged.
"${magick_bin}" -size 1280x800 plasma: "${content_dir}/20-gateway-booted.png"

## whonix-func, passing rc=0, BLANK dir -> gate flips the published rc to FAIL (5) and threads a
## --step-stderr-file so the page states WHY.
rt_publish_result whonix 18.2.4.3 acct whonix-func 0 "${blank_dir}" release-checks >/dev/null
if [ "$(cat -- "${rc_file}")" = '5' ]; then
   printf '%s\n' "ok: blank milestone frame flips a passing whonix-func run to FAIL"
else
   printf '%s\n' "FAIL: blank whonix-func run published rc=$(cat -- "${rc_file}"), expected 5" >&2
   failures=$((failures + 1))
fi
if grep --quiet -- '--step-stderr-file' "${argv_file}"; then
   printf '%s\n' "ok: blank gate threads a --step-stderr-file (the reason reaches the page)"
else
   printf '%s\n' "FAIL: blank gate did not thread a stderr reason: $(cat -- "${argv_file}")" >&2
   failures=$((failures + 1))
fi

## whonix-pair (leak lane) is gated identically.
rt_publish_result whonix 18.2.4.3 acct whonix-pair 0 "${blank_dir}" tor-confirm >/dev/null
if [ "$(cat -- "${rc_file}")" = '5' ]; then
   printf '%s\n' "ok: blank milestone frame flips a passing whonix-pair (leak) run to FAIL"
else
   printf '%s\n' "FAIL: blank whonix-pair run published rc=$(cat -- "${rc_file}"), expected 5" >&2
   failures=$((failures + 1))
fi

## Negative: a content-rich desktop frame must NOT false-fail a passing run.
rt_publish_result whonix 18.2.4.3 acct whonix-func 0 "${content_dir}" release-checks >/dev/null
if [ "$(cat -- "${rc_file}")" = '0' ]; then
   printf '%s\n' "ok: a content-rich milestone frame does NOT false-fail the run"
else
   printf '%s\n' "FAIL: content frame wrongly failed: published rc=$(cat -- "${rc_file}")" >&2
   failures=$((failures + 1))
fi

## Scoping: the calamares lane runs its OWN per-milestone gate, so rt_publish_result must NOT
## double-gate it (a blank dir under calamares-install keeps its rc; no false-fail of sparse frames).
rt_publish_result kicksecure 18.2.4.3 acct calamares-install 0 "${blank_dir}" Kicksecure >/dev/null
if [ "$(cat -- "${rc_file}")" = '0' ]; then
   printf '%s\n' "ok: calamares-install is not double-gated by rt_publish_result"
else
   printf '%s\n' "FAIL: calamares-install wrongly gated: published rc=$(cat -- "${rc_file}")" >&2
   failures=$((failures + 1))
fi

## An already-FAILING whonix run (rc=5 from the battery) with a blank frame keeps rc=5 (its primary
## reason stands) -- the gate does not mask it as a different code, and still records the blank frame.
rt_publish_result whonix 18.2.4.3 acct whonix-func 5 "${blank_dir}" release-checks >/dev/null
if [ "$(cat -- "${rc_file}")" = '5' ]; then
   printf '%s\n' "ok: an already-failing run keeps its rc when a frame is also blank"
else
   printf '%s\n' "FAIL: already-failing run rc changed to $(cat -- "${rc_file}")" >&2
   failures=$((failures + 1))
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "" "${failures} shot-publish assertion(s) failed" >&2
   exit 1
fi
printf '%s\n' "" "all shot-publish assertions passed"
