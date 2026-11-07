#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The --source built lanes: test a LOCALLY-BUILT artifact instead of downloading.
## kicksecure built = --iso (a git-describe build version 18.2.3.0-222-g<sha> is NOT a release
## token, so it must NOT flow through rt_version_token / the eph account-name ceiling -- a built
## run uses a FIXED eph-inst-GUEST-built account and records origin=built). whonix built =
## --ova-gw/--ova-ws under the persistent persist-inst-/persist-leak- account. --source is
## MANDATORY and coupled to the artifact flags. Canary: on the old (no --source) code the flag
## is unknown and the coupling rejections do not exist.

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

failures=0
ok()  { printf '%s\n' "ok: $1"; }
bad() { printf '%s\n' "FAIL: $1" >&2; failures=$((failures + 1)); }

## --- pure helpers (source the guarded main) ---
# shellcheck disable=SC1090
source "${subject}"

## A git-describe tail is reduced to a concise, path-safe <count>-g<12-hex> label.
iso_name='Kicksecure-LXQt-18.2.3.0-222-g0355db7f4fe1b4a73573d6d61aa50833369a8f26.Intel_AMD64.iso'
got="$(rt_build_version_from_iso "/home/admin/derivative-binary/x/${iso_name}")"
if [ "${got}" = '222-g0355db7f4fe1' ]; then
   ok 'rt_build_version_from_iso reduces a git-describe tail to <count>-g<short-sha>'
else
   bad "rt_build_version_from_iso: got '${got}'"
fi

## The real dm dev build-version (builder-id prefix + TWO 40-char hashes) is >64 chars and
## used to FAIL rt_build_version_ok -> require a hand-passed --version. It now auto-reduces to
## a concise, path-safe, self-describing label (regression for the opaque-version bug).
devname='Kicksecure-LXQt-adrelanos_f65a6f9f513e60777ed356d7de9032de652e6b91-1974-g8f5fa3b0b722686b80de4e451641ac41c747d843.Intel_AMD64.iso'
gotdev="$(rt_build_version_from_iso "/home/admin/derivative-binary/x/${devname}")"
if [ "${gotdev}" = '1974-g8f5fa3b0b722' ] && rt_build_version_ok "${gotdev}"; then
   ok 'rt_build_version_from_iso auto-derives a concise path-safe label from the full dev version'
else
   bad "rt_build_version_from_iso dev version: got '${gotdev}'"
fi

## path-safe labels accepted; traversal / separators / bad charset / overlong rejected.
for good in '18.2.3.0-222-g0355db7f' '18.2.1.9' '1.0+build-1'; do
   if rt_build_version_ok "${good}"; then
      ok "rt_build_version_ok accepts '${good}'"
   else
      bad "rt_build_version_ok rejected a safe label '${good}'"
   fi
done
printf -v overlong_tag 'x%065d' 0
for evil in '../etc' 'a/b' 'a..b' 'has space' '-rc' '--help' '.' '..' "${overlong_tag}"; do
   if rt_build_version_ok "${evil}"; then
      bad "rt_build_version_ok accepted an unsafe label '${evil}'"
   else
      ok 'rt_build_version_ok rejects an unsafe label'
   fi
done

## rt_build_version_from_iso fails CLOSED on a non-matching / arch-less name (never a
## silent blind-last-dot truncation); the caller then requires --version.
for badname in 'custom.iso' 'Kicksecure-LXQt-18.2.3.0.iso' 'foo-bar.Intel_AMD64.iso'; do
   if rt_build_version_from_iso "/x/${badname}" >/dev/null 2>&1; then
      bad "rt_build_version_from_iso wrongly derived a label from '${badname}'"
   else
      ok "rt_build_version_from_iso fails closed on '${badname}'"
   fi
done

## --- the lane wiring (run the real script, --dry-run so no VM/root) ---
d="$(mktemp --directory)"
iso="${d}/${iso_name}"
touch -- "${iso}"
cleanup() { safe-rm --recursive --force -- "${d}"; }
trap cleanup EXIT

plan="$("${subject}" kicksecure lxqt --source built --iso "${iso}" --firmware efi --checks --dry-run 2>&1)"
if grep --quiet 'origin=built' <<<"${plan}"; then ok 'kicksecure built plan records origin=built'; else bad "no origin=built in plan: ${plan}"; fi
if grep --quiet 'account=eph-inst-kicksecure-built' <<<"${plan}"; then ok 'kicksecure built uses the fixed eph-inst-kicksecure-built account'; else bad "wrong account in plan: ${plan}"; fi
if grep --quiet 'resolved=222-g0355db7f4fe1' <<<"${plan}"; then ok 'kicksecure built derives the concise version label into the plan'; else bad "no derived version in plan: ${plan}"; fi

## --source is MANDATORY: absence fails loud (never a silently-picked source). Canary: the old
## code had no --source and ran the lane anyway.
if nosrc_err="$("${subject}" kicksecure lxqt --iso "${iso}" --dry-run 2>&1)"; then
   bad "missing --source wrongly accepted: ${nosrc_err}"
else
   case "${nosrc_err}" in
      *'--source'*)
         ok 'missing --source rejected (mandatory)'
         ;;
      *)
         bad "missing --source failed for the wrong reason: ${nosrc_err}"
         ;;
   esac
fi

## Coupling: an artifact flag is built-only. --source official + --iso is rejected (a source+
## artifact mismatch could otherwise silently test the wrong subject).
if "${subject}" kicksecure lxqt --source official --iso "${iso}" --dry-run >/dev/null 2>&1; then
   bad '--source official + --iso wrongly accepted'
else
   ok '--source official forbids --iso (coupling)'
fi

## kicksecure --source built REQUIRES --iso.
if "${subject}" kicksecure lxqt --source built --dry-run >/dev/null 2>&1; then
   bad 'kicksecure --source built without --iso wrongly accepted'
else
   ok 'kicksecure --source built requires --iso'
fi

## --iso is kicksecure-only (whonix built uses the --ova pair, not an ISO install).
if "${subject}" whonix lxqt --lane inst --source built --iso "${iso}" --version 18.2.3.0-g9999 --dry-run >/dev/null 2>&1; then
   bad '--iso wrongly accepted for whonix built'
else
   ok '--iso rejected for whonix built (kicksecure-only)'
fi

## An EMPTY --iso value must be REJECTED, never read as "no artifact". The pre-fix '-ge 2'-only
## check accepted '--iso ""'.
if empty_iso_err="$("${subject}" kicksecure lxqt --source built --iso '' --dry-run 2>&1)"; then
   bad "empty --iso value wrongly accepted: ${empty_iso_err}"
else
   case "${empty_iso_err}" in
      *'empty value for --iso'*)
         ok 'empty --iso value rejected'
         ;;
      *)
         bad "empty --iso failed for the wrong reason: ${empty_iso_err}"
         ;;
   esac
fi

## A built result must NOT overwrite an official-release cell: a release-shaped label
## (pure dotted token) is rejected.
if "${subject}" kicksecure lxqt --source built --iso "${iso}" --version 18.2.3.0 --dry-run >/dev/null 2>&1; then
   bad '--version with a release-shaped label was wrongly accepted'
else
   ok 'release-shaped --version label rejected (no official-cell overwrite)'
fi

## a LONG pure-dotted label (> the 32-char release-token cap) is still release-shaped.
if "${subject}" kicksecure lxqt --source built --iso "${iso}" --version 1.2.3.4.5.6.7.8.9.0.1.2.3.4.5.6.7.8 --dry-run >/dev/null 2>&1; then
   bad 'long pure-dotted --version label wrongly accepted'
else
   ok 'long pure-dotted --version label rejected'
fi

## a build-distinct override IS accepted and keeps origin=built.
over_plan="$("${subject}" kicksecure lxqt --source built --iso "${iso}" --version 18.2.3.0-g9999 --dry-run 2>&1)"
if grep --quiet 'resolved=18.2.3.0-g9999' <<<"${over_plan}" && grep --quiet 'origin=built' <<<"${over_plan}"; then
   ok '--version build-distinct override accepted, keeps origin=built'
else
   bad "build-distinct --version override failed: ${over_plan}"
fi

## the filename desktop must match INTERFACE (no CLI build under the lxqt cell).
mismatch_iso="${d}/Kicksecure-CLI-18.2.3.0-222-gdead.Intel_AMD64.iso"
touch -- "${mismatch_iso}"
if "${subject}" kicksecure lxqt --source built --iso "${mismatch_iso}" --dry-run >/dev/null 2>&1; then
   bad 'interface/desktop mismatch wrongly accepted'
else
   ok 'interface/desktop mismatch rejected'
fi

## --- whonix --source built (two-phase: --provision imports the --ova pair; a TEST run carries
##     NO ovas and only verifies the pinned marker, like the official lane) ---
ova_gw="${d}/Whonix-Gateway-CLI-build.ova"
ova_ws="${d}/Whonix-Workstation-CLI-build.ova"
touch -- "${ova_gw}" "${ova_ws}"

## inst TEST run (no ovas): plan records origin=built, state=built, the persist-inst- account
## (shared with the official blessed lane; the build-distinct marker distinguishes the pair).
winst_plan="$("${subject}" whonix cli --lane inst --source built --version 18.2.3.0-g9999 --dry-run 2>&1)"
if grep --quiet 'origin=built' <<<"${winst_plan}" && grep --quiet 'source=built' <<<"${winst_plan}"; then ok 'whonix built inst plan records origin=built source=built'; else bad "whonix built inst plan: ${winst_plan}"; fi
if grep --quiet 'state=built' <<<"${winst_plan}"; then ok 'whonix built inst uses account_kind=built'; else bad "whonix built inst state: ${winst_plan}"; fi
if grep --quiet 'account=persist-inst-whonix' <<<"${winst_plan}"; then ok 'whonix built inst uses persist-inst-whonix'; else bad "whonix built inst account: ${winst_plan}"; fi

## leak TEST run: stays in persist-leak-whonix (account_kind=leak).
wleak_plan="$("${subject}" whonix cli --lane leak --source built --version 18.2.3.0-g9999 --dry-run 2>&1)"
if grep --quiet 'account=persist-leak-whonix' <<<"${wleak_plan}" && grep --quiet 'state=leak' <<<"${wleak_plan}"; then ok 'whonix built leak stays persist-leak-whonix (account_kind=leak)'; else bad "whonix built leak plan: ${wleak_plan}"; fi

## a TEST run must REJECT --ova-* (they are a provision-only input; carrying them on a test run
## is the misleading decorative-path the review flagged -- the run tests the pre-imported pair).
if "${subject}" whonix cli --lane inst --source built --ova-gw "${ova_gw}" --ova-ws "${ova_ws}" --version 18.2.3.0-g9999 --dry-run >/dev/null 2>&1; then
   bad 'whonix built TEST run wrongly accepted --ova-* (provision-only)'
else
   ok 'whonix built TEST run rejects --ova-* (provision-only)'
fi

## --provision imports the pair: plan records mode=provision + the ova paths.
wprov_plan="$("${subject}" whonix cli --lane inst --source built --ova-gw "${ova_gw}" --ova-ws "${ova_ws}" --version 18.2.3.0-g9999 --provision --dry-run 2>&1)"
if grep --quiet 'mode=provision' <<<"${wprov_plan}" && grep --quiet "ova_gw=${ova_gw}" <<<"${wprov_plan}"; then ok 'whonix built --provision plan records the ova pair'; else bad "whonix built provision plan: ${wprov_plan}"; fi

## --provision needs BOTH ovas.
if "${subject}" whonix cli --lane inst --source built --ova-gw "${ova_gw}" --version 18.2.3.0-g9999 --provision --dry-run >/dev/null 2>&1; then
   bad 'whonix built --provision with only --ova-gw wrongly accepted'
else
   ok 'whonix built --provision requires both --ova-gw and --ova-ws'
fi

## whonix --source built requires an explicit build-distinct --version (no OVA-name derivation).
if "${subject}" whonix cli --lane inst --source built --dry-run >/dev/null 2>&1; then
   bad 'whonix built without --version wrongly accepted'
else
   ok 'whonix built requires --version'
fi

## a release-shaped --version is rejected for whonix built too, INCLUDING the dash form that
## folds to the same results cell as the official dotted release (no official-cell overwrite).
for rel in 18.2.3.0 18-2-3-0; do
   if "${subject}" whonix cli --lane inst --source built --version "${rel}" --dry-run >/dev/null 2>&1; then
      bad "whonix built release-shaped --version '${rel}' wrongly accepted"
   else
      ok "whonix built rejects release-shaped --version '${rel}'"
   fi
done

## --ova flags are built-only: --source official + --ova-gw is rejected.
if "${subject}" whonix cli --lane inst --source official --ova-gw "${ova_gw}" --ova-ws "${ova_ws}" --dry-run >/dev/null 2>&1; then
   bad '--source official + --ova pair wrongly accepted'
else
   ok '--source official forbids --ova-gw/--ova-ws (coupling)'
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "" "${failures} built-iso-lane assertion(s) failed" >&2
   exit 1
fi
printf '%s\n' "" "all built-iso-lane assertions passed"
