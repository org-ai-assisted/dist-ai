#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## vbox-image-test-default encodes the lane-importance policy: the DEFAULT set is the five
## conservative lanes (kicksecure lxqt EFI+SecureBoot, kicksecure lxqt BIOS, whonix lxqt BIOS
## inst, whonix lxqt BIOS leak, whonix cli BIOS inst); coreboot / extra lanes are OPT-IN only;
## --no-publish and --channel/--iso flow through. EVERY emitted lane carries the mandatory
## --source (built for a kicksecure --iso, official otherwise). vbox-image-test is stubbed
## (records the lane argv it is handed); no server, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

bin="${VBOX_IMAGE_TEST_DEFAULT_BIN:-vbox-image-test-default}"
[ -x "${bin}" ] || { printf '%s\n' "FATAL: vbox-image-test-default not executable at '${bin}'" >&2; exit 1; }

pass_count=0
fail_count=0
pass() { pass_count=$(( pass_count + 1 )); printf '%s\n' "PASS: ${1}"; }
fail() { fail_count=$(( fail_count + 1 )); printf '%s\n' "FAIL: ${1}"; }
want() {
   if [ "${1}" = "${2}" ]; then
      pass "${3} (${1})"
   else
      fail "${3}: got '${1}', want '${2}'"
   fi
}

work="$(mktemp --directory)"
# shellcheck disable=SC2317  # invoked via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}" || true; }
trap cleanup EXIT

## Stub vbox-image-test: record each arg (one per line).
stub="${work}/stub"
mkdir --parents -- "${stub}"
cat > "${stub}/vbox-image-test" <<'STUB'
#!/bin/bash
for a in "$@"; do printf '%s\n' "${a}" >> "${VIT_ARGS}"; done
STUB
chmod +x -- "${stub}/vbox-image-test"
export PATH="${stub}:${PATH}"

args="${work}/args"
run() { true > "${args}"; VIT_ARGS="${args}" "${bin}" "$@"; }
line() { sed -n "${1}p" "${args}"; }
has() { grep --quiet --fixed-strings -- "${1}" "${args}"; }
n() { wc --lines < "${args}" | tr --delete ' '; }

# --- default: exactly the 5 conservative lanes, no --no-publish ---
run
want "$(n)" 5 "default = 5 lanes"
want "$(line 1)" "kicksecure lxqt --source official --channel stable --firmware efi-secureboot" "lane 1 = kicksecure lxqt EFI+SecureBoot (release)"
want "$(line 2)" "kicksecure lxqt --source official --channel stable --firmware bios" "lane 2 = kicksecure lxqt BIOS"
if has "whonix lxqt --lane inst --source official --channel stable --firmware bios"; then pass "default includes whonix lxqt BIOS inst"; else fail "default missing whonix lxqt BIOS inst"; fi
if has "whonix lxqt --lane leak --source official --channel stable --firmware bios"; then pass "default includes whonix lxqt BIOS leak"; else fail "default missing whonix lxqt BIOS leak"; fi
if has "whonix cli --lane inst --source official --channel stable --firmware bios"; then pass "default includes whonix cli BIOS inst"; else fail "default missing whonix cli BIOS inst"; fi
if has "--no-publish"; then fail "default wrongly passed --no-publish"; else pass "default publishes (no --no-publish)"; fi

# --- --source is MANDATORY on dm-release-test, so EVERY emitted lane must carry it. Canary:
#     the old code emitted no --source at all (0 matches). The default set is ALL official. ---
want "$(grep --count -- '--source' "${args}")" "$(n)" "every default lane carries --source"
if has "--source built"; then fail "default (no --iso) wrongly emitted --source built"; else pass "default lanes are all --source official"; fi

# --- Whonix defaults are BIOS, never Secure Boot (primary real usage) ---
if has "whonix lxqt --lane inst --source official --channel stable --firmware efi-secureboot"; then fail "whonix inst wrongly defaults to Secure Boot"; else pass "whonix inst is BIOS by default"; fi

# --- --iso: BOTH kicksecure lanes test the built ISO (--source built, no --channel), firmware
#     preserved; the whonix lanes stay --source official (the pre-imported release pair). ---
run --iso /b.iso
want "$(line 1)" "kicksecure lxqt --source built --iso /b.iso --firmware efi-secureboot" "--iso -> kicksecure EFI+SecureBoot lane tests the built ISO"
want "$(line 2)" "kicksecure lxqt --source built --iso /b.iso --firmware bios" "--iso -> kicksecure BIOS lane tests the built ISO"
if has "whonix lxqt --lane inst --source official --channel stable --firmware bios"; then pass "--iso leaves whonix lanes --source official"; else fail "--iso wrongly changed the whonix source"; fi

# --- coreboot is OPT-IN ---
run
if has "--coreboot-rom"; then fail "coreboot lane present by default (should be opt-in)"; else pass "coreboot is opt-in (absent by default)"; fi
run --coreboot-rom /x.rom
if has "--coreboot-rom /x.rom"; then pass "--coreboot-rom adds a coreboot firmware lane"; else fail "--coreboot-rom did not add the lane"; fi

# --- --no-publish flows through; --channel resolves into every channel-keyed lane ---
run --no-publish
want "$(line 1)" "--no-publish" "--no-publish passed to vbox-image-test"
run --channel developers
if has "kicksecure lxqt --source official --channel developers --firmware efi-secureboot"; then pass "--channel developers resolves (kicksecure)"; else fail "--channel not applied to kicksecure"; fi
if has "whonix lxqt --lane leak --source official --channel developers --firmware bios"; then pass "--channel developers resolves (whonix)"; else fail "--channel not applied to whonix"; fi

# --- --add appends a raw lane ---
run --add "kicksecure lxqt --firmware bios"
if has "kicksecure lxqt --firmware bios"; then pass "--add appends a raw lane"; else fail "--add did not append"; fi

printf '%s\n' "----"
printf '%s\n' "passed=${pass_count} failed=${fail_count}"
[ "${fail_count}" -eq 0 ]
