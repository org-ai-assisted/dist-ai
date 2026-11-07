#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## vbox-image-test-default encodes the lane-importance policy: the DEFAULT set is exactly the
## three conservative LXQt + efi-secureboot lanes (kicksecure lxqt, whonix inst, whonix leak);
## cli / coreboot / extra lanes are OPT-IN only; --no-publish and --channel/--iso flow through.
## vbox-image-test is stubbed (records the lane argv it is handed); no server, no network.

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

# --- default: exactly the 3 conservative lanes, no --no-publish ---
run
want "$(n)" 3 "default = 3 lanes"
want "$(line 1)" "kicksecure lxqt --channel stable" "default lane 1 = kicksecure lxqt (release)"
if has "whonix lxqt --lane inst --channel stable"; then pass "default includes whonix inst"; else fail "default missing whonix inst"; fi
if has "whonix lxqt --lane leak --channel stable"; then pass "default includes whonix leak"; else fail "default missing whonix leak"; fi
if has "--no-publish"; then fail "default wrongly passed --no-publish"; else pass "default publishes (no --no-publish)"; fi

# --- --iso: the kicksecure lane tests the built ISO ---
run --iso /b.iso
want "$(line 1)" "kicksecure lxqt --iso /b.iso" "--iso -> kicksecure lane tests the built ISO"

# --- cli is OPT-IN: absent by default, present with --cli ---
run
if has "kicksecure cli"; then fail "cli lane present by default (should be opt-in)"; else pass "cli is opt-in (absent by default)"; fi
run --cli
want "$(n)" 4 "--cli adds one lane"
if has "kicksecure cli --channel stable"; then pass "--cli adds a kicksecure cli lane"; else fail "--cli did not add the cli lane"; fi

# --- coreboot is OPT-IN ---
run --coreboot-rom /x.rom
if has "--coreboot-rom /x.rom"; then pass "--coreboot-rom adds a coreboot firmware lane"; else fail "--coreboot-rom did not add the lane"; fi

# --- --no-publish flows through; --channel resolves ---
run --no-publish
want "$(line 1)" "--no-publish" "--no-publish passed to vbox-image-test"
run --channel developers
if has "kicksecure lxqt --channel developers"; then pass "--channel developers resolves"; else fail "--channel not applied"; fi

# --- --add appends a raw lane ---
run --add "kicksecure lxqt --firmware bios"
if has "kicksecure lxqt --firmware bios"; then pass "--add appends a raw lane"; else fail "--add did not append"; fi

printf '%s\n' "----"
printf '%s\n' "passed=${pass_count} failed=${fail_count}"
[ "${fail_count}" -eq 0 ]
