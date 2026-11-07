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

# --- F3 (thread 601C2b) invariant: with --iso, ONLY the kicksecure LXQt lanes carry --iso; no
#     cli lane and no whonix lane does (the stale finding feared --iso leaking into a CLI lane). ---
if grep --quiet -E 'whonix.*--iso' "${args}"; then fail "a whonix lane wrongly carries --iso"; else pass "no whonix lane carries --iso (F3 invariant)"; fi
if grep --quiet -E 'cli.*--iso' "${args}"; then fail "a cli lane wrongly carries --iso"; else pass "no cli lane carries --iso (F3 invariant)"; fi

# --- grok#3 guard: an --iso path with whitespace is rejected early (exit 64) -- a lane is one
#     space-joined string, so a space would mis-split on the remote shell. Canary: old accepted. ---
ws_rc=0
true > "${args}"
VIT_ARGS="${args}" "${bin}" --iso '/built image.iso' >/dev/null 2>&1 || ws_rc=$?
want "${ws_rc}" 64 "--iso path with whitespace rejected (exit 64)"

# --- coreboot is OPT-IN ---
run
if has "--coreboot-rom"; then fail "coreboot lane present by default (should be opt-in)"; else pass "coreboot is opt-in (absent by default)"; fi
run --coreboot-rom /x.rom
if has "--coreboot-rom /x.rom"; then pass "--coreboot-rom adds a coreboot firmware lane"; else fail "--coreboot-rom did not add the lane"; fi

# --- --no-publish flows through ---
run --no-publish
want "$(line 1)" "--no-publish" "--no-publish passed to vbox-image-test"

# --- --channel developers: whonix OVAs are not auto-discoverable, so --version is REQUIRED.
#     Canary: old code emitted whonix developers lanes that die at version resolution; now the
#     batch is rejected EARLY (exit 64) before any lane is built. ---
dev_rc=0
true > "${args}"
VIT_ARGS="${args}" "${bin}" --channel developers >/dev/null 2>&1 || dev_rc=$?
want "${dev_rc}" 64 "--channel developers without --version is rejected (exit 64)"
if [ -s "${args}" ]; then fail "rejected developers run still emitted lanes"; else pass "rejected developers run emitted no lanes"; fi

# --- --channel developers --version VER: threaded into the whonix lanes ONLY (kicksecure
#     auto-discovers; a whonix version must not pin kicksecure's). ---
run --channel developers --version 18.9
if has "whonix lxqt --lane inst --source official --channel developers --version 18.9 --firmware bios"; then pass "developers --version threads into whonix inst"; else fail "whonix inst missing --version"; fi
if has "whonix lxqt --lane leak --source official --channel developers --version 18.9 --firmware bios"; then pass "developers --version threads into whonix leak"; else fail "whonix leak missing --version"; fi
if has "whonix cli --lane inst --source official --channel developers --version 18.9 --firmware bios"; then pass "developers --version threads into whonix cli"; else fail "whonix cli missing --version"; fi
want "$(line 1)" "kicksecure lxqt --source official --channel developers --firmware efi-secureboot" "developers kicksecure lane carries NO --version (auto-discover)"

# --- codex#1: a --version value with whitespace would inject extra dm-release-test options into
#     the whonix lanes (--version '18.9 --lane leak' -> --lane leak lands as a separate arg).
#     Rejected early. Canary: old code accepted it and the injected option reached the lane. ---
inj_rc=0
true > "${args}"
VIT_ARGS="${args}" "${bin}" --channel developers --version '18.9 --lane leak' >/dev/null 2>&1 || inj_rc=$?
want "${inj_rc}" 64 "--version with whitespace (option injection) rejected (exit 64)"
if grep --quiet -E 'kicksecure.*--version' "${args}"; then fail "kicksecure lane wrongly carries --version"; else pass "no kicksecure lane carries --version"; fi

# --- --add appends a raw lane ---
run --add "kicksecure lxqt --firmware bios"
if has "kicksecure lxqt --firmware bios"; then pass "--add appends a raw lane"; else fail "--add did not append"; fi

# --- --dry-run / --print-lanes: print the resolved lanes to stdout and NEVER invoke
#     vbox-image-test (merely running this tool otherwise fires the real OVH batch).
#     Canary: old code rejected --dry-run as an unknown argument (exit 64). ---
dr_out="${work}/dryrun.out"
dr_rc=0
true > "${args}"
VIT_ARGS="${args}" "${bin}" --dry-run >"${dr_out}" 2>/dev/null || dr_rc=$?
want "${dr_rc}" 0 "--dry-run exits 0"
if [ -s "${args}" ]; then fail "--dry-run wrongly invoked vbox-image-test"; else pass "--dry-run did not invoke vbox-image-test"; fi
want "$(wc --lines < "${dr_out}" | tr --delete ' ')" 5 "--dry-run printed the 5 lanes"
if grep --quiet --fixed-strings 'kicksecure lxqt --source official --channel stable --firmware efi-secureboot' "${dr_out}"; then pass "--dry-run printed the flagship lane"; else fail "--dry-run missing the flagship lane"; fi
pl_rc=0
true > "${args}"
VIT_ARGS="${args}" "${bin}" --print-lanes >/dev/null 2>&1 || pl_rc=$?
want "${pl_rc}" 0 "--print-lanes alias exits 0"
if [ -s "${args}" ]; then fail "--print-lanes wrongly invoked vbox-image-test"; else pass "--print-lanes did not invoke vbox-image-test"; fi

printf '%s\n' "----"
printf '%s\n' "passed=${pass_count} failed=${fail_count}"
[ "${fail_count}" -eq 0 ]
