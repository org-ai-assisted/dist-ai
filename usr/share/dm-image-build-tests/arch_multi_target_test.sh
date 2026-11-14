#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for dm-image-build's `--arch`, `--multi-target` and `--smbios-reader` passthrough:
##   - default (no flags) -> dist_build_target_arch=<native>, dist_build_multi_target_list='',
##     dist_build_smbios_reader=false (byte-identical env to the pre-flag behavior)
##   - --arch arm64           -> dist_build_target_arch=arm64 (CROSS-build on an amd64 host)
##   - --multi-target virtualbox -> dist_build_multi_target_list='virtualbox' (forces the OVA even
##     where the per-arch default omits it, e.g. arm64 in dm-build-official-one)
##   - --multi-target 'virtualbox qcow2' -> the full set preserved verbatim
##   - --arch bogus does NOT crash the parser (dm/parse-cmd validates the arch itself)
##   - --smbios-reader true -> '--smbios-reader true' forwarded to dm-build-official AND
##     dist_build_unlock_dangerous_options=true exported, i.e. routed through the build's
##     dangerous-option gate exactly as CI does (unlock alone WITHOUT the forwarded arg would
##     SKIP error_dangerous_option_maybe); false/absent -> neither
##   - dist_build_smbios_reader is ALWAYS exported from the flag (default false): the var is on
##     dm's env-keep list and 10_misc.bsh only default_if_empty's it, so an inherited
##     dist_build_smbios_reader=true from the caller MUST be clobbered or it would bake the reader
##     in with the gate skipped. A non-boolean --smbios-reader errors (exit 2), never reaching the
##     build spine
## Drives the REAL main() (sourced define-only), with the build spine as a recorder stub that
## captures the EXPORTED env (not just argv), in a fake checkout. No VM, no root, no git repo.
## CANARY: pre-change dm-image-build has none of these flags, so `--arch arm64` / `--multi-target X`
## / `--smbios-reader true` error as unknown arguments (exit 2) and never reach the recorder -> the
## arm64 / virtualbox / smbios assertions FAIL on the old code.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

subject=""
for candidate in "${DM_IMAGE_BUILD:-}" \
   "${test_dir}/../../bin/dm-image-build" \
   "/usr/bin/dm-image-build"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      subject="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
[ -n "${subject}" ] || { printf '%s\n' "FATAL: dm-image-build not found (set DM_IMAGE_BUILD)." >&2; exit 1; }

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## Fake checkout: a .git dir (so the checkout guard passes) + recorder build-spine stubs. The
## dm-build-official recorder captures the two env vars this suite asserts on.
fakedir="${work}/dm"
mkdir -p -- "${fakedir}/.git" "${fakedir}/help-steps"
export DMBO_ARCH="${work}/dmbo.arch"
export DMBO_MULTI="${work}/dmbo.multi"
export DMBO_UNLOCK="${work}/dmbo.unlock"
export DMBO_SMBIOS="${work}/dmbo.smbios"
export DMBO_ARGV="${work}/dmbo.argv"
printf '%s\n' '#!/bin/bash' 'exit 0' > "${fakedir}/help-steps/signing-key-create"
printf '%s\n' '#!/bin/bash' 'exit 0' > "${fakedir}/help-steps/sign-and-tag"
# shellcheck disable=SC2016  ## recorder body: the dist_build_* vars + $* expand when the STUB runs
printf '%s\n' '#!/bin/bash' \
   'printf "%s" "${dist_build_target_arch:-UNSET}" > "${DMBO_ARCH}"' \
   'printf "%s" "${dist_build_multi_target_list-UNSET}" > "${DMBO_MULTI}"' \
   'printf "%s" "${dist_build_unlock_dangerous_options-UNSET}" > "${DMBO_UNLOCK}"' \
   'printf "%s" "${dist_build_smbios_reader-UNSET}" > "${DMBO_SMBIOS}"' \
   'printf "%s\n" "$*" > "${DMBO_ARGV}"' \
   'exit 0' > "${fakedir}/help-steps/dm-build-official"
chmod +x -- "${fakedir}/help-steps/"*

## Stub the host-poking commands main() runs in its cascade. dpkg --print-architecture returns a
## fixed native arch so the default-arch assertion is deterministic.
# shellcheck disable=SC2317  ## called by the sourced main()
git() { case "$*" in "rev-parse HEAD") printf '%s\n' deadbeefdeadbeef ;; *) : ;; esac; }
# shellcheck disable=SC2317
sudo() { return 0; }
# shellcheck disable=SC2317
dpkg() { if [ "${1:-}" = "--print-architecture" ]; then printf '%s\n' amd64; fi; }

# shellcheck disable=SC1090
source "${subject}"

pass=0
fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi; }

## run_main ARGS... -> sets MAIN_RC and the DMBO_ARCH / DMBO_MULTI recorder files (empty if the
## build spine was never reached). main() ends in `exit`, so run it in a subshell.
run_main() {
   true > "${DMBO_ARCH}"
   true > "${DMBO_MULTI}"
   true > "${DMBO_UNLOCK}"
   true > "${DMBO_SMBIOS}"
   true > "${DMBO_ARGV}"
   MAIN_RC=0
   ( main --dir "${fakedir}" "$@" ) >/dev/null 2>&1 || MAIN_RC=$?
}
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

## run_main_env NAME=VAL ... -- ARGS...: run main() with the given vars EXPORTED in the caller
## environment (the subshell inherits them), to prove dm-image-build clobbers an inherited
## dist_build_smbios_reader instead of letting it survive into the build.
run_main_env() {
   local -a env_assign=()
   while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do env_assign+=("$1"); shift; done
   shift  ## drop the "--"
   true > "${DMBO_ARCH}"
   true > "${DMBO_MULTI}"
   true > "${DMBO_UNLOCK}"
   true > "${DMBO_SMBIOS}"
   true > "${DMBO_ARGV}"
   MAIN_RC=0
   ( export "${env_assign[@]}"; main --dir "${fakedir}" "$@" ) >/dev/null 2>&1 || MAIN_RC=$?
}

## --- default: native arch, empty multi-target (byte-identical to pre-flag behavior) -----------
run_main
rc=0; [ "$(cat -- "${DMBO_ARCH}")" = "amd64" ] || rc=1
check 'default -> dist_build_target_arch=<native> (amd64 stub)' "${rc}"
rc=0; [ "$(cat -- "${DMBO_MULTI}")" = "" ] || rc=1
check 'default -> dist_build_multi_target_list empty (per-arch default)' "${rc}"
## Default still forwards the top-level --target iso (byte-identical to pre-flag behavior).
rc=0; has '--target iso' "$(cat -- "${DMBO_ARGV}")" || rc=1
check 'default -> top-level --target iso still forwarded' "${rc}"
## Default MUST NOT enable the reader: no --smbios-reader arg, no dangerous-option unlock.
rc=0; if has '--smbios-reader' "$(cat -- "${DMBO_ARGV}")"; then rc=1; fi
check 'default -> no --smbios-reader forwarded (reader off by default)' "${rc}"
rc=0; [ "$(cat -- "${DMBO_UNLOCK}")" != "true" ] || rc=1
check 'default -> dangerous options NOT unlocked' "${rc}"
## Default MUST export dist_build_smbios_reader=false explicitly (clobber any inherited value).
rc=0; [ "$(cat -- "${DMBO_SMBIOS}")" = "false" ] || rc=1
check 'default -> dist_build_smbios_reader exported false (not UNSET)' "${rc}"

## --- --arch arm64: cross-build arch forwarded -------------------------------------------------
run_main --arch arm64
rc=0; [ "$(cat -- "${DMBO_ARCH}")" = "arm64" ] || rc=1
check '--arch arm64 -> dist_build_target_arch=arm64' "${rc}"

## --- --multi-target virtualbox: forces the OVA target ----------------------------------------
run_main --multi-target virtualbox
rc=0; [ "$(cat -- "${DMBO_MULTI}")" = "virtualbox" ] || rc=1
check '--multi-target virtualbox -> dist_build_multi_target_list=virtualbox' "${rc}"
## MUST NOT leak a top-level --target iso into "$@": dm-build-official-one appends "$@" to the
## per-flavor VM build, so a leaked --target iso would make the OVA build ALSO build an ISO.
rc=0; if has '--target iso' "$(cat -- "${DMBO_ARGV}")"; then rc=1; fi
check '--multi-target build does NOT forward a top-level --target iso' "${rc}"

## --- the arm64 VirtualBox OVA case: both flags together ---------------------------------------
run_main --flavor kicksecure-cli --arch arm64 --multi-target virtualbox
rc=0; [ "$(cat -- "${DMBO_ARCH}")" = "arm64" ] && [ "$(cat -- "${DMBO_MULTI}")" = "virtualbox" ] || rc=1
check 'arm64 + virtualbox together -> both env vars set' "${rc}"

## --- a multi-value set is preserved verbatim -------------------------------------------------
run_main --multi-target 'virtualbox qcow2'
rc=0; [ "$(cat -- "${DMBO_MULTI}")" = "virtualbox qcow2" ] || rc=1
check "--multi-target 'virtualbox qcow2' -> full set preserved" "${rc}"

## --- arch validation is dm/parse-cmd's job, not this wrapper's: any arch string is forwarded,
## the build does not crash early (parse-cmd rejects an invalid arch downstream) ----------------
run_main --arch bogus
rc=0; [ "${MAIN_RC}" -eq 0 ] && [ "$(cat -- "${DMBO_ARCH}")" = "bogus" ] || rc=1
check '--arch <any> forwarded verbatim (parse-cmd validates, not dm-image-build)' "${rc}"

## --- --smbios-reader true: bakes in the GRUB SMBIOS cmdline reader (boot-test images only) ------
run_main --smbios-reader true
rc=0; [ "${MAIN_RC}" -eq 0 ] && has '--smbios-reader true' "$(cat -- "${DMBO_ARGV}")" \
   && [ "$(cat -- "${DMBO_UNLOCK}")" = "true" ] \
   && [ "$(cat -- "${DMBO_SMBIOS}")" = "true" ] || rc=1
check '--smbios-reader true -> forwarded as build arg + dangerous options unlocked' "${rc}"

## --- --smbios-reader false: explicit off is honored (same as default) -------------------------
run_main --smbios-reader false
rc=0
[ "${MAIN_RC}" -eq 0 ] || rc=1
[ "$(cat -- "${DMBO_UNLOCK}")" != "true" ] || rc=1
[ "$(cat -- "${DMBO_SMBIOS}")" = "false" ] || rc=1
if has '--smbios-reader' "$(cat -- "${DMBO_ARGV}")"; then rc=1; fi
check '--smbios-reader false -> not forwarded, dangerous options not unlocked' "${rc}"

## --- --smbios-reader bogus: a non-boolean errors (exit 2) and never reaches the build spine ----
run_main --smbios-reader bogus
rc=0; [ "${MAIN_RC}" -eq 2 ] && [ "$(cat -- "${DMBO_ARGV}")" = "" ] || rc=1
check '--smbios-reader <non-boolean> -> exit 2, build spine not reached' "${rc}"

## --- the arm64 VirtualBox boot-test case: arch + multi-target + smbios-reader together ---------
run_main --flavor kicksecure-cli --arch arm64 --multi-target virtualbox --smbios-reader true
rc=0; [ "$(cat -- "${DMBO_ARCH}")" = "arm64" ] \
   && [ "$(cat -- "${DMBO_MULTI}")" = "virtualbox" ] \
   && has '--smbios-reader true' "$(cat -- "${DMBO_ARGV}")" \
   && [ "$(cat -- "${DMBO_UNLOCK}")" = "true" ] || rc=1
check 'arm64 + virtualbox + smbios-reader together -> arch/multi env + reader arg + unlock' "${rc}"

## --- CANARY: an inherited dist_build_smbios_reader=true must NOT survive when the flag is off ---
## dist_build_smbios_reader is on dm's env-keep list (95_env-vars-keep.bsh) and 10_misc.bsh only
## default_if_empty's it, so without an explicit export the caller's inherited `true` would cross
## into the build and bake the GRUB SMBIOS reader in -- with the dangerous-option gate SKIPPED,
## since the off path forwards no --smbios-reader arg for parse-cmd to gate on. dm-image-build must
## clobber the inherited value to the flag default (false). FAILS on code that only unlocks-on-true.
run_main_env dist_build_smbios_reader=true --
rc=0
[ "$(cat -- "${DMBO_SMBIOS}")" = "false" ] || rc=1
if has '--smbios-reader' "$(cat -- "${DMBO_ARGV}")"; then rc=1; fi
[ "$(cat -- "${DMBO_UNLOCK}")" != "true" ] || rc=1
check 'inherited dist_build_smbios_reader=true + flag OFF -> clobbered false, no arg, no unlock' "${rc}"

run_main_env dist_build_smbios_reader=true -- --smbios-reader false
rc=0
[ "$(cat -- "${DMBO_SMBIOS}")" = "false" ] || rc=1
if has '--smbios-reader' "$(cat -- "${DMBO_ARGV}")"; then rc=1; fi
[ "$(cat -- "${DMBO_UNLOCK}")" != "true" ] || rc=1
check 'inherited dist_build_smbios_reader=true + --smbios-reader false -> clobbered false' "${rc}"

## An inherited false must not block an explicit --smbios-reader true: the gate still runs via the
## forwarded arg, the reader is enabled, dangerous options unlocked.
run_main_env dist_build_smbios_reader=false -- --smbios-reader true
rc=0
[ "$(cat -- "${DMBO_SMBIOS}")" = "true" ] || rc=1
has '--smbios-reader true' "$(cat -- "${DMBO_ARGV}")" || rc=1
[ "$(cat -- "${DMBO_UNLOCK}")" = "true" ] || rc=1
check 'inherited dist_build_smbios_reader=false + --smbios-reader true -> true, arg forwarded, unlock' "${rc}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
