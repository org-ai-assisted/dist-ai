#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression for dm-image-build's `--dry-run true|false` passthrough to dm-build-official:
##   - default (no --dry-run)  -> dm-build-official is called WITHOUT --dry-run (a REAL image)
##   - --dry-run true          -> dm-build-official gets `--dry-run true` (dummy images, fast)
##   - --dry-run false         -> still no --dry-run forwarded (byte-identical to default)
##   - --dry-run bogus         -> rejected (exit 2), no build attempted
## It does NOT add --upload (upload stays SIMULATED by construction).
##
## Drives the REAL main() (sourced define-only) in a subshell. The build-spine steps
## (signing-key-create / sign-and-tag / dm-build-official) are recorder stubs in a fake checkout,
## and git/sudo/dpkg are stubbed as functions. No VM, no root, no git repo.
## CANARY: pre-change dm-image-build has no --dry-run flag, so `--dry-run true` errors as an
## unknown argument (exit 2) and the "forwarded" assertion FAILS.

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

## A fake checkout: a .git dir (so the checkout guard passes) + recorder build-spine stubs.
fakedir="${work}/dm"
mkdir -p -- "${fakedir}/.git" "${fakedir}/help-steps"
export DMBO_ARGV="${work}/dmbo.argv"
export DMBO_USER="${work}/dmbo.user"
printf '%s\n' '#!/bin/bash' 'exit 0' > "${fakedir}/help-steps/signing-key-create"
printf '%s\n' '#!/bin/bash' 'exit 0' > "${fakedir}/help-steps/sign-and-tag"
# shellcheck disable=SC2016  ## recorder body: ${DMBO_ARGV}/${DMBO_USER}/${user_name} expand when the STUB runs
printf '%s\n' '#!/bin/bash' 'printf "%s\n" "$*" > "${DMBO_ARGV}"' 'printf "%s" "${user_name:-UNSET}" > "${DMBO_USER}"' 'exit 0' > "${fakedir}/help-steps/dm-build-official"
chmod +x -- "${fakedir}/help-steps/"*

## Stub the host-poking commands main() runs in its cascade, so the test needs no git repo/root.
## Each stub returns 0 (the case/if falls through to a success), so an unguarded `git rev-parse`
## etc. in main() cannot trip the test shell's errexit.
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
has() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac }

## run_main ARGS... -> sets MAIN_RC, records dm-build-official argv in DMBO_ARGV (empty if the
## build spine was never reached). main() ends in `exit`, so run it in a subshell.
run_main() {
   true > "${DMBO_ARGV}"
   MAIN_RC=0
   ( main --dir "${fakedir}" "$@" ) >/dev/null 2>&1 || MAIN_RC=$?
}

## --- default: no --dry-run forwarded -------------------------------------------------------
run_main
argv="$(cat -- "${DMBO_ARGV}")"
rc=0; has '--target iso' "${argv}" && ! has '--dry-run' "${argv}" || rc=1
check 'default -> dm-build-official WITHOUT --dry-run (real image)' "${rc}"

## --- build user: user_name preset to the EFFECTIVE user (not logname) --------------------------
## CANARY: without the export, dm falls back to the `logname` command (the ssh login user when
## driven via server-exec --user), building into /home/<login-user> which the effective user cannot
## mkdir. dm-image-build presets user_name to id -un so the build tree is the effective user's.
run_main
rc=0; [ "$(cat -- "${DMBO_USER}")" = "$(id -un)" ] || rc=1
check 'user_name exported as the effective user (id -un), not logname' "${rc}"

## --- --dry-run true: forwarded ---------------------------------------------------------------
run_main --dry-run true
argv="$(cat -- "${DMBO_ARGV}")"
rc=0; has '--dry-run true' "${argv}" || rc=$?
check '--dry-run true -> dm-build-official --dry-run true' "${rc}"
## Never adds --upload (upload stays simulated by construction).
rc=0; if has '--upload' "${argv}"; then rc=1; fi
check 'no --upload is ever forwarded (upload simulated)' "${rc}"

## --- --dry-run false: byte-identical to default (no --dry-run forwarded) ----------------------
run_main --dry-run false
argv="$(cat -- "${DMBO_ARGV}")"
rc=0; if has '--dry-run' "${argv}"; then rc=1; fi
check '--dry-run false -> no --dry-run forwarded (same as default)' "${rc}"

## --- --dry-run bogus: rejected, no build -----------------------------------------------------
run_main --dry-run maybe
rc=0; [ "${MAIN_RC}" -eq 2 ] || rc=1
check '--dry-run bogus rejected (exit 2)' "${rc}"
rc=0; [ ! -s "${DMBO_ARGV}" ] || rc=1
check 'rejected --dry-run never reached the build spine' "${rc}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
