#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Canary: each REAL VM entry point self-locks by re-execing under dm-vm-lock with the CORRECT
## class, so the mutex cannot be bypassed. A stub dm-vm-lock records the class and does NOT run
## the leaf's VM work. Removing a guard, or using the wrong class, FAILS here. Drives the real
## scripts (dist-ai convention: no synthetic copies).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
# shellcheck source=./lib.bash
source "${test_dir}/lib.bash"   ## for check() + vmlock_done(); TOOL itself is not exercised here

bin="$(cd -- "${test_dir}/../../bin" && pwd)"
work="$(mktemp --directory --tmpdir dm-vm-lock-wiring.XXXXXX)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## A dm-vm-lock stub that records the args the leaf passed and exits WITHOUT running the leaf's
## VM work (so no VBox/build is touched). The guard `exec dm-vm-lock ...` replaces the leaf, so
## the stub's exit ends the run.
stubbin="${work}/bin"
mkdir --parents -- "${stubbin}"
rec="${work}/calls"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' "printf '%s\\n' \"\$*\" > '${rec}'"
   printf '%s\n' 'exit 0'
} > "${stubbin}/dm-vm-lock"
chmod +x -- "${stubbin}/dm-vm-lock"
export PATH="${stubbin}:${PATH}"

ppfile="${work}/pp"; printf 'x\n' > "${ppfile}"
## image-test-run locks AFTER its config-readability check, so give it a readable (empty) config
## -- the guard re-execs before the config is sourced, so its contents do not matter here.
conf="${work}/dummy.conf"; printf '' > "${conf}"

assert_class() {
   ## assert_class <label> <expected-class> <leaf-path> <args...>
   local label="$1" want="$2" leaf="$3"; shift 3
   if [ ! -x "${leaf}" ]; then
      check "${label}: leaf present at ${leaf}" 1
      return
   fi
   printf '' > "${rec}"
   DM_VM_LOCK_HELD='' "${leaf}" "$@" >/dev/null 2>&1 || true
   local got; got="$(cat -- "${rec}" 2>/dev/null || true)"
   case "${got}" in
      "acquire --class ${want} "*)
         r=0
         ;;
      *)
         r=1
         ;;
   esac
   check "${label} self-locks via dm-vm-lock (--class ${want})" "${r}"
}

assert_class 'dm-whonix-pair (leak test)'     leak "${bin}/dm-whonix-pair"     --gw GW --ws WS
assert_class 'dm-calamares-install (VBox)'    work "${bin}/dm-calamares-install" --vm V --iso /nonexistent.iso --passphrase-file "${ppfile}"
assert_class 'image-test-run (VBox image)'    work "${bin}/image-test-run"     "${conf}"
assert_class 'dm-iso-build (image build)'     work "${bin}/dm-iso-build"

vmlock_done
