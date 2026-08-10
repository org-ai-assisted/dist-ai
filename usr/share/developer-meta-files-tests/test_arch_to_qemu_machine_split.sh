#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guards the arch->qemu helper SPLIT:
##   * developer-meta-files' arch-to-qemu-machine.bsh keeps ONLY the build-time
##     machine-name map (dist_build_arch_to_qemu_machine), sourced by
##     help-steps/variables. The boot-test-only board TYPE and serial-console
##     maps must NOT live here -- they are dead weight in the build.
##   * dist-ai's dm-image-boot-tests bundles its own copy of the fragment WITH
##     all three functions, because only its dm-qemu consumes the extra two.
## A regression either way (re-adding the two to the build copy, or dropping any
## of the three from the boot-test copy) breaks the intent, so assert both.
##
## Self-contained (sources only the fragment, which is side-effect-free by
## contract); detects nothing external, so no has()/command -v needed.
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

pass_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   test_failures=$((test_failures + 1))
   printf '%s\n' "FAIL: $*" >&2
}

## The build copy in developer-meta-files. Prefixed candidates are only added
## when their prefix var is set (an unset prefix collapses to '/usr/...' and
## would short-circuit to the installed copy before the checkout is tried).
build_rel='usr/libexec/developer-meta-files/arch-to-qemu-machine.bsh'
build_candidates=()
[ -z "${DEVELOPER_META_FILES_DIR:-}" ] || build_candidates+=( "${DEVELOPER_META_FILES_DIR}/${build_rel}" )
build_candidates+=( "${dm_checkout}/packages/kicksecure/developer-meta-files/${build_rel}" )
build_candidates+=( "/${build_rel}" )
build_copy=""
for candidate in "${build_candidates[@]}"; do
   if [ -r "${candidate}" ]; then
      build_copy="${candidate}"
      break
   fi
done
if [ -z "${build_copy}" ]; then
   printf '%s\n' "SKIP: developer-meta-files arch-to-qemu-machine.bsh not found (set DEVELOPER_META_FILES_DIR)." >&2
   exit 77
fi

## The boot-test copy bundled in dist-ai, beside this test's share tree.
boot_copy=""
for candidate in \
   "${script_dir}/../dm-image-boot-tests/arch-to-qemu-machine.bsh" \
   "/usr/share/dm-image-boot-tests/arch-to-qemu-machine.bsh"; do
   if [ -r "${candidate}" ]; then
      boot_copy="${candidate}"
      break
   fi
done

defines() {
   ## A top-level function definition 'name() {' in the fragment.
   grep --quiet --extended-regexp -- "^${2}\\(\\) \\{" "$1"
}

base_fn='dist_build_arch_to_qemu_machine'
type_fn='dist_build_arch_to_qemu_machine_type'
console_fn='dist_build_arch_to_serial_console'

## --- build copy: base only -------------------------------------------------
if defines "${build_copy}" "${base_fn}"; then
   pass "build copy defines the base map ${base_fn}()"
else
   fail "build copy is missing ${base_fn}(); help-steps/variables sources this for the build"
fi
if defines "${build_copy}" "${type_fn}"; then
   fail "build copy still defines ${type_fn}() -- boot-test-only, must live in dist-ai"
else
   pass "build copy does not define the boot-test-only ${type_fn}()"
fi
if defines "${build_copy}" "${console_fn}"; then
   fail "build copy still defines ${console_fn}() -- boot-test-only, must live in dist-ai"
else
   pass "build copy does not define the boot-test-only ${console_fn}()"
fi

## --- behavioural: the base map still resolves correctly --------------------
## The fragment is side-effect-free by contract, so sourcing it in a subshell and
## calling the function is safe.
check_base() {
   local arch want got
   arch="$1"; want="$2"
   got="$(
      # shellcheck disable=SC1090 # path resolved at runtime
      source "${build_copy}"
      "${base_fn}" "${arch}"
   )"
   if [ "${got}" = "${want}" ]; then
      pass "base map: ${arch} -> ${got}"
   else
      fail "base map: ${arch} -> '${got}', wanted '${want}'"
   fi
}
check_base amd64 x86_64
check_base arm64 aarch64
check_base ppc64el ppc64le
check_base s390x s390x
## An unmapped architecture must signal non-zero.
unmapped_rc=0
(
   # shellcheck disable=SC1090 # path resolved at runtime
   source "${build_copy}"
   "${base_fn}" no-such-arch
) >/dev/null 2>&1 || unmapped_rc="$?"
if [ "${unmapped_rc}" -ne 0 ]; then
   pass "base map: an unmapped architecture returns non-zero (${unmapped_rc})"
else
   fail "base map: an unmapped architecture returned 0"
fi

## --- boot-test copy: all three ---------------------------------------------
if [ -z "${boot_copy}" ]; then
   fail "dist-ai boot-test copy arch-to-qemu-machine.bsh not found; dm-qemu depends on it"
else
   for fn in "${base_fn}" "${type_fn}" "${console_fn}"; do
      if defines "${boot_copy}" "${fn}"; then
         pass "boot-test copy defines ${fn}()"
      else
         fail "boot-test copy is missing ${fn}(); dm-qemu sources all three"
      fi
   done
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s) (${pass_count} passed)." >&2
   exit 1
fi
printf '%s\n' "OK: arch-to-qemu-machine split (${pass_count} assertions)."
