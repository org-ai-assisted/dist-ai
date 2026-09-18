#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## 3500_install-packages has two selectors whose wrong answer produces a broken
## or non-reproducible image, so each is worth pinning:
##   - newest-kernel-version: picks the kernel dracut rebuilds the initramfs for.
##     A byte-order pick ('sed -n 1p') takes 'vmlinuz-6.1.0-9' over
##     'vmlinuz-6.12.0-1' ('.' < digit under LC_ALL=C), i.e. the OLD kernel, so
##     the initramfs no longer matches the kernel grub boots.
##   - select-grub-probe-device: picks the device whose UUID replaces
##     root=/dev/mapper. Choosing an EMPTY '/boot' probe result (a transient
##     failure) over a valid root probe aborts an otherwise-good build.
##
## Both are extracted with dm-build-step-fn; no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DIST_AI_DIR:-}" ]; then
   dist_ai_dir="${DIST_AI_DIR}"
else
   dist_ai_dir="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/../../.." && pwd )"
fi
tool="${dist_ai_dir}/usr/bin/dm-build-step-fn"
if [ ! -x "${tool}" ]; then
   tool="$( type -P dm-build-step-fn || true )"
fi
if [ -z "${tool}" ] || [ ! -x "${tool}" ]; then
   printf '%s\n' "FAIL: dm-build-step-fn not found or not executable" >&2
   exit 1
fi

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi
step_file="${dm_checkout}/build-steps.d/3500_install-packages"
if [ ! -r "${step_file}" ]; then
   printf '%s\n' "FAIL: cannot read ${step_file}" >&2
   exit 1
fi

pass_count=0
fail_count=0
pass() {
   pass_count=$(( pass_count + 1 ))
   printf '%s\n' "PASS: $*"
}
fail() {
   fail_count=$(( fail_count + 1 ))
   printf '%s\n' "FAIL: $*" >&2
}

work_dir="$( mktemp --directory )"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   safe-rm --recursive --force -- "${work_dir}"
}
trap cleanup EXIT

## A /boot listing in ls -1 (LC_ALL=C) order: the OLD kernel sorts first by byte,
## so a byte-first pick would take it; version-sort must take the newer one.
boot_listing="$( printf '%s\n' \
   'System.map-6.1.0-9-amd64' \
   'config-6.1.0-9-amd64' \
   'initrd.img-6.1.0-9-amd64' \
   'vmlinuz-6.1.0-9-amd64' \
   'vmlinuz-6.12.0-1-amd64' )"

run_fn() {
   ## $1 = function, rest = args
   local fn
   fn="$1"
   shift
   "${tool}" --file "${step_file}" --fn "${fn}" --run "$@" 2>/dev/null
}

## --- newest-kernel-version -------------------------------------------------
out="$( run_fn newest-kernel-version "${boot_listing}" || true )"
if [ "${out}" = "6.12.0-1-amd64" ]; then
   pass 'newest-kernel-version picks the newest kernel by version, not byte order'
else
   fail "newest-kernel-version: expected '6.12.0-1-amd64', got '${out}'"
fi

out="$( run_fn newest-kernel-version "$( printf 'vmlinuz-6.1.0-9-amd64\n' )" || true )"
if [ "${out}" = "6.1.0-9-amd64" ]; then
   pass 'newest-kernel-version returns the sole kernel and strips vmlinuz-'
else
   fail "newest-kernel-version single: expected '6.1.0-9-amd64', got '${out}'"
fi

out="$( run_fn newest-kernel-version "$( printf 'config-x\ninitrd.img-x\n' )" || true )"
if [ -z "${out}" ]; then
   pass 'newest-kernel-version is empty when there is no vmlinuz'
else
   fail "newest-kernel-version no-kernel: expected empty, got '${out}'"
fi

## --- select-grub-probe-device ----------------------------------------------
out="$( run_fn select-grub-probe-device /dev/mapper/loop0p2 /dev/mapper/loop0p2 || true )"
if [ "${out}" = "/dev/mapper/loop0p2" ]; then
   pass 'select-grub-probe-device: equal probes return that device'
else
   fail "select equal: expected '/dev/mapper/loop0p2', got '${out}'"
fi

out="$( run_fn select-grub-probe-device /dev/mapper/loop0p2 /dev/mapper/loop0p3 || true )"
if [ "${out}" = "/dev/mapper/loop0p3" ]; then
   pass 'select-grub-probe-device: differing probes prefer a non-empty /boot'
else
   fail "select differ: expected '/dev/mapper/loop0p3', got '${out}'"
fi

out="$( run_fn select-grub-probe-device /dev/mapper/loop0p2 '' || true )"
if [ "${out}" = "/dev/mapper/loop0p2" ]; then
   pass 'select-grub-probe-device: an empty /boot probe falls back to the root probe'
else
   fail "select empty-boot: expected '/dev/mapper/loop0p2', got '${out}'"
fi

## --- CANARY: the buggy forms are actually caught ---------------------------
## Byte-first kernel pick returns the OLD kernel; always-/boot device pick
## returns empty when the /boot probe failed.
buggy="${work_dir}/9995_buggy"
cat > "${buggy}" <<'BUGGY'
#!/bin/bash
newest-kernel-version() {
   printf '%s\n' "$1" | grep 'vmlinuz' | sed -n '1p' | sed 's/^vmlinuz-//'
}
select-grub-probe-device() {
   if [ "$1" = "$2" ]; then
      printf '%s\n' "$1"
   else
      printf '%s\n' "$2"
   fi
}
BUGGY
buggy_kernel="$( "${tool}" --file "${buggy}" --fn newest-kernel-version --run "${boot_listing}" 2>/dev/null || true )"
buggy_device="$( "${tool}" --file "${buggy}" --fn select-grub-probe-device --run /dev/mapper/loop0p2 '' 2>/dev/null || true )"
if [ "${buggy_kernel}" = "6.1.0-9-amd64" ] && [ -z "${buggy_device}" ]; then
   pass 'canary: byte-first kernel pick and always-/boot device pick are caught'
else
   fail "canary broken: buggy kernel='${buggy_kernel}' device='${buggy_device}'"
fi

summary_line="===== install-packages selectors: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
