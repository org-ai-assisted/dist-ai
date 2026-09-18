#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## 4350_reimage-raw-reproducible require-ext-type is the fail-closed guard before
## the partition is blkdiscard'd and rebuilt as ext4. It must:
##   - ACCEPT ext2/ext3/ext4 (the reimage only rebuilds ext);
##   - REJECT any other type (xfs/btrfs/...) so a build that requested another
##     filesystem is not SILENTLY reformatted to ext4;
##   - REJECT an EMPTY type -- blkid prints nothing and exits non-zero when it
##     cannot identify the filesystem; the caller's '|| true' turns that into ""
##     which must fail closed here, NOT be treated as ext.
##
## Extracted with dm-build-step-fn; no root, no blkid, no build.

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
step_file="${dm_checkout}/build-steps.d/4350_reimage-raw-reproducible"
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

## Exit 0 == accepted (ext), non-zero == refused. dm-build-step-fn --run
## propagates the function's own exit code.
verdict() {
   local file fs_type status
   file="$1"
   fs_type="$2"
   status=0
   "${tool}" --file "${file}" --fn require-ext-type --run "${fs_type}" \
      >/dev/null 2>&1 || status="$?"
   printf '%s\n' "${status}"
}

check_accept() {
   if [ "$( verdict "${step_file}" "$1" )" = "0" ]; then
      pass "accepts ext type '$1'"
   else
      fail "expected ext type '$1' accepted, was refused"
   fi
}
check_reject() {
   if [ "$( verdict "${step_file}" "$1" )" != "0" ]; then
      pass "refuses non-ext type '$1'"
   else
      fail "expected non-ext type '$1' refused, was accepted"
   fi
}

## --- accepted: the ext family ----------------------------------------------
check_accept ext2
check_accept ext3
check_accept ext4

## --- refused: other, near-miss, and empty ----------------------------------
check_reject xfs
check_reject btrfs
check_reject vfat
check_reject ext4dev
check_reject ''

## --- CANARY: the guard can actually reject ---------------------------------
## A form that treated any non-empty type as ext would wrongly accept xfs; the
## '' case proves the blkid-failure path (|| true -> empty) fails closed.
buggy="${work_dir}/9994_buggy"
cat > "${buggy}" <<'BUGGY'
#!/bin/bash
require-ext-type() {
   [ -n "$1" ]
}
BUGGY
if [ "$( verdict "${buggy}" xfs )" = "0" ] && [ "$( verdict "${buggy}" '' )" != "0" ]; then
   pass 'canary: a non-empty-only guard would accept xfs (the real guard does not)'
else
   fail 'canary broken: the non-empty-only buggy guard did not behave as expected'
fi

summary_line="===== require-ext-type: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
