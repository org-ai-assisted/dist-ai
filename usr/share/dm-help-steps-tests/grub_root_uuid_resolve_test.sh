#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## 3500_install-packages resolve-partition-uuid must match the partition NAME as
## a LITERAL whole field, never as a regex or a substring.
##
## WHY THIS IS WORTH TESTING: the UUID it returns is written into the image's
## grub.cfg 'root='. A wrong UUID does not look like a failure -- it produces a
## grub.cfg that fails to boot. The two ways the lookup can pick the wrong
## partition each get a case here, written to FAIL against the buggy forms:
##   - a REGEX match: a grub-probe name like 'a.c' whose '.' matches 'abc'
##     (this is the form the current file regressed to: 'grep -- "^NAME "').
##   - a SUBSTRING match: 'loop0p1' also matching 'loop0p10'
##     (the form before the anchor was added: 'grep --fixed-strings').
##
## Needs no root, no network, no build: the function is extracted with
## dm-build-step-fn and 'lsblk' is stubbed on PATH.

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

## Stub lsblk: ignore all args, emit a fixed NAME,UUID table. 'loop0p10' is
## listed BEFORE 'loop0p1' so a substring match ('grep --fixed-strings loop0p1'
## + head) would take the loop0p10 row first and return the wrong UUID.
stub_dir="${work_dir}/bin"
mkdir --parents -- "${stub_dir}"
cat > "${stub_dir}/lsblk" <<'LSBLK'
#!/bin/bash
printf '%s\n' \
   'loop0p10 UUID-TEN' \
   'loop0p1 UUID-ONE' \
   'loop0p2 UUID-TWO' \
   'abc UUID-ABC'
LSBLK
chmod +x -- "${stub_dir}/lsblk"

## Call resolve-partition-uuid <name> with the stub on PATH.
resolve() {
   PATH="${stub_dir}:${PATH}" "${tool}" --file "$1" --fn resolve-partition-uuid --run "$2" 2>/dev/null
}

## --- 1. exact match returns that partition's UUID ---------------------------
output="$( resolve "${step_file}" abc || true )"
if [ "${output}" = "UUID-ABC" ]; then
   pass 'exact name returns its UUID'
else
   fail "exact match: expected 'UUID-ABC', got '${output}'"
fi

## --- 2. a substring is NOT a match -----------------------------------------
## 'loop0p1' must return UUID-ONE, never UUID-TEN, even though 'loop0p1' is a
## substring of 'loop0p10' and 'loop0p10' is listed first.
output="$( resolve "${step_file}" loop0p1 || true )"
if [ "${output}" = "UUID-ONE" ]; then
   pass 'a substring of a longer name does not match the longer name'
else
   fail "substring safety: expected 'UUID-ONE', got '${output}'"
fi

## --- 3. a regex metacharacter is NOT interpreted ---------------------------
## 'a.c' has no exact row, so the result must be empty. A regex match would let
## '.' match 'abc' and wrongly return UUID-ABC.
output="$( resolve "${step_file}" 'a.c' || true )"
if [ -z "${output}" ]; then
   pass 'a regex metacharacter in the name is not interpreted (no false match)'
else
   fail "regex safety: expected empty, got '${output}'"
fi

## --- 4. an absent name returns nothing -------------------------------------
output="$( resolve "${step_file}" no-such-partition || true )"
if [ -z "${output}" ]; then
   pass 'an absent name returns nothing'
else
   fail "absent name: expected empty, got '${output}'"
fi

## --- 5. CANARY: the assertions have teeth against the buggy form ------------
## Build a fixture whose resolve-partition-uuid uses the regressed regex grep,
## and confirm cases 2 and 3 WOULD fail against it. Without this, a lookup that
## silently reverted to regex/substring could pass everything above.
buggy="${work_dir}/9998_buggy"
cat > "${buggy}" <<'BUGGY'
#!/bin/bash
resolve-partition-uuid() {
   local partition_name
   partition_name="$1"
   lsblk --raw --noheadings --output NAME,UUID \
      | grep -- "^${partition_name} " \
      | head -n1 \
      | cut -d' ' -f2
}
BUGGY
## Note: the buggy form is anchored ('^NAME '), so it survives the substring
## case; the regex case is what exposes it.
buggy_substr="$( resolve "${buggy}" loop0p1 || true )"
buggy_regex="$( resolve "${buggy}" 'a.c' || true )"
if [ "${buggy_regex}" = "UUID-ABC" ] && [ "${buggy_substr}" = "UUID-ONE" ]; then
   pass 'canary: the regex-buggy form is caught by case 3 (and only case 3)'
else
   fail "canary broken: buggy form gave substr='${buggy_substr}' regex='${buggy_regex}'"
fi

summary_line="===== resolve-partition-uuid: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
