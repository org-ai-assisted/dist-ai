#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## resolve-partition-uuid (help-steps/build-step-helpers.bsh, used by
## 3500_install-packages) must match the partition NAME as a LITERAL whole field,
## never as a regex or a substring: the UUID it returns is written into the
## image's grub.cfg 'root='. A wrong UUID does not look like a failure -- it
## produces a grub.cfg that fails to boot.
##
## The real function is SOURCED from the shared helper library (no dm-build-step-fn
## extraction, no duplicate definition) with 'lsblk' stubbed on PATH; the canaries
## redefine it with the buggy forms in a subshell. Needs no root, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi
lib="${dm_checkout}/help-steps/build-step-helpers.bsh"
if [ ! -r "${lib}" ]; then
   printf '%s\n' "FAIL: cannot read ${lib}" >&2
   exit 1
fi
# shellcheck disable=SC1090
source "${lib}"

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
## listed BEFORE 'loop0p1' so a substring match would take the loop0p10 row first
## and return the wrong UUID. 'a\b' carries a literal backslash for the escape
## case.
stub_dir="${work_dir}/bin"
mkdir --parents -- "${stub_dir}"
cat > "${stub_dir}/lsblk" <<'LSBLK'
#!/bin/bash
printf '%s\n' \
   'loop0p10 UUID-TEN' \
   'loop0p1 UUID-ONE' \
   'loop0p2 UUID-TWO' \
   'abc UUID-ABC' \
   'a\b UUID-BS'
LSBLK
chmod +x -- "${stub_dir}/lsblk"
export PATH="${stub_dir}:${PATH}"

## --- 1. exact match returns that partition's UUID --------------------------
if [ "$( resolve-partition-uuid abc )" = "UUID-ABC" ]; then
   pass 'exact name returns its UUID'
else
   fail "exact match: expected 'UUID-ABC'"
fi

## --- 2. a substring is NOT a match -----------------------------------------
if [ "$( resolve-partition-uuid loop0p1 )" = "UUID-ONE" ]; then
   pass 'a substring of a longer name does not match the longer name'
else
   fail "substring safety: expected 'UUID-ONE'"
fi

## --- 3. a regex metacharacter is NOT interpreted ---------------------------
if [ -z "$( resolve-partition-uuid 'a.c' )" ]; then
   pass 'a regex metacharacter in the name is not interpreted (no false match)'
else
   fail 'regex safety: expected empty'
fi

## --- 3b. a backslash in the name is matched LITERALLY ----------------------
if [ "$( resolve-partition-uuid 'a\b' )" = "UUID-BS" ]; then
   pass 'a backslash escape in the name is not interpreted (literal match)'
else
   fail "escape safety: expected 'UUID-BS'"
fi

## --- 4. an absent name returns nothing -------------------------------------
if [ -z "$( resolve-partition-uuid no-such-partition )" ]; then
   pass 'an absent name returns nothing'
else
   fail 'absent name: expected empty'
fi

## --- 5. CANARY: the buggy forms are actually caught ------------------------
## Redefine the function with the two historical bugs in a subshell (the real one
## is untouched) and confirm each is caught by the case that targets it.
regex_hit="$(
   resolve-partition-uuid() {
      lsblk --raw --noheadings --output NAME,UUID | grep -- "^$1 " | head --lines=1 | cut -d' ' -f2
   }
   resolve-partition-uuid 'a.c'
)"
substr_hit="$(
   resolve-partition-uuid() {
      lsblk --raw --noheadings --output NAME,UUID | grep --fixed-strings -- "$1" | head --lines=1 | cut -d' ' -f2
   }
   resolve-partition-uuid loop0p1
)"
if [ "${regex_hit}" = "UUID-ABC" ] && [ "${substr_hit}" = "UUID-TEN" ]; then
   pass 'canary: the regex form (case 3) and the substring form (case 2) are caught'
else
   fail "canary broken: regex='${regex_hit}' substr='${substr_hit}'"
fi

summary_line="===== resolve-partition-uuid: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
