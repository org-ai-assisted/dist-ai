#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## shim-manage-mok is the interactive MOK enroll/reset tool. Drives the REAL
## source-able script (the `sourceable` skill): sourcing defines parse_cmdline /
## shim_enroll_mok (and the shim-signed / log / has helpers) WITHOUT running main,
## so neither the EXIT trap nor the root/dep checks fire at source time.
##
## Covered: (1) parse_cmdline maps --enroll/--reset/-n|--non-interactive to the
## mode globals, and an unknown option exits nonzero; (2) shim_enroll_mok's
## CONFUSING mokutil --test-key convention -- nonzero exit + '<pubfile> is already
## enrolled' means ENROLLED (early success, rc 0); nonzero + any other message
## means COULD-NOT-DETECT (rc 1). Asserted on rc, not just the message.
##
## A missing subject/dep is an ENVIRONMENT BUG -> exit 1 (FATAL), never a skip.

## dkms_mok_dir (set here) and dkms_mok_public_file (assigned by the sourced
## dkms_mok_variables_set) cross a boundary shellcheck does not follow -- so its
## unused (SC2034) and unassigned (SC2154) warnings are false here.
# shellcheck disable=SC2034,SC2154
set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   subject="${HELPER_SCRIPTS_REPO}/usr/sbin/shim-manage-mok"
   export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO}"
else
   subject='/usr/sbin/shim-manage-mok'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi

## Drift-guard: the enrolled-detection string and the two user-facing verdicts.
for sentinel in \
   ' is already enrolled' \
   'MOK already enrolled. Exiting, ok.' \
   'Cannot detect MOK enrollment state! Exiting.'; do
   if ! grep --quiet --fixed-strings -- "${sentinel}" "${subject}"; then
      printf '%s\n' "FATAL: sentinel '${sentinel}' not found in '${subject}'; it drifted -- update this test." >&2
      exit 1
   fi
done

# shellcheck disable=SC1090,SC1091
source "${subject}"
for fn in parse_cmdline shim_enroll_mok dkms_mok_variables_set; do
   if [ "$(type -t "${fn}")" != 'function' ]; then
      printf '%s\n' "FATAL: sourcing '${subject}' defined no '${fn}' function" >&2
      exit 1
   fi
done
if ! has safe-rm; then
   printf '%s\n' "FATAL: safe-rm not on PATH" >&2
   exit 1
fi
## Not root in the test: the root check is stubbed to a no-op.
as_root() { :; }

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

dkms_base="${work}/dkms"
bindir="${work}/bin"
mkdir --parents -- "${bindir}" "${dkms_base}"

## mokutil stub: 'mokutil --test-key <pubfile>' is $1=--test-key $2=<pubfile>.
## The real script treats a NONZERO exit as "key enrolled" and then matches the
## exact message. MOKUTIL_MODE forces which nonzero branch.
cat > "${bindir}/mokutil" <<'STUB'
#!/bin/bash
case "${MOKUTIL_MODE:-}" in
   enrolled)     printf '%s is already enrolled\n' "$2"; exit 1 ;;
   cannotdetect) printf '%s\n' 'EFI variables are not supported on this system'; exit 1 ;;
   *)            exit 0 ;;
esac
STUB
chmod +x -- "${bindir}/mokutil"
export PATH="${bindir}:${PATH}"

## Point the dkms base at the temp tree and derive dkms_mok_public_file (read by
## shim_enroll_mok) through the REAL dkms_mok_variables_set.
dkms_mok_dir="${dkms_base}"
dkms_mok_variables_set
touch -- "${dkms_mok_public_file}"

pass=0
fail=0
check() {
   local label="$1" got="$2" want="$3"
   if [ "${got}" = "${want}" ]; then
      pass=$(( pass + 1 ))
      printf '%s\n' "PASS: ${label}"
   else
      fail=$(( fail + 1 ))
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
   fi
}
contains() {
   case "$1" in
      *"$2"*)
         printf 'yes'
         ;;
      *)
         printf 'no'
         ;;
   esac
}

## --- (1) parse_cmdline maps flags to the mode globals -----------------------
manage_mode='none'; non_interactive='false'
parse_cmdline --enroll
check "parse_cmdline --enroll -> manage_mode=enroll" "${manage_mode}" "enroll"

manage_mode='none'; non_interactive='false'
parse_cmdline --reset
check "parse_cmdline --reset -> manage_mode=reset" "${manage_mode}" "reset"

manage_mode='none'; non_interactive='false'
parse_cmdline -n
check "parse_cmdline -n -> non_interactive=true" "${non_interactive}" "true"

manage_mode='none'; non_interactive='false'
parse_cmdline --non-interactive
check "parse_cmdline --non-interactive -> non_interactive=true" "${non_interactive}" "true"

manage_mode='none'; non_interactive='false'
parse_cmdline --reset -n
check "parse_cmdline --reset -n -> mode=reset"          "${manage_mode}"     "reset"
check "parse_cmdline --reset -n -> non_interactive=true" "${non_interactive}" "true"

## unknown option exits nonzero (subshell: parse_cmdline calls 'exit').
unknown_rc=0
( parse_cmdline --bogus-option ) >/dev/null 2>&1 || unknown_rc=$?
check "parse_cmdline unknown option -> nonzero exit" "$([ "${unknown_rc}" -ne 0 ] && printf nonzero || printf zero)" "nonzero"

## --- (2) mokutil --test-key enrolled-detection (the confusing rc convention) -
run_enroll() {
   local rc=0 out
   out="$(shim_enroll_mok 2>&1)" || rc=$?
   printf '%s\n%s' "${rc}" "${out}"
}

export MOKUTIL_MODE='enrolled'
res="$(run_enroll)"
rc="${res%%$'\n'*}"
out="${res#*$'\n'}"
check "enrolled (rc1 + 'is already enrolled') -> shim_enroll_mok rc 0" "${rc}" "0"
check "enrolled -> 'MOK already enrolled. Exiting, ok.'" "$(contains "${out}" 'MOK already enrolled. Exiting, ok.')" "yes"

## CANARY: the SAME nonzero mokutil exit with a DIFFERENT message must NOT be read
## as enrolled -- it is cannot-detect -> rc 1. So flipping only the message flips
## the verdict, proving the exact-string compare (not merely 'mokutil failed') and
## the rc are load-bearing.
export MOKUTIL_MODE='cannotdetect'
res="$(run_enroll)"
rc="${res%%$'\n'*}"
out="${res#*$'\n'}"
check "canary: cannot-detect (rc1 + other message) -> shim_enroll_mok rc 1" "${rc}" "1"
check "canary: cannot-detect -> 'Cannot detect MOK enrollment state! Exiting.'" "$(contains "${out}" 'Cannot detect MOK enrollment state! Exiting.')" "yes"

printf '%s\n' ""
printf '%s\n' "===== shim_manage_mok: ${pass} pass, ${fail} fail, 0 skip ====="
[ "${fail}" -eq 0 ]
