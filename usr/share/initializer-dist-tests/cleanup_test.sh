#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## initializer-dist chroot-scripts-post.d '80_cleanup': source-ability plus the
## pure decision functions.
##
## Drives the REAL script. It is source-able (was_executed guard, strict-mode
## confined to main()), so this test sources it and calls the functions that
## carry logic worth testing, each pointed at a tmpdir fixture:
##   - should_skip <name>            SKIP_SCRIPTS membership (exact token).
##   - check_debconf_passwords <f>   refuse (return 1) iff a stored answer is
##                                   present; otherwise delete the file.
##   - reset_debconf_grub_devices <f> emit 'RESET <name>' for each grub
##                                   install_devices question, nothing else.
##   - check_debconf_device_leak <f> refuse iff a build-host block device path
##                                   remains; /dev/null must not trip it.
## The file-path argument is the subject's own testability seam. debconf-communicate
## is PATH-shadowed by a mock that captures its stdin; safe-rm / grep / cut / sort /
## sed run for real from the helper-scripts checkout.
##
## A missing subject or check_runtime.bsh is a HARD FAIL (exit 1), never a skip.
## No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v INITIALIZER_DIST_REPO ] || INITIALIZER_DIST_REPO=""
[ -v HELPER_SCRIPTS_REPO ] || HELPER_SCRIPTS_REPO=""

if [ -n "${INITIALIZER_DIST_REPO}" ]; then
   subject="${INITIALIZER_DIST_REPO}/usr/libexec/initializer-dist/chroot-scripts-post.d/80_cleanup"
else
   subject='/usr/libexec/initializer-dist/chroot-scripts-post.d/80_cleanup'
fi
if [ -n "${HELPER_SCRIPTS_REPO}" ]; then
   real_hs_libdir="${HELPER_SCRIPTS_REPO}/usr/libexec/helper-scripts"
   real_hs_bindir="${HELPER_SCRIPTS_REPO}/usr/bin"
else
   real_hs_libdir='/usr/libexec/helper-scripts'
   real_hs_bindir='/usr/bin'
fi

if [ ! -r "${subject}" ]; then
   printf '%s\n' "FATAL: subject not readable at '${subject}'" >&2
   printf '%s\n' "set INITIALIZER_DIST_REPO to an initializer-dist checkout, or install initializer-dist" >&2
   exit 1
fi
if [ ! -r "${real_hs_libdir}/check_runtime.bsh" ]; then
   printf '%s\n' "FATAL: check_runtime.bsh not readable under '${real_hs_libdir}'" >&2
   printf '%s\n' "set HELPER_SCRIPTS_REPO to a helper-scripts checkout, or install helper-scripts" >&2
   exit 1
fi

test_dir="$(mktemp --directory)"
cleanup_handler() {
   safe-rm -r -f -- "${test_dir}"
}
trap cleanup_handler EXIT

## The subject resolves check_runtime.bsh (was_executed) via HELPER_SCRIPTS_PATH.
export HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_REPO:-}"

## --- PATH-shadow mock for debconf-communicate; real safe-rm from the checkout ---
mockbin="${test_dir}/bin"
mkdir --parents -- "${mockbin}"

## Records everything piped to it, so a case can assert the RESET commands the
## subject generated. DC_CAPTURE names the sink; default /dev/null.
cat > "${mockbin}/debconf-communicate" <<'EOF'
#!/bin/bash
cat -- - > "${DC_CAPTURE:-/dev/null}"
exit 0
EOF
chmod +x -- "${mockbin}/debconf-communicate"

export PATH="${mockbin}:${real_hs_bindir}:${PATH}"

## --------------------------------------------------------------------------
pass=0
fail=0
check() {
   local label got want
   label="$1"
   got="$2"
   want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${label}"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: ${label} (got '${got}', want '${want}')"
      fail=$((fail + 1))
   fi
}

## true if the path exists, else false -- as a word.
exists() {
   if [ -e "$1" ]; then printf 'yes'; else printf 'no'; fi
}

## Run a function with errexit disabled inside it (as main()'s bare calls do
## under the guarded strict block) and report ONLY its return code -- the
## function's own stdout/stderr (diagnostics on the refuse paths) is discarded
## so it cannot bleed into the captured value.
call_fn() {
   local rc=0
   "$@" >/dev/null 2>&1 || rc=$?
   printf '%s' "${rc}"
}

## ================= source-ability (BEFORE the in-process source) =================
## Run in an ISOLATED subprocess and MUST precede the in-process source below.
## They verify the subject is inert when sourced (no strict-mode leak, no
## auto-run). If it regressed to run at file scope, sourcing it into THIS shell
## would exit or delete host paths before any check -- so the in-process source
## is GATED on these passing. $0 is a placeholder, NOT the subject: was_executed
## compares BASH_SOURCE[0] to $0.
leak_rc=0
HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH}" bash -c 'source "$1"; false; true' placeholder "${subject}" >/dev/null 2>&1 \
   || leak_rc=$?
check "sourcing does not leak strict-mode" "${leak_rc}" "0"

src_out="$(HELPER_SCRIPTS_PATH="${HELPER_SCRIPTS_PATH}" bash -c 'source "$1"' placeholder "${subject}" 2>&1)" || true
check "sourcing does not auto-run" "${src_out}" ""

if [ "${leak_rc}" -ne 0 ] || [ -n "${src_out}" ]; then
   printf '%s\n' "FATAL: subject is not safe to source in-process (see checks above)" >&2
   exit 1
fi

# shellcheck disable=SC1090
source "${subject}"

## grep / cut / sort / sed / basename / safe-rm are hard deps of the subject and
## this test; they are called directly and fail loud if absent (no preflight).
check "should_skip is defined"                 "$(type -t should_skip)"                 "function"
check "check_debconf_passwords is defined"      "$(type -t check_debconf_passwords)"      "function"
check "reset_debconf_grub_devices is defined"   "$(type -t reset_debconf_grub_devices)"   "function"
check "check_debconf_device_leak is defined"    "$(type -t check_debconf_device_leak)"    "function"
check "clean_dhcp is defined"                   "$(type -t clean_dhcp)"                   "function"
check "clean_apt is defined"                    "$(type -t clean_apt)"                    "function"
check "clean_nondeterministic is defined"       "$(type -t clean_nondeterministic)"       "function"
check "clean_seeds_and_ids is defined"          "$(type -t clean_seeds_and_ids)"          "function"
check "clean_logs_and_history is defined"       "$(type -t clean_logs_and_history)"       "function"
check "main is defined"                         "$(type -t main)"                         "function"

## ============================== should_skip ==============================
check "should_skip: exact token in list -> 0" \
   "$(SKIP_SCRIPTS='40_first 80_cleanup 90_last' call_fn should_skip 80_cleanup)" "0"
check "should_skip: name absent -> 1" \
   "$(SKIP_SCRIPTS='40_first 90_last' call_fn should_skip 80_cleanup)" "1"
check "should_skip: empty list -> 1" \
   "$(SKIP_SCRIPTS='' call_fn should_skip 80_cleanup)" "1"
check "should_skip: unset list -> 1" \
   "$(unset SKIP_SCRIPTS; call_fn should_skip 80_cleanup)" "1"
## A longer name that merely CONTAINS the target is not a match (word, not substring).
check "should_skip: substring is not a match -> 1" \
   "$(SKIP_SCRIPTS='80_cleanup_extra' call_fn should_skip 80_cleanup)" "1"

## ===================== check_debconf_passwords =====================
## Stored answer present -> refuse (return 1) and KEEP the file.
pw="${test_dir}/pw_answer.dat"
printf '%s\n' 'Name: shim/secureboot_key' 'Value: hunter2' > "${pw}"
check "passwords: stored answer -> return 1" "$(call_fn check_debconf_passwords "${pw}")" "1"
check "passwords: refused file NOT deleted"  "$(exists "${pw}")" "yes"

## No stored answer (question ownership only) -> return 0 and DELETE the file.
pw="${test_dir}/pw_empty.dat"
printf '%s\n' 'Name: shim/secureboot_key' 'Owners: shim-signed' 'Flags: seen' > "${pw}"
check "passwords: no answer -> return 0"      "$(call_fn check_debconf_passwords "${pw}")" "0"
check "passwords: emptied file deleted"       "$(exists "${pw}")" "no"

## 'Value:' only counts at line start: a mid-line mention must not trip it.
pw="${test_dir}/pw_midline.dat"
printf '%s\n' 'Name: foo/bar' 'Description: the Value: field is empty' > "${pw}"
check "passwords: mid-line 'Value:' -> return 0" "$(call_fn check_debconf_passwords "${pw}")" "0"
check "passwords: mid-line file deleted"         "$(exists "${pw}")" "no"

## Missing file -> return 0, no error.
check "passwords: missing file -> return 0" \
   "$(call_fn check_debconf_passwords "${test_dir}/absent.dat")" "0"

## ===================== reset_debconf_grub_devices =====================
## Both grub install_devices variants present -> exactly those names RESET,
## sorted and unique; the non-grub answer is untouched.
cfg="${test_dir}/cfg_grub.dat"
printf '%s\n' \
   'Name: grub-pc/install_devices' \
   'Value: /dev/loop0' \
   'Name: grub-efi-amd64/install_devices_empty' \
   'Value: true' \
   'Name: keyboard-configuration/layout' \
   'Value: English' > "${cfg}"
cap="${test_dir}/reset_grub.cap"
DC_CAPTURE="${cap}" reset_debconf_grub_devices "${cfg}"
check "grub_reset: RESET both grub questions, sorted-unique" \
   "$(cat -- "${cap}")" \
   "$(printf '%s\n' 'RESET grub-efi-amd64/install_devices_empty' 'RESET grub-pc/install_devices')"

## No grub install_devices question -> nothing emitted.
cfg="${test_dir}/cfg_nogrub.dat"
printf '%s\n' 'Name: keyboard-configuration/layout' 'Value: English' > "${cfg}"
cap="${test_dir}/reset_none.cap"
DC_CAPTURE="${cap}" reset_debconf_grub_devices "${cfg}"
check "grub_reset: no grub question -> no output" "$(cat -- "${cap}")" ""

## ===================== check_debconf_device_leak =====================
## A leftover build-host loop device -> refuse.
cfg="${test_dir}/leak_loop.dat"
printf '%s\n' 'Name: grub-pc/install_devices' 'Template: grub-pc/install_devices' 'Value: /dev/loop0' > "${cfg}"
check "device_leak: /dev/loop0 remains -> return 1" \
   "$(call_fn check_debconf_device_leak "${cfg}")" "1"

## A clean config (no device path) -> pass.
cfg="${test_dir}/leak_clean.dat"
printf '%s\n' 'Name: keyboard-configuration/layout' 'Value: English' > "${cfg}"
check "device_leak: clean config -> return 0" \
   "$(call_fn check_debconf_device_leak "${cfg}")" "0"

## /dev/null is not a block device and must not trip the check.
cfg="${test_dir}/leak_devnull.dat"
printf '%s\n' 'Name: some/answer' 'Value: /dev/null' > "${cfg}"
check "device_leak: /dev/null -> return 0" \
   "$(call_fn check_debconf_device_leak "${cfg}")" "0"

## A real block-device class other than loop (nvme) -> refuse.
cfg="${test_dir}/leak_nvme.dat"
printf '%s\n' 'Name: grub-pc/install_devices' 'X: y' 'Value: /dev/nvme0n1' > "${cfg}"
check "device_leak: /dev/nvme0n1 remains -> return 1" \
   "$(call_fn check_debconf_device_leak "${cfg}")" "1"

## ================================ summary ================================
printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   printf '%s\n' "FAILED"
   exit 1
fi
printf '%s\n' "OK"
