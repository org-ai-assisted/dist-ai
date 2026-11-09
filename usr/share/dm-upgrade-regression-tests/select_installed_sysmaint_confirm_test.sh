#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Assert select_installed_sysmaint (grub-boot-select.bsh) never presses Enter unless the
## "Choose boot mode" menu is CONFIRMED still on screen. The bug: on a slow/late BIOS OCR
## the old body fired Down+Enter blindly on the first match; if the menu had already
## autobooted, that Enter landed on the dracut LUKS prompt as an EMPTY passphrase and
## wedged the unlock. No VM, no network: gui_ocr's screenshot+tesseract are stubbed so the
## on-screen text is scripted per call, and the scancodes sent are logged and asserted.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
share_dir="${script_dir}/../dm-smbios-reader-boot-tests"
for lib in gui-drive.bsh grub-boot-select.bsh; do
   [ -r "${share_dir}/${lib}" ] || { printf '%s\n' "ERROR: not found: ${share_dir}/${lib}" >&2; exit 1; }
done

tmp="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap, not a direct call
cleanup() {
   safe-rm --recursive --force -- "${tmp}"
}
trap cleanup EXIT

## Scripted-OCR + scancode-log wiring the stubs read from the environment.
export SCANCODE_LOG="${tmp}/scancodes.log"
export OCR_COUNTER_FILE="${tmp}/ocr.counter"
export OCR_RESPONSES_DIR="${tmp}/ocr"
mkdir -- "${OCR_RESPONSES_DIR}"

## VBOXMANAGE stub: log only the scancodes of `controlvm <vm> keyboardputscancode <codes>`
## (one line per gui_scan call); succeed silently for anything else.
vboxmanage="${tmp}/vboxmanage"
cat > "${vboxmanage}" <<'STUB'
#!/bin/bash
if [ "${1:-}" = 'controlvm' ] && [ "${3:-}" = 'keyboardputscancode' ]; then
   shift 3
   printf '%s\n' "$*" >> "${SCANCODE_LOG}"
fi
exit 0
STUB

## GUESTCTL stub: `<vm> shot <file>` just succeeds (gui_ocr then runs tesseract on it).
guestctl="${tmp}/guestctl"
cat > "${guestctl}" <<'STUB'
#!/bin/bash
exit 0
STUB

## TESSERACT stub: return the Nth scripted OCR frame (counter-driven), falling back to
## default.txt once the scripted frames run out -- so a confirm loop keeps seeing the same
## post-autoboot screen.
tesseract="${tmp}/tesseract"
cat > "${tesseract}" <<'STUB'
#!/bin/bash
n="$(cat -- "${OCR_COUNTER_FILE}" 2>/dev/null || printf '0')"
n=$(( n + 1 ))
printf '%s' "${n}" > "${OCR_COUNTER_FILE}"
resp="${OCR_RESPONSES_DIR}/${n}.txt"
if [ -r "${resp}" ]; then
   cat -- "${resp}"
else
   cat -- "${OCR_RESPONSES_DIR}/default.txt" 2>/dev/null || true
fi
STUB
chmod +x "${vboxmanage}" "${guestctl}" "${tesseract}"

## Caller globals the sourced fragments consume (gui-drive.bsh).
# shellcheck disable=SC2034
vm='testvm'
# shellcheck disable=SC2034
VBOXMANAGE="${vboxmanage}"
# shellcheck disable=SC2034
GUESTCTL="${guestctl}"
# shellcheck disable=SC2034
TESSERACT="${tesseract}"
# shellcheck disable=SC2034
me='select_confirm_test'
# shellcheck disable=SC2034  ## consumed by grub-boot-select.bsh's die()
FAIL_RC=5
## Fast timeouts so the safe-fail path does not stall the unit test (production defaults 60/10).
export GRUB_SELECT_TIMEOUT_S=3
export GRUB_SELECT_CONFIRM_S=1

## The caller-provided die: prints to stderr and EXITs (mirrors the real tool's die).
die() {
   printf '%s\n' "${2:-}" >&2
   exit "$1"
}

# shellcheck source=../dm-smbios-reader-boot-tests/gui-drive.bsh
source "${share_dir}/gui-drive.bsh"
# shellcheck source=../dm-smbios-reader-boot-tests/grub-boot-select.bsh
source "${share_dir}/grub-boot-select.bsh"

MENU="$(printf '%s\n' 'Choose boot mode' 'System will start in 4 seconds' 'PERSISTENT Mode | USER Session' 'PERSISTENT Mode | SYSMAINT Session')"
LUKS="$(printf '%s\n' 'Please unlock disk cryptroot' 'Enter passphrase for /dev/sda2_crypt')"
NOISE="$(printf '%s\n' 'Loading Linux' 'Booting a kernel')"
## GRUB's post-autoboot banner: the entry TITLE text ("PERSISTENT Mode") appears here, so a
## confirm/detect regex matching entry titles (not just the "Choose boot mode" header) would
## wrongly treat this booting screen as the live menu and fire Enter into the LUKS prompt.
BOOTING="$(printf '%s\n' "Booting 'PERSISTENT Mode | USER Session | daily activities'" 'Loading Linux 6.12.0-1 ...' 'Loading initial ramdisk ...')"
DOWN='e0 50 e0 d0'
ENTER='1c 9c'

pass=0
fail=0
assert_eq() {
   local desc="$1" got="$2" want="$3"
   if [ "${got}" = "${want}" ]; then
      printf '%s\n' "PASS: ${desc}"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: ${desc}" "  got:  ${got}" "  want: ${want}" >&2
      fail=$(( fail + 1 ))
   fi
}

## Reset the per-case OCR script + scancode log, then write frames 1..N (default.txt is the
## post-sequence fallback). Usage: set_case <default-frame> <frame1> [frame2 ...]
set_case() {
   local def="$1"; shift
   printf '%s' '' > "${SCANCODE_LOG}"
   printf '%s' '0' > "${OCR_COUNTER_FILE}"
   safe-rm --force -- "${OCR_RESPONSES_DIR}"/*.txt 2>/dev/null || true
   printf '%s' "${def}" > "${OCR_RESPONSES_DIR}/default.txt"
   local i=1
   local frame
   for frame in "$@"; do
      printf '%s' "${frame}" > "${OCR_RESPONSES_DIR}/${i}.txt"
      i=$(( i + 1 ))
   done
}

## --- happy path: menu present at detection AND at confirm -> Down then Enter ----------
## select is run in a subshell so its die() (exit) on the safe-fail cases cannot terminate
## this test; all driven state (scancode log, OCR counter) lives in files, not shell vars.
set_case "${MENU}" "${MENU}" "${MENU}"
rc=0
( select_installed_sysmaint ) 2>/dev/null || rc=$?
assert_eq 'happy: returns 0' "${rc}" '0'
assert_eq 'happy: scancodes = Down then Enter' "$(cat -- "${SCANCODE_LOG}")" "$(printf '%s\n' "${DOWN}" "${ENTER}")"

## --- empty-passphrase guard (the bug): menu seen, then GONE by confirm ----------------
## Down halts+moves, but the confirm never re-sees the menu -> Enter must NOT be sent (it
## would submit an empty passphrase to the LUKS prompt). FAILS on the pre-fix body, which
## sent Down+Enter blindly on the first match.
set_case "${LUKS}" "${MENU}"
rc=0
( select_installed_sysmaint ) 2>/dev/null || rc=$?
assert_eq 'bug-guard: safe-fails nonzero' "${rc}" '5'
assert_eq 'bug-guard: Down was sent' "$(grep --fixed-strings --line-regexp --count -- "${DOWN}" "${SCANCODE_LOG}" || true)" '1'
assert_eq 'bug-guard: Enter was NOT sent after the menu vanished' "$(grep --fixed-strings --line-regexp --count -- "${ENTER}" "${SCANCODE_LOG}" || true)" '0'

## --- post-autoboot banner at confirm: menu seen, then GRUB's "Booting 'PERSISTENT Mode
## | USER Session'" banner (entry TITLE, not the header). Enter must NOT fire -- the menu is
## gone, GRUB is booting USER, and an Enter would hit the LUKS prompt. FAILS on a body whose
## confirm matches entry titles rather than the header only.
set_case "${BOOTING}" "${MENU}"
rc=0
( select_installed_sysmaint ) 2>/dev/null || rc=$?
assert_eq 'banner-confirm: safe-fails nonzero' "${rc}" '5'
assert_eq 'banner-confirm: Enter NOT sent for the post-autoboot banner' "$(grep --fixed-strings --line-regexp --count -- "${ENTER}" "${SCANCODE_LOG}" || true)" '0'

## --- missed menu entirely: the banner is on screen throughout (never the header). No Down,
## no Enter -- detection matches the header only, so a booting screen is never acted on.
set_case "${BOOTING}"
rc=0
( select_installed_sysmaint ) 2>/dev/null || rc=$?
assert_eq 'banner-only: safe-fails nonzero' "${rc}" '5'
assert_eq 'banner-only: no scancodes sent' "$(cat -- "${SCANCODE_LOG}")" ''

## --- never detected: autoboot/other screen throughout -> safe-fail, no scancodes ------
set_case "${NOISE}"
rc=0
( select_installed_sysmaint ) 2>/dev/null || rc=$?
assert_eq 'never-detected: safe-fails nonzero' "${rc}" '5'
assert_eq 'never-detected: no scancodes sent' "$(cat -- "${SCANCODE_LOG}")" ''

printf '%s\n' "" "${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
