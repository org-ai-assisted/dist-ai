#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Files placed into the image chroot must get an EXPLICIT mode.
##
## THE BUG THIS GUARDS: a plain 'cp' carries the SOURCE file's mode into the
## image, and that mode is whatever the builder's umask produced at checkout.
## git records 100644, but 'git checkout' creates 0666 & ~umask -- 0644 on a
## umask-022 CI runner, 0660 on a umask-007 Kicksecure host. The image's
## permissions therefore depended on WHO built it, which makes a byte-identical
## rebuild impossible for anyone whose umask differs.
##
## Measured on commit 96fee033c: /etc/default/grub.d/20_dist-base-files.cfg came
## out 0644 in CI and 0640 locally, and it was one of only TWO differences left
## between the CI image and a local build of the same commit.
##
## Needs no root, no network, no build: this reads the build steps.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi
if [ ! -d "${dm_checkout}/build-steps.d" ]; then
   printf '%s\n' "SKIP: no derivative-maker checkout (set DERIVATIVE_MAKER_DIR)." >&2
   exit 77
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

## Any 'cp' whose destination is inside the chroot inherits a umask-dependent
## mode. The named cp_reproducible / cp_reproducible_exec arrays (help-steps/
## variables) state the intent instead.
## BOTH parameter forms: a step writing "$CHROOT_FOLDER/etc/x" creates the same
## umask-dependent mode, and matching only the braced form would report success.
chroot_folder_ref='(\$\{CHROOT_FOLDER\}|\$CHROOT_FOLDER)'
## Commented-out lines are not build steps. Without this the broadened pattern
## flags a disabled 'cp' in 3400_copy-vms-into-raw and the rule cries wolf.
offenders="$( grep -nE "cp (--|-[a-zA-Z]+ )?.*${chroot_folder_ref}" \
   -- "${dm_checkout}"/build-steps.d/* 2>/dev/null \
   | grep -vE '^[^:]+:[0-9]+: *#' || true )"

if [ -z "${offenders}" ]; then
   pass 'no plain cp into the chroot; every placed file states its mode'
else
   fail "these copy into the image chroot WITHOUT an explicit mode, so the
      resulting permissions depend on the builder's umask:
$( printf '%s\n' "${offenders}" | sed 's/^/         /' )"
fi

## CANARY: the grep must actually be capable of matching, or a rule that scans
## nothing would pass forever. Prove it against a known-shaped line.
canary_file="$( mktemp )"
# shellcheck disable=SC2317  # reached only via the EXIT trap
cleanup() {
   safe-rm --force -- "${canary_file}"
}
trap cleanup EXIT
printf '%s\n' '   ${SUDO_TO_ROOT} cp -- "${src}/x" "${CHROOT_FOLDER}/etc/x"' > "${canary_file}"
if grep -qE "cp (--|-[a-zA-Z]+ )?.*${chroot_folder_ref}" -- "${canary_file}"; then
   pass 'canary: the pattern does match a plain chroot cp, so a clean result means something'
else
   fail 'canary broken: the pattern matches nothing, so this test proves nothing'
fi

## ...and it must NOT flag the fixed form, or the rule would be unusable.
printf '%s\n' '   ${SUDO_TO_ROOT} "${cp_reproducible[@]}" "${src}/x" "${CHROOT_FOLDER}/etc/x"' > "${canary_file}"
if grep -qE "cp (--|-[a-zA-Z]+ )?.*${chroot_folder_ref}" -- "${canary_file}"; then
   fail 'the pattern flags the CORRECT cp_reproducible form; it would fire forever'
else
   pass 'the fixed cp_reproducible form is not flagged'
fi

## UNBRACED canary: the form coderabbit flagged as bypassing the braced pattern.
printf '%s\n' '   ${SUDO_TO_ROOT} cp -- "${src}/x" "$CHROOT_FOLDER/etc/x"' > "${canary_file}"
if grep -qE "cp (--|-[a-zA-Z]+ )?.*${chroot_folder_ref}" -- "${canary_file}"; then
   pass 'canary: the unbraced $CHROOT_FOLDER form is matched too'
else
   fail 'the unbraced $CHROOT_FOLDER form is NOT matched; a build step using it would bypass this test'
fi

## The build must also pin a umask, or every file it creates outside these five
## sites still inherits the builder's. That is the same defect, one layer up.
if grep -qE '^umask 0022' -- "${dm_checkout}/help-steps/variables"; then
   pass 'help-steps/variables pins a deterministic umask'
else
   fail 'help-steps/variables does not pin a umask; file modes still depend on the builder'
fi

summary_line="===== chroot copy explicit mode: ${pass_count} pass, ${fail_count} fail ====="
printf '%s\n' "${summary_line}"
if [ "${fail_count}" -gt 0 ]; then
   exit 1
fi
exit 0
