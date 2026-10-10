#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## deb_variables_check must derive the Debian maintainer identity (DEBEMAIL /
## DEBFULLNAME) from the debian/control 'Maintainer:' field when the env vars are
## unset, so the debian/changelog trailer always equals the control Maintainer
## (lintian source-nmu-has-incorrect-version-number becomes impossible with zero
## config). An explicitly-set env var still wins (a genuine NMU by a different
## uploader). This drives the REAL deb_variables_check (sourced; the helper's main
## is was_executed-guarded) against a debian/control fixture whose Maintainer email
## differs from the override email, and asserts: unset -> derived from control;
## explicit -> preserved; per-var independent; a Maintainer that is not exactly one
## 'Full Name <email>' mailbox (missing, ambiguous, unclosed, or a non-address) fails
## loud rather than guessing.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

# shellcheck disable=SC2317
error_handler() {
   local exit_code="$?"
   printf '%s\n' "ERROR: exit_code: ${exit_code} | BASH_COMMAND: ${BASH_COMMAND}"
   exit 1
}
trap error_handler ERR

locate_helper() {
   local candidate from_bin=''
   if [ -n "${GENMKFILE_BIN:-}" ]; then
      from_bin="$(dirname -- "$(dirname -- "${GENMKFILE_BIN}")")/share/genmkfile/make-helper-one.bsh"
   fi
   for candidate in \
      "${GENMKFILE_SHARE:-}/make-helper-one.bsh" \
      "${from_bin}" \
      "${HOME:-}/derivative-maker/packages/kicksecure/genmkfile/usr/share/genmkfile/make-helper-one.bsh" \
      "/usr/share/genmkfile/make-helper-one.bsh"
   do
      [ -n "${candidate}" ] || continue
      case "${candidate}" in
         '/make-helper-one.bsh' )
            continue
            ;;
      esac
      if test -r "${candidate}"; then
         printf '%s\n' "${candidate}"
         return 0
      fi
   done
   return 1
}

if ! helper_file="$(locate_helper)"; then
   printf '%s\n' 'FATAL: make-helper-one.bsh not found (set GENMKFILE_SHARE).' >&2
   exit 1
fi

## Capability gate: this suite tests the genmkfile CHECKOUT (wired via GENMKFILE_BIN or
## GENMKFILE_SHARE). If nothing was wired and only the installed /usr/share/genmkfile helper
## resolved -- which drifts from the tree under review -- SKIP rather than report a confusing
## FAIL against a possibly-stale subject nobody is changing.
if [ -z "${GENMKFILE_SHARE:-}" ] && [ -z "${GENMKFILE_BIN:-}" ] \
   && [ "${helper_file}" = "/usr/share/genmkfile/make-helper-one.bsh" ]; then
   printf '%s\n' "SKIP: no genmkfile checkout wired (set GENMKFILE_BIN); not testing the installed copy." >&2
   exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
fi
if ! type -P grep-dctrl >/dev/null 2>&1; then
   printf '%s\n' 'FATAL: grep-dctrl (dctrl-tools) is required.' >&2
   exit 1
fi

GENMKFILE_PATH="$(dirname -- "${helper_file}")"
export GENMKFILE_PATH
## style-ok: allow-sc1091-disable -- helper_file is located at runtime, unfollowable
# shellcheck disable=SC1090,SC1091
source "${helper_file}"

test_root="$(mktemp --directory)"
# shellcheck disable=SC2317
cleanup_handler() {
   safe-rm -r -f -- "${test_root}"
}
trap cleanup_handler EXIT

tests_total=0
tests_failed=0
pass() { printf '%s\n' "PASS  $1"; }
fail() { tests_failed=$(( tests_failed + 1 )); printf '%s\n' "FAIL  $1" >&2; }

## Write a minimal debian/control whose Maintainer field is $1.
write_control() {
   {
      printf '%s\n' 'Source: testpkg'
      printf '%s\n' 'Section: misc'
      printf '%s\n' 'Priority: optional'
      printf '%s\n' "Maintainer: $1"
      printf '%s\n' 'Standards-Version: 4.6.2'
      printf '%s\n' ''
      printf '%s\n' 'Package: testpkg'
      printf '%s\n' 'Architecture: all'
      printf '%s\n' 'Description: test package'
      printf '%s\n' ' long description'
   } > "${test_root}/control"
}

## Drive the REAL maintainer-identity flow against the control fixture, exactly as
## make_get_dependencies does it: derive from debian/control ONLY when neither
## DEBEMAIL nor DEBFULLNAME is set, then validate. Records the resulting DEBEMAIL /
## DEBFULLNAME to ${test_root}/out, and any exit_with_error message to
## ${test_root}/die (the run is a subshell so a stubbed exit_with_error cannot end the
## test, and DEBEMAIL/DEBFULLNAME changes do not leak between cases). DEBEMAIL/DEBFULLNAME
## are taken from the environment the caller sets up before invoking this.
run_check() {
   true > "${test_root}/out"
   true > "${test_root}/die"
   (
      ## Consumed by the sourced deb_variables_check, invisible to shellcheck.
      # shellcheck disable=SC2034
      make_debian_control_file_absolute_path="${test_root}/control"
      # shellcheck disable=SC2317
      make_output_info() { :; }
      # shellcheck disable=SC2317
      make_output_warn() { :; }
      # shellcheck disable=SC2317
      make_output_error() { :; }
      # shellcheck disable=SC2317
      exit_with_error() {
         printf '%s' "${2:-}" > "${test_root}/die"
         exit "${1:-1}"
      }
      if [ -z "${DEBEMAIL:-}" ] && [ -z "${DEBFULLNAME:-}" ]; then
         deb_maintainer_identity_from_control
      fi
      deb_variables_check
      printf '%s\n' "DEBEMAIL=${DEBEMAIL:-}" > "${test_root}/out"
      printf '%s\n' "DEBFULLNAME=${DEBFULLNAME:-}" >> "${test_root}/out"
   ) >/dev/null 2>&1 || true
}

read_out() {
   local key="$1"
   if [ ! -s "${test_root}/out" ]; then
      printf '%s\n' ''
      return 0
   fi
   ## Emit the value for KEY= from the captured out file.
   while IFS='=' read -r out_key out_value; do
      if [ "${out_key}" = "${key}" ]; then
         printf '%s\n' "${out_value}"
         return 0
      fi
   done < "${test_root}/out"
   printf '%s\n' ''
}

write_control 'Canary Name <canary@kicksecure.com>'

## 1. Both env vars unset -> derive BOTH from the control Maintainer.
unset DEBEMAIL DEBFULLNAME
run_check
tests_total=$(( tests_total + 1 ))
got_email="$(read_out DEBEMAIL)"
got_name="$(read_out DEBFULLNAME)"
if [ "${got_email}" = 'canary@kicksecure.com' ] && [ "${got_name}" = 'Canary Name' ]; then
   pass "unset env derives both from control (email + name)"
else
   fail "derive-both wrong: email=[${got_email}] name=[${got_name}] (want canary@kicksecure.com / Canary Name)"
fi

## 2. Both env vars set explicitly -> PRESERVED, control ignored (genuine NMU override).
export DEBEMAIL='explicit@uploader.org'
export DEBFULLNAME='Explicit Uploader'
run_check
tests_total=$(( tests_total + 1 ))
got_email="$(read_out DEBEMAIL)"
got_name="$(read_out DEBFULLNAME)"
if [ "${got_email}" = 'explicit@uploader.org' ] && [ "${got_name}" = 'Explicit Uploader' ]; then
   pass "explicit env overrides control (both preserved)"
else
   fail "override-both wrong: email=[${got_email}] name=[${got_name}] (want explicit@uploader.org / Explicit Uploader)"
fi

## 3. A half-set identity (only DEBEMAIL) is all-or-nothing: control does NOT complete
## it (no incoherent operator-email + control-name mailbox) -> fail loud.
export DEBEMAIL='explicit@uploader.org'
unset DEBFULLNAME
run_check
tests_total=$(( tests_total + 1 ))
die_msg="$(cat -- "${test_root}/die")"
got_name="$(read_out DEBFULLNAME)"
if [ -n "${die_msg}" ] && [ -z "${got_name}" ]; then
   pass "half-set identity (only email) aborts loud (no mixed name from control)"
else
   fail "half-set (email) NOT rejected: die=[${die_msg}] name=[${got_name}]"
fi

## 3b. Symmetric half-set (only DEBFULLNAME) -> also fail loud, no mixed email.
unset DEBEMAIL
export DEBFULLNAME='Explicit Uploader'
run_check
tests_total=$(( tests_total + 1 ))
die_msg="$(cat -- "${test_root}/die")"
got_email="$(read_out DEBEMAIL)"
if [ -n "${die_msg}" ] && [ -z "${got_email}" ]; then
   pass "half-set identity (only name) aborts loud (no mixed email from control)"
else
   fail "half-set (name) NOT rejected: die=[${die_msg}] email=[${got_email}]"
fi
unset DEBFULLNAME

## 4. Maintainer has no '<email>' and env unset -> fail loud (nothing silently wrong).
write_control 'Malformed Maintainer No Brackets'
unset DEBEMAIL DEBFULLNAME
run_check
tests_total=$(( tests_total + 1 ))
die_msg="$(cat -- "${test_root}/die")"
got_email="$(read_out DEBEMAIL)"
if [ -n "${die_msg}" ] && [ -z "${got_email}" ]; then
   pass "malformed Maintainer with no env aborts loud (no silent empty identity)"
else
   fail "malformed NOT rejected: die=[${die_msg}] email=[${got_email}]"
fi

## 5. A Maintainer carrying more than one address is ambiguous -> fail loud, never
## guess which bracket is the real one.
write_control 'Jane Doe (formerly <jane@old.com>) <jane@new.com>'
unset DEBEMAIL DEBFULLNAME
run_check
tests_total=$(( tests_total + 1 ))
die_msg="$(cat -- "${test_root}/die")"
got_email="$(read_out DEBEMAIL)"
if [ -n "${die_msg}" ] && [ -z "${got_email}" ]; then
   pass "multi-address Maintainer aborts loud (no guessing which bracket)"
else
   fail "ambiguous Maintainer NOT rejected: die=[${die_msg}] email=[${got_email}]"
fi

## 6. A trailing space inside the brackets is trimmed from the derived email.
write_control 'Foo Bar <foo@example.com >'
unset DEBEMAIL DEBFULLNAME
run_check
tests_total=$(( tests_total + 1 ))
got_email="$(read_out DEBEMAIL)"
got_name="$(read_out DEBFULLNAME)"
if [ "${got_email}" = 'foo@example.com' ] && [ "${got_name}" = 'Foo Bar' ]; then
   pass "whitespace inside the Maintainer brackets is trimmed from the email"
else
   fail "untrimmed derived email: email=[${got_email}] name=[${got_name}] (want foo@example.com / Foo Bar)"
fi

## 7. A debian/control grep-dctrl cannot fully parse (malformed later stanza) must
## fail loud, not derive from the partial value grep-dctrl still prints.
{
   printf '%s\n' 'Source: testpkg'
   printf '%s\n' 'Maintainer: Foo Bar <foo@example.com>'
   printf '%s\n' 'Priority: optional'
   printf '%s\n' ''
   printf '%s\n' 'Package: testpkg'
   printf '%s\n' 'Architecture any'
} > "${test_root}/control"
unset DEBEMAIL DEBFULLNAME
run_check
tests_total=$(( tests_total + 1 ))
die_msg="$(cat -- "${test_root}/die")"
got_email="$(read_out DEBEMAIL)"
if [ -n "${die_msg}" ] && [ -z "${got_email}" ]; then
   pass "a grep-dctrl parse error aborts loud (no derive from a partial parse)"
else
   fail "parse error NOT surfaced: die=[${die_msg}] email=[${got_email}]"
fi

## 8. A Maintainer in a binary stanza must NOT leak in: only the SOURCE stanza's
## Maintainer is used (no multi-line value, no cross-stanza blend).
{
   printf '%s\n' 'Source: testpkg'
   printf '%s\n' 'Maintainer: Canary Name <canary@kicksecure.com>'
   printf '%s\n' 'Priority: optional'
   printf '%s\n' ''
   printf '%s\n' 'Package: testpkg'
   printf '%s\n' 'Architecture: all'
   printf '%s\n' 'Maintainer: Bob Binary <bob@example.com>'
   printf '%s\n' 'Description: test package'
   printf '%s\n' ' long description'
} > "${test_root}/control"
unset DEBEMAIL DEBFULLNAME
run_check
tests_total=$(( tests_total + 1 ))
got_email="$(read_out DEBEMAIL)"
got_name="$(read_out DEBFULLNAME)"
if [ "${got_email}" = 'canary@kicksecure.com' ] && [ "${got_name}" = 'Canary Name' ]; then
   pass "binary-stanza Maintainer ignored; only the source Maintainer is derived"
else
   fail "cross-stanza leak: email=[${got_email}] name=[${got_name}] (want canary@kicksecure.com / Canary Name)"
fi

## 9. A single unclosed '<' (no closing '>') is not a mailbox -> fail loud.
write_control 'Real Name <oops'
unset DEBEMAIL DEBFULLNAME
run_check
tests_total=$(( tests_total + 1 ))
die_msg="$(cat -- "${test_root}/die")"
got_email="$(read_out DEBEMAIL)"
if [ -n "${die_msg}" ] && [ -z "${got_email}" ]; then
   pass "unclosed bracket aborts loud (not a mailbox)"
else
   fail "unclosed bracket NOT rejected: die=[${die_msg}] email=[${got_email}]"
fi

## 10. A parenthetical note AFTER the address that carries its own '<...>' is still
## more than one address -> ambiguous, fail loud (no stale-address leak).
write_control 'John Doe <john@example.com> (previously Jane Roe <jane@old.example>)'
unset DEBEMAIL DEBFULLNAME
run_check
tests_total=$(( tests_total + 1 ))
die_msg="$(cat -- "${test_root}/die")"
got_email="$(read_out DEBEMAIL)"
if [ -n "${die_msg}" ] && [ -z "${got_email}" ]; then
   pass "trailing parenthetical address is ambiguous -> abort (no stale-address leak)"
else
   fail "trailing-address Maintainer NOT rejected: die=[${die_msg}] email=[${got_email}]"
fi

## 11. A single bracketed value that is not an address (no '@') -> fail loud.
write_control 'Plain Name <notanemail>'
unset DEBEMAIL DEBFULLNAME
run_check
tests_total=$(( tests_total + 1 ))
die_msg="$(cat -- "${test_root}/die")"
got_email="$(read_out DEBEMAIL)"
if [ -n "${die_msg}" ] && [ -z "${got_email}" ]; then
   pass "non-address bracketed value aborts loud (must be a real addr-spec)"
else
   fail "non-address NOT rejected: die=[${die_msg}] email=[${got_email}]"
fi

## 12. A folded (RFC822 continuation-line) Maintainer must NOT leak an embedded newline
## into the identity -> fail loud (an embedded newline would split the changelog trailer).
{
   printf '%s\n' 'Source: testpkg'
   printf '%s\n' 'Maintainer: John'
   printf '%s\n' ' Doe <john@example.com>'
   printf '%s\n' 'Priority: optional'
   printf '%s\n' ''
   printf '%s\n' 'Package: testpkg'
   printf '%s\n' 'Architecture: all'
   printf '%s\n' 'Description: test package'
   printf '%s\n' ' long description'
} > "${test_root}/control"
unset DEBEMAIL DEBFULLNAME
run_check
tests_total=$(( tests_total + 1 ))
die_msg="$(cat -- "${test_root}/die")"
got_name="$(read_out DEBFULLNAME)"
if [ -n "${die_msg}" ] && [ -z "${got_name}" ]; then
   pass "folded multi-line Maintainer aborts loud (no embedded newline in identity)"
else
   fail "folded Maintainer NOT rejected: die=[${die_msg}] name=[${got_name}]"
fi

## 13. A bracketed value that is not a valid address (bare '@', internal whitespace,
## or more than one '@') -> fail loud, never written to the changelog.
for bad in '@' 'jane @ example.com' 'a@@b'; do
   write_control "Jane Doe <${bad}>"
   unset DEBEMAIL DEBFULLNAME
   run_check
   tests_total=$(( tests_total + 1 ))
   die_msg="$(cat -- "${test_root}/die")"
   got_email="$(read_out DEBEMAIL)"
   if [ -n "${die_msg}" ] && [ -z "${got_email}" ]; then
      pass "malformed address '<${bad}>' aborts loud"
   else
      fail "malformed address '<${bad}>' NOT rejected: die=[${die_msg}] email=[${got_email}]"
   fi
done

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "maintainer_identity_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "maintainer_identity_test: ${tests_total} pass, 0 fail, 0 skip"
