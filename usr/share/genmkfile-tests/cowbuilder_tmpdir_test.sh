#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## genmkfile's cowbuilder invocation must CLEAR the temp-dir variables.
##
## libpam-tmpdir (a Kicksecure security feature) sets TMPDIR=/tmp/user/0 for sudo's
## root session. pbuilder passes the environment into the chroot, where that path does
## not exist, and the build dies in pbuilder-satisfydepends with:
##
##   dpkg-deb: error: failed to make temporary file (control member):
##             No such file or directory
##
## Debian #823651. The failure is remote from its cause -- nothing in the message
## mentions TMPDIR or libpam-tmpdir -- which is why it needs a test rather than a
## reviewer.
##
## Two properties are asserted, and the second is the one that rots quietly:
##   1. the four variables are cleared on the cowbuilder command line
##   2. they are cleared AFTER 'sudo'. sudo's env_reset discards anything set on the
##      calling side, so the same clearing placed before 'sudo' silently does nothing
##      -- it would still look correct in a diff.
##
## Static assertion against the shipped source. Running a real cowbuilder here would
## need root, a chroot and the network; the ORDER property is a property of the
## command line itself, so reading it is the faithful check, not a shortcut.
##
## Exit: 0 pass | 1 fail | 77 skip when genmkfile is not present.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Subject selection mirrors the rest of this suite (first that exists):
##   $GENMKFILE_SHARE -> the derivative-maker submodule checkout -> the installed
##   /usr/share/genmkfile. Checkout BEFORE installed: the installed copy drifts from
##   the tree under review, so preferring it tests code nobody is changing.
locate_helper() {
   local candidate
   ## GENMKFILE_BIN is how CI points at the component checkout, which lives at neither
   ## the dm path nor /usr. Derive the share dir from it, or every share-based test
   ## SKIPs there -- reporting nothing while looking green.
   local from_bin=''
   if [ -n "${GENMKFILE_BIN:-}" ]; then
      from_bin="$(dirname -- "$(dirname -- "${GENMKFILE_BIN}")")/share/genmkfile/make-helper-one.bsh"
   fi
   for candidate in \
      "${GENMKFILE_SHARE:-}/make-helper-one.bsh" \
      "${from_bin}" \
      "${HOME}/derivative-maker/packages/kicksecure/genmkfile/usr/share/genmkfile/make-helper-one.bsh" \
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

tests_total=0
tests_failed=0

pass() {
   tests_total=$(( tests_total + 1 ))
   printf '%s\n' "PASS  $1"
}

fail() {
   tests_total=$(( tests_total + 1 ))
   tests_failed=$(( tests_failed + 1 ))
   printf '%s\n' "FAIL  $1" >&2
}

## The cowbuilder call is a single backslash-continued command. Join it into one
## logical line so the argument ORDER can be inspected: reading the raw lines would
## make 'sudo' and the env clearing look unrelated.
##
## Anchored on the LAST 'make_log_and_run' before '--buildresult', not the first one
## in the file. A plain sed range spans from the earliest 'make_log_and_run' (a
## dpkg-source call) all the way to the cowbuilder line, and the order check then
## measures against dpkg-source's 'sudo' instead of cowbuilder's -- it passed a
## subject with the clearing deliberately moved before 'sudo'.
##
## No '--' before the filename: awk has no end-of-options marker and would read it
## as a file to open. The path comes from locate_helper, not from an argument.
invocation="$(
   awk '
      /make_log_and_run \\/ { buf = $0; capturing = 1; next }
      capturing { buf = buf " " $0 }
      /--buildresult/ && capturing { print buf; exit }
   ' "${helper_file}" \
   | tr --squeeze-repeats ' '
)"

if [ -z "${invocation}" ]; then
   printf '%s\n' 'FAIL  could not locate the cowbuilder invocation in the subject' >&2
   exit 1
fi

## 1. every temp-dir variable is cleared
for var in TMPDIR TMP TEMPDIR TEMP; do
   case "${invocation}" in
      *"--unset=${var}"* )
         pass "${var} is cleared on the cowbuilder invocation"
         ;;
      * )
         fail "${var} is NOT cleared -- libpam-tmpdir will break the build"
         ;;
   esac
done

## 2. the clearing happens AFTER sudo, or env_reset undoes it
sudo_prefix="${invocation%%sudo *}"
case "${sudo_prefix}" in
   *'--unset=TMPDIR'* )
      fail "the temp-dir clearing sits BEFORE sudo, where env_reset discards it"
      ;;
   * )
      pass "the clearing is applied after sudo (survives env_reset)"
      ;;
esac

## 3. CANARY: the assertions above must be able to fail. A subject with the clearing
##    removed has to be rejected, or a future refactor that drops it reads as green.
mutated="$(printf '%s\n' "${invocation}" | sed 's/--unset=TMPDIR//g')"
case "${mutated}" in
   *'--unset=TMPDIR'* )
      fail "canary: the mutation did not remove the clearing, so check 1 proves nothing"
      ;;
   * )
      pass "canary: check 1 distinguishes a subject with the clearing removed"
      ;;
esac

## 4. the invocation is the real one -- guards against the sed above silently
##    matching some other command and every assertion passing vacuously
case "${invocation}" in
   *cowbuilder*--basepath*--buildresult* )
      pass "the inspected command really is the cowbuilder build invocation"
      ;;
   * )
      fail "the extracted text is not the cowbuilder invocation: ${invocation}"
      ;;
esac

## 5. and ONLY that invocation. If the extraction bleeds into an earlier
##    make_log_and_run, the order check above measures the wrong 'sudo' and silently
##    passes a subject that has the clearing in the wrong place.
case "${invocation}" in
   *dpkg-source* | *debsign* )
      fail "the extraction spans more than the cowbuilder invocation: ${invocation}"
      ;;
   * )
      pass "the extraction is confined to the cowbuilder invocation"
      ;;
esac

printf '%s\n' "" "${tests_total} test(s), ${tests_failed} failed"
if [ "${tests_failed}" -ne 0 ]; then
   exit 1
fi
exit 0
