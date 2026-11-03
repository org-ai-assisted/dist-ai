#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## subject-resolve.bash: resolve the SUBJECT binary a *_test.sh drives (the
## static gate, the orchestrator, ...) to an ABSOLUTE path, honoring an explicit
## env override exactly. One root for the whole "check one path, run another"
## false-green class:
##   - A SET override (even empty) is honored EXACTLY -- never a silent fall back
##     to the installed copy. An empty/missing/non-exec override fails the -x
##     check loud, so a canary cannot pass WITHOUT testing the binary it named.
##   - Only an UNSET override falls back: in-tree (TEST_DIR/../../bin/BIN) then
##     the installed /usr/bin/BIN.
##   - The result is ALWAYS absolute, so it survives a later `cd` (a relative
##     override would not resolve from inside a temp repo) and is never
##     PATH-searched (a slash-free override would otherwise be a CWD file to -x
##     but a PATH lookup at invocation -- silently running the installed copy).
##
## Pure sourced-only fragment: one function, no strict-mode preamble and no
## was_executed guard.
## style-ok: no-strict -- sourced-only fragment

## resolve_test_subject VAR_NAME BIN_NAME TEST_DIR
## Echo the absolute subject path on stdout; print FATAL to stderr and return 1
## when it is missing or not executable. Caller: SUBJ="$(resolve_test_subject
## VAR BIN DIR)" || exit 1.
resolve_test_subject() {
   local var_name bin_name test_dir subject
   var_name="$1"
   bin_name="$2"
   test_dir="$3"
   ## SET (even empty) -> honored exactly; UNSET -> in-tree then installed. The
   ## '+x' indirect test distinguishes empty-but-set from unset without eval.
   if [ "${!var_name+x}" = 'x' ]; then
      subject="${!var_name}"
   else
      subject="${test_dir}/../../bin/${bin_name}"
      [ -x "${subject}" ] || subject="/usr/bin/${bin_name}"
   fi
   ## Pin a relative or slash-free value to an absolute path from the CURRENT dir
   ## (before any cd), so the -x check and the later invocation name the SAME
   ## binary. An empty value canonicalizes to nothing and fails -x below, loud.
   if [ "${subject:0:1}" != '/' ]; then
      subject="$(readlink --canonicalize-missing -- "${subject}")" || true
   fi
   if [ ! -x "${subject}" ]; then
      printf '%s\n' "FATAL: ${bin_name} not executable at '${subject}'." >&2
      return 1
   fi
   printf '%s\n' "${subject}"
}
