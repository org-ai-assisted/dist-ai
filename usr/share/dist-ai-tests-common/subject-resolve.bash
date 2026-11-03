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
   ## Locals are '_rts_'-prefixed: VAR_NAME is read by INDIRECT expansion
   ## (${!_rts_var}), so a plain local name (subject, var_name) that collided with
   ## the caller's own variable name would be read instead of the caller's value,
   ## silently treating a SET override as unset. The prefix makes a collision
   ## effectively impossible.
   local _rts_var _rts_bin _rts_dir _rts_subject
   _rts_var="$1"
   _rts_bin="$2"
   _rts_dir="$3"
   ## SET (even empty) -> honored exactly; UNSET -> in-tree then installed. The
   ## '+x' indirect test distinguishes empty-but-set from unset without eval.
   if [ "${!_rts_var+x}" = 'x' ]; then
      _rts_subject="${!_rts_var}"
   else
      _rts_subject="${_rts_dir}/../../bin/${_rts_bin}"
      [ -x "${_rts_subject}" ] || _rts_subject="/usr/bin/${_rts_bin}"
   fi
   ## Pin a relative or slash-free value to an absolute path from the CURRENT dir
   ## (before any cd), so the -x check and the later invocation name the SAME
   ## binary. An empty value canonicalizes to nothing and fails -x below, loud.
   if [ "${_rts_subject:0:1}" != '/' ]; then
      _rts_subject="$(readlink --canonicalize-missing -- "${_rts_subject}")" || true
   fi
   if [ ! -x "${_rts_subject}" ]; then
      printf '%s\n' "FATAL: ${_rts_bin} not executable at '${_rts_subject}'." >&2
      return 1
   fi
   printf '%s\n' "${_rts_subject}"
}
