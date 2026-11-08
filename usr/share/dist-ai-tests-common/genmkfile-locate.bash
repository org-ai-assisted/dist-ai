#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## genmkfile-locate.bash: resolve the genmkfile library (make-helper-one.bsh) a
## genmkfile *_test.sh sources, and apply the shared checkout capability gate.
## One copy of the discovery + gate for the whole genmkfile-tests suite, so the
## tests cannot drift into selecting different helpers or different skip results.
##
## Explicit selection is honored EXACTLY (the "check one, run another" false-green
## class): a SET GENMKFILE_BIN / GENMKFILE_SHARE that names an UNREADABLE helper
## FAILS loud -- it never falls back to an unrelated checkout, which would test
## code the caller did not select. Only when NEITHER is set does it fall back to
## the dm checkout, then the installed copy (the latter -> SKIP, since it drifts
## from the tree under review).
##
## Pure sourced-only fragment: functions only, no strict-mode preamble and no
## was_executed guard.
## style-ok: no-strict -- sourced-only fragment

## 'genmkfile_helper_file' is an OUT global set here and read by the sourcing test.
# shellcheck disable=SC2034

## genmkfile_require_helper
## Sets the global 'genmkfile_helper_file' to the resolved absolute-or-given path.
## Exits 77 (SKIP) when no checkout is wired and only the installed copy exists;
## exits 1 (FATAL) when an explicitly selected helper is unreadable or none is
## found. Call it NOT inside a command substitution, so its exit reaches the test.
genmkfile_require_helper() {
   local from_bin candidate
   ## GENMKFILE_BIN is how CI points at the component checkout (neither the dm path
   ## nor /usr). Derive the share dir from it; honor it exactly.
   if [ -n "${GENMKFILE_BIN:-}" ]; then
      from_bin="$(dirname -- "$(dirname -- "${GENMKFILE_BIN}")")/share/genmkfile/make-helper-one.bsh"
      if [ ! -r "${from_bin}" ]; then
         printf '%s\n' "FATAL: GENMKFILE_BIN set but '${from_bin}' is not readable." >&2
         exit 1
      fi
      genmkfile_helper_file="${from_bin}"
      return 0
   fi
   if [ -n "${GENMKFILE_SHARE:-}" ]; then
      if [ ! -r "${GENMKFILE_SHARE}/make-helper-one.bsh" ]; then
         printf '%s\n' "FATAL: GENMKFILE_SHARE set but '${GENMKFILE_SHARE}/make-helper-one.bsh' is not readable." >&2
         exit 1
      fi
      genmkfile_helper_file="${GENMKFILE_SHARE}/make-helper-one.bsh"
      return 0
   fi
   ## Nothing wired: the dm checkout BEFORE the installed copy (the installed copy
   ## drifts from the tree under review).
   for candidate in \
      "${HOME}/derivative-maker/packages/kicksecure/genmkfile/usr/share/genmkfile/make-helper-one.bsh" \
      "/usr/share/genmkfile/make-helper-one.bsh"; do
      [ -r "${candidate}" ] || continue
      if [ "${candidate}" = "/usr/share/genmkfile/make-helper-one.bsh" ]; then
         printf '%s\n' "SKIP: no genmkfile checkout wired (set GENMKFILE_BIN); not testing the installed copy." >&2
         exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
      fi
      genmkfile_helper_file="${candidate}"
      return 0
   done
   printf '%s\n' 'FATAL: make-helper-one.bsh not found (set GENMKFILE_BIN or GENMKFILE_SHARE).' >&2
   exit 1
}
