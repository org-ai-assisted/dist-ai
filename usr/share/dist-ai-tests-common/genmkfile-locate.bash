#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## genmkfile-locate.bash: resolve the genmkfile library (make-helper-one.bsh) a
## genmkfile *_test.sh sources, OR the genmkfile binary it execs, and apply the
## shared checkout capability gate. One copy of the discovery + gate for the whole
## genmkfile-tests suite, so the tests cannot drift into selecting different
## subjects (library vs binary) or different skip results.
##
## Explicit selection is honored EXACTLY (the "check one, run another" false-green
## class): a SET GENMKFILE_BIN / GENMKFILE_SHARE that names an UNREADABLE helper or
## a non-executable binary FAILS loud -- it never falls back to an unrelated
## checkout, which would test code the caller did not select. Only when NEITHER is
## set does it fall back to the dm checkout, then the installed copy (the latter ->
## SKIP, since it drifts from the tree under review).
##
## Pure sourced-only fragment: functions only, no strict-mode preamble and no
## was_executed guard.
## style-ok: no-strict -- sourced-only fragment

## OUT globals set here and read by the sourcing test.
# shellcheck disable=SC2034

## genmkfile_require_helper
## Sets the global 'genmkfile_helper_file' to the resolved make-helper-one.bsh.
## Exits 77 (SKIP) when no checkout is wired and only the installed copy exists;
## exits 1 (FATAL) when an explicitly selected helper is unreadable or none is
## found. Call it NOT inside a command substitution, so its exit reaches the test.
genmkfile_require_helper() {
   local bin_real from_bin candidate dm_candidate
   ## GENMKFILE_BIN is how CI points at the component checkout (neither the dm path
   ## nor /usr). Derive the share dir from it; honor it exactly.
   if [ -n "${GENMKFILE_BIN:-}" ]; then
      ## Resolve the binary to an absolute, symlink-free path BEFORE deriving the
      ## share dir: a relative or symlinked GENMKFILE_BIN would otherwise resolve
      ## the helper lexically to the wrong checkout (or a cwd-relative path that
      ## breaks once a test changes directory).
      bin_real="$(readlink --canonicalize -- "${GENMKFILE_BIN}")"
      from_bin="$(dirname -- "$(dirname -- "${bin_real}")")/share/genmkfile/make-helper-one.bsh"
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
      ## Absolute so a test that changes directory still sources it.
      genmkfile_helper_file="$(readlink --canonicalize -- "${GENMKFILE_SHARE}/make-helper-one.bsh")"
      return 0
   fi
   ## Nothing wired: the dm checkout BEFORE the installed copy (the installed copy
   ## drifts from the tree under review). Only consider the dm candidate when HOME is
   ## set -- an empty HOME would otherwise build a bogus root-level '/derivative-maker'
   ## path that must never be trusted; with no HOME, fall through to the installed skip.
   dm_candidate=""
   [ -n "${HOME:-}" ] && dm_candidate="${HOME}/derivative-maker/packages/kicksecure/genmkfile/usr/share/genmkfile/make-helper-one.bsh"
   for candidate in \
      "${dm_candidate}" \
      "/usr/share/genmkfile/make-helper-one.bsh"; do
      [ -n "${candidate}" ] || continue
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

## genmkfile_require_bin
## Sets the global 'genmkfile_bin_path' to the resolved genmkfile binary, for the
## suites that EXEC the genmkfile binary end-to-end rather than sourcing the
## library. Same exact-honor / skip / FATAL contract as genmkfile_require_helper.
## Call it NOT inside a command substitution, so its exit reaches the test.
genmkfile_require_bin() {
   local candidate dm_candidate share_real
   ## GENMKFILE_BIN is how CI points at the component checkout's binary; honor it
   ## exactly -- a set-but-non-executable path is an env bug, not a reason to test
   ## an unrelated checkout.
   if [ -n "${GENMKFILE_BIN:-}" ]; then
      if [ ! -x "${GENMKFILE_BIN}" ]; then
         printf '%s\n' "FATAL: GENMKFILE_BIN set but '${GENMKFILE_BIN}' is not executable." >&2
         exit 1
      fi
      ## Absolute, symlink-free so a test that changes directory before exec still
      ## finds it (install_modes_test.sh cds into a temp tree, then execs this).
      genmkfile_bin_path="$(readlink --canonicalize -- "${GENMKFILE_BIN}")"
      return 0
   fi
   ## An explicit GENMKFILE_SHARE selects a checkout for binary tests too: derive
   ## the binary from the SAME checkout (symmetric to how require_helper derives
   ## the share dir from GENMKFILE_BIN), so a SHARE-only selection cannot silently
   ## fall through to the dm checkout and test a DIFFERENT subject.
   if [ -n "${GENMKFILE_SHARE:-}" ]; then
      share_real="$(readlink --canonicalize -- "${GENMKFILE_SHARE}")"
      candidate="$(dirname -- "$(dirname -- "${share_real}")")/bin/genmkfile"
      if [ ! -x "${candidate}" ]; then
         printf '%s\n' "FATAL: GENMKFILE_SHARE set but '${candidate}' is not executable." >&2
         exit 1
      fi
      genmkfile_bin_path="${candidate}"
      return 0
   fi
   ## Nothing wired: the dm checkout BEFORE the installed copy (the installed copy
   ## drifts from the tree under review). Only consider the dm candidate when HOME is
   ## set -- an empty HOME would otherwise build a bogus root-level '/derivative-maker'
   ## path that must never be trusted; with no HOME, fall through to the installed skip.
   dm_candidate=""
   [ -n "${HOME:-}" ] && dm_candidate="${HOME}/derivative-maker/packages/kicksecure/genmkfile/usr/bin/genmkfile"
   for candidate in \
      "${dm_candidate}" \
      "/usr/bin/genmkfile"; do
      [ -n "${candidate}" ] || continue
      [ -x "${candidate}" ] || continue
      if [ "${candidate}" = "/usr/bin/genmkfile" ]; then
         printf '%s\n' "SKIP: no genmkfile checkout wired (set GENMKFILE_BIN); not testing the installed copy." >&2
         exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
      fi
      genmkfile_bin_path="${candidate}"
      return 0
   done
   printf '%s\n' 'FATAL: genmkfile binary not found (set GENMKFILE_BIN).' >&2
   exit 1
}
