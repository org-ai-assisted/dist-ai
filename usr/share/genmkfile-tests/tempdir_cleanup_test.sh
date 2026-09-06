#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## make_init creates 'genmkfile_temp_dir' with 'mktemp --directory'. Only make_deinit removes
## it, and make_deinit runs solely on the normal fall-through -- so under 'errexit' any error
## exit (an unrecognized target, a failed control parse, a failed build step) terminates before
## make_deinit and leaks one temp directory per failed run. An EXIT trap set in make_init must
## remove it on every exit path, WITHOUT deleting it mid-run inside a command-substitution
## subshell (which would corrupt a real build).
##
## This pins: an ERROR exit leaves no leftover temp dir, and a NORMAL run also leaves none (the
## trap must not fire early and must be idempotent with make_deinit).
##
## Hermetic: a private TMPDIR under the workdir; no root, nothing outside the workdir touched.
##
## Exit: 0 pass | 1 fail | 77 skip when genmkfile is not present.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp

locate_genmkfile() {
   if [ -n "${GENMKFILE_BIN:-}" ]; then
      printf '%s\n' "${GENMKFILE_BIN}"
      return 0
   fi
   local checkout
   checkout="${HOME}/derivative-maker/packages/kicksecure/genmkfile/usr/bin/genmkfile"
   if [ -x "${checkout}" ]; then
      printf '%s\n' "${checkout}"
      return 0
   fi
   if [ -x /usr/bin/genmkfile ]; then
      printf '%s\n' /usr/bin/genmkfile
      return 0
   fi
   return 1
}

if ! genmkfile_bin="$(locate_genmkfile)"; then
   printf '%s\n' 'FATAL: genmkfile not found (set GENMKFILE_BIN).' >&2
   exit 1
fi

if [ -z "${GENMKFILE_BIN:-}" ] && [ "${genmkfile_bin}" = "/usr/bin/genmkfile" ]; then
   printf '%s\n' "SKIP: no genmkfile checkout wired (set GENMKFILE_BIN); not testing the installed copy." >&2
   exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
fi
printf '%s\n' "INFO: genmkfile under test: ${genmkfile_bin}"

work_dir="$(mktemp --directory -- "${TMP}/genmkfile-tempdir-cleanup.XXXXXX")"
checks=0
failures=0

# shellcheck disable=SC2317
cleanup_handler() {
   safe-rm --recursive --force -- "${work_dir}" || true
   return 0
}
trap cleanup_handler EXIT

pass() {
   checks=$(( checks + 1 ))
   printf '%s\n' "PASS  $1"
}
fail() {
   checks=$(( checks + 1 ))
   failures=$(( failures + 1 ))
   printf '%s\n' "FAIL  $1" >&2
}

## Count 'mktemp --directory' leftovers (tmp.XXXXXXXXXX dirs) in a private TMPDIR.
leftover_temp_dirs() {
   find "$1" -mindepth 1 -maxdepth 1 -type d -name 'tmp.*' 2>/dev/null | wc -l
}

pkg_dir="${work_dir}/pkg"
mkdir --parents -- "${pkg_dir}"

## --- error exit must not leak ------------------------------------------------
## No debian/control here, so an early step fails; the point is that make_init already ran (and
## created its temp dir) before the failure, so the ERROR path is what must still clean up.
err_tmp="${work_dir}/tmp-err"
mkdir --parents -- "${err_tmp}"
rc=0
(
   cd -- "${pkg_dir}" \
   && env TMPDIR="${err_tmp}" "${genmkfile_bin}" definitely-not-a-real-target
) > "${work_dir}/err.log" 2>&1 || rc=$?
if [ "${rc}" -ne 0 ]; then
   pass 'a bogus target exits non-zero'
else
   fail 'a bogus target unexpectedly exited 0'
fi
n_err="$(leftover_temp_dirs "${err_tmp}")"
if [ "${n_err}" -eq 0 ]; then
   pass 'error exit leaves no leaked temp directory'
else
   fail "error exit leaked ${n_err} temp director(y/ies) under TMPDIR"
fi

## --- normal run must not leak (and the trap must not fire mid-run) ------------
ok_tmp="${work_dir}/tmp-ok"
mkdir --parents -- "${ok_tmp}"
rc=0
(
   cd -- "${pkg_dir}" \
   && env TMPDIR="${ok_tmp}" "${genmkfile_bin}" help
) > "${work_dir}/ok.log" 2>&1 || rc=$?
if [ "${rc}" -eq 0 ]; then
   pass 'a normal run (help) exits 0'
else
   fail "a normal run (help) exited ${rc}: $(tail -4 -- "${work_dir}/ok.log")"
fi
n_ok="$(leftover_temp_dirs "${ok_tmp}")"
if [ "${n_ok}" -eq 0 ]; then
   pass 'normal run leaves no leaked temp directory'
else
   fail "normal run leaked ${n_ok} temp director(y/ies) under TMPDIR"
fi

printf '%s\n' "" "${checks} check(s), ${failures} failure(s)"
if [ "${failures}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: genmkfile_temp_dir is cleaned up on every exit path'
exit 0
