#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Fast source-tarball reproducibility check: proves the normalize-symlinks +
## dm-prepare-release path yields a BYTE-IDENTICAL source tarball across the two
## host kinds AND across two independent clones -- in seconds, with no full
## build. A full '--target source' build hits the whole git_sanity_test /
## pristine-tree machinery (signed commits, ephemeral tags, cruft) and even a
## pinned-submodule unicode byte; this exercises exactly the reproducibility
## contract instead.
##
## Two independent variables that USED to break it, both asserted here:
##   - symlink FORM: a plain-Debian (core.symlinks=true) checkout has real
##     symlinks; a Kicksecure (core.symlinks=false) one has text placeholders.
##     normalize_symlinks_in_tree flattens the first to match the second.
##   - .git: clone-dependent (pack order, refs, logs); dm-prepare-release must
##     exclude it or two clones never match.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

dm_dir="${DERIVATIVE_MAKER_DIR:-${HOME}/derivative-maker}"
prepare="${DM_PREPARE_BUILD_MACHINE:-${dm_dir}/build-steps.d/1200_prepare-build-machine}"
release="${DM_PREPARE_RELEASE:-${dm_dir}/packages/kicksecure/developer-meta-files/usr/bin/dm-prepare-release}"
for f in "${prepare}" "${release}"; do
   if [ ! -r "${f}" ]; then
      printf '%s\n' "FATAL: not readable: ${f} (set DERIVATIVE_MAKER_DIR)." >&2
      exit 1
   fi
done
for tool in xz strip-nondeterminism; do
   if ! type -P "${tool}" >/dev/null; then
      printf '%s\n' "FATAL: required tool '${tool}' not found." >&2
      exit 1
   fi
done

## The reproducibility CONTRACT the tarball step must keep (asserted against the
## real dm-prepare-release, so a regression that drops one is caught).
for token in "--exclude='.git'" "--sort=name" "--owner=0" "--numeric-owner" "--mtime=" "strip-nondeterminism"; do
   if grep --quiet --fixed-strings -- "${token}" "${release}"; then
      pass "dm-prepare-release keeps the reproducibility flag: ${token}"
   else
      fail "dm-prepare-release lost the reproducibility flag: ${token}"
   fi
done

workdir=""
cleanup() {
   [ -z "${workdir}" ] || safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT
workdir="$(mktemp --directory)"

git_x() {
   git -c core.hooksPath=/dev/null -c protocol.file.allow=always "$@"
}

## Fixture: a symlink in the parent AND in a submodule, plus a real .gitignore
## (a source file that must SURVIVE the .git exclusion).
sub="${workdir}/sub"
git_x init --quiet -- "${sub}"
git_x -C "${sub}" config user.email 'test@example.com'
git_x -C "${sub}" config user.name 'test'
printf '%s\n' 'payload' > "${sub}/real.txt"
ln --symbolic -- real.txt "${sub}/sublink"
git_x -C "${sub}" add --all
git_x -C "${sub}" commit --quiet --message 'sub'

origin="${workdir}/origin"
git_x init --quiet -- "${origin}"
git_x -C "${origin}" config user.email 'test@example.com'
git_x -C "${origin}" config user.name 'test'
mkdir --parents -- "${origin}/branding"
printf 'PNG\n' > "${origin}/branding/logo.png"
ln --symbolic -- logo.png "${origin}/branding/logo_installer.png"
printf 'cruft\n' > "${origin}/.gitignore"
git_x -C "${origin}" add --all
git_x -C "${origin}" submodule add --quiet -- "${sub}" pkg/testpkg
git_x -C "${origin}" commit --quiet --message 'origin'

run_normalize() {
   local clone="$1"
   (
      set -o errexit
      set -o nounset
      set -o pipefail
      # shellcheck disable=SC2317
      safe-rm() { command rm "$@"; }
      source_code_folder_dist="${clone}"
      # shellcheck disable=SC1090
      source <(sed -n \
         -e '/^normalize-symlinks() {/,/^}/p' \
         -e '/^normalize_file_modes_in_tree() {/,/^}/p' \
         -e '/^normalize_symlinks_in_tree() {/,/^}/p' \
         -- "${prepare}")
      normalize-symlinks
   )
}

## The REAL tarball flags from dm-prepare-release.
make_tarball() {
   local tree="$1" out="$2"
   tar \
      --create \
      --owner=0 --group=0 --numeric-owner \
      --mode=go=rX,u+rw,a-s \
      --sort=name \
      --sparse \
      --mtime="@1700000000" \
      --exclude='.git' \
      --directory="$(dirname -- "${tree}")" \
      --file - \
      "$(basename -- "${tree}")" \
      | xz > "${out}"
   strip-nondeterminism "${out}"
}

## Two INDEPENDENT clones -> different .git; different host kinds -> different
## symlink form. Normalise + tar both; they must converge.
for host in true false; do
   git_x -c core.symlinks="${host}" clone --quiet --recurse-submodules \
      -- "${origin}" "${workdir}/h_${host}"
   run_normalize "${workdir}/h_${host}"
   mv -- "${workdir}/h_${host}" "${workdir}/derivative-maker"
   make_tarball "${workdir}/derivative-maker" "${workdir}/src_${host}.tar.xz"
   mv -- "${workdir}/derivative-maker" "${workdir}/h_${host}"
done

members="$(tar --list --file "${workdir}/src_true.tar.xz")"
case "${members}" in
   *"/.git/"*|*"/.git"$'\n'*)
      fail ".git leaked into the source tarball (non-reproducible across clones)"
      ;;
   *)
      pass ".git is excluded from the source tarball"
      ;;
esac
case "${members}" in
   *".gitignore"*)
      pass ".gitignore (a source file) is kept, not swept by the .git exclusion"
      ;;
   *)
      fail ".gitignore was wrongly excluded"
      ;;
esac
if cmp --silent "${workdir}/src_true.tar.xz" "${workdir}/src_false.tar.xz"; then
   pass "source tarball is byte-identical across host kinds AND clones"
else
   fail "source tarball differs across host kinds/clones -- not reproducible"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: source tarball reproducibility."
