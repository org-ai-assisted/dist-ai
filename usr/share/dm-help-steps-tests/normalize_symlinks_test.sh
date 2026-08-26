#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'build-steps.d/1200_prepare-build-machine'
## normalize-symlinks (with normalize_symlinks_in_tree + normalize_file_modes_in_tree).
##
## THE BUG IT GUARDS: on a core.symlinks=false host -- the Kicksecure/Whonix
## DEFAULT (security-misc-shared /etc/gitconfig) and so a very likely build host --
## git checks a mode 120000 symlink out as a REGULAR text file holding the target
## path. The build MUST materialise it back into a real symlink, or the same commit
## ships a different image on different hosts (a text file where a real branding
## symlink belongs, e.g. live-build-data/d-i-branding/logo_installer.png). A 2026
## refactor silently reversed the normaliser into a real->text 'find -type l'
## no-op -- which does NOTHING on exactly those core.symlinks=false hosts, and
## leaves core.symlinks=true (CI) trees dirty. This test drives the SHIPPED
## functions and fails if the direction regresses again.
##
## Drives the real functions against throwaway git repos; no root, no network.
## Asserts BOTH directions and the reproducibility the fix exists for:
##   - fixture canary: a core.symlinks=false clone materialises the symlink as a
##     REGULAR FILE (the bug is genuinely reproduced)
##   - after normalise: it is a REAL symlink, in the parent AND in a submodule
##   - git status stays CLEAN (no 'unexplained dirty tree')
##   - reproducibility: a core.symlinks=true clone normalises to a byte-identical tree
##   - file MODES are normalised to git's recorded mode (0640 -> 0644)

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

prepare=""
for candidate in "${DM_PREPARE_BUILD_MACHINE:-}" \
   "${DERIVATIVE_MAKER_DIR:-}/build-steps.d/1200_prepare-build-machine" \
   "${dm_checkout}/build-steps.d/1200_prepare-build-machine"; do
   case "${candidate}" in
      ''|'/build-steps.d/1200_prepare-build-machine')
         continue
         ;;
   esac
   if [ -r "${candidate}" ]; then
      prepare="${candidate}"
      break
   fi
done

if [ -z "${prepare}" ]; then
   printf '%s\n' "FATAL: no derivative-maker build-steps.d/1200_prepare-build-machine found." >&2
   exit 1
fi

for fn in 'normalize-symlinks()' 'normalize_symlinks_in_tree()' 'normalize_file_modes_in_tree()'; do
   if grep --quiet --fixed-strings "${fn}" "${prepare}"; then
      pass "1200 defines ${fn}"
   else
      fail "1200 does not define ${fn} (regressed?)"
   fi
done

## Must be dispatched from main; a defined-but-uncalled normaliser is dead code.
if grep --quiet --extended-regexp '^ +normalize-symlinks "\$@"' "${prepare}"; then
   pass "normalize-symlinks is called from main"
else
   fail "normalize-symlinks is defined but never called from main"
fi

workdir=""
cleanup() {
   [ -z "${workdir}" ] || safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT
workdir="$(mktemp --directory)"

## -c core.hooksPath=/dev/null: not testing the operator's hooks.
## -c protocol.file.allow=always: local file:// submodule add on modern git.
git_x() {
   git -c core.hooksPath=/dev/null -c protocol.file.allow=always "$@"
}

## --- fixtures: an origin with a symlink + a submodule with a symlink ----------
sub="${workdir}/sub"
git_x init --quiet -- "${sub}"
git_x -C "${sub}" config user.email 'test@example.com'
git_x -C "${sub}" config user.name 'test'
printf '%s\n' 'payload' > "${sub}/real.txt"
ln --symbolic -- real.txt "${sub}/sublink"
git_x -C "${sub}" add --all
git_x -C "${sub}" commit --quiet --message 'submodule with a symlink'

origin="${workdir}/origin"
git_x init --quiet -- "${origin}"
git_x -C "${origin}" config user.email 'test@example.com'
git_x -C "${origin}" config user.name 'test'
mkdir --parents -- "${origin}/live-build-data/d-i-branding"
printf 'PNG\n' > "${origin}/live-build-data/d-i-branding/logo_debian.png"
ln --symbolic -- logo_debian.png "${origin}/live-build-data/d-i-branding/logo_installer.png"
printf 'exec\n' > "${origin}/an_executable"
chmod 0755 "${origin}/an_executable"
git_x -C "${origin}" add --all
git_x -C "${origin}" update-index --chmod=+x an_executable
git_x -C "${origin}" submodule add --quiet -- "${sub}" packages/kicksecure/testpkg
git_x -C "${origin}" commit --quiet --message 'parent with a symlink + a submodule'

## Extract and run the SHIPPED normaliser functions against a clone.
run_normalize() {
   local clone="$1"
   (
      set -o errexit
      set -o nounset
      set -o pipefail
      ## safe-rm is a helper-scripts tool that may be absent in the test image;
      ## the function under test only uses it to remove a file it just read.
      ## Called indirectly by the sourced normalise functions.
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

logo='live-build-data/d-i-branding/logo_installer.png'
sublink='packages/kicksecure/testpkg/sublink'

## --- core.symlinks=false clone: the bug host --------------------------------
false_clone="${workdir}/host_false"
git_x -c core.symlinks=false clone --quiet --recurse-submodules -- "${origin}" "${false_clone}"
git_x -C "${false_clone}" config core.symlinks false
git_x -C "${false_clone}" submodule foreach --quiet 'git config core.symlinks false' >/dev/null 2>&1 || true

## CANARY: the fixture must actually reproduce the bug -- a regular file, not a link.
if [ -L "${false_clone}/${logo}" ]; then
   fail "canary: core.symlinks=false clone produced a real symlink; this git cannot reproduce the bug"
else
   pass "canary: core.symlinks=false clone materialised the symlink as a regular file"
fi

run_normalize "${false_clone}"

if [ -L "${false_clone}/${logo}" ]; then
   pass "after normalise: parent symlink is a REAL symlink"
else
   fail "after normalise: parent symlink is still a regular file (real->text regression)"
fi
if [ -L "${false_clone}/${sublink}" ]; then
   pass "after normalise: SUBMODULE symlink is a REAL symlink"
else
   fail "after normalise: submodule symlink not materialised (submodules skipped?)"
fi

false_status="$(git_x -C "${false_clone}" status --porcelain)"
if [ -z "${false_status}" ]; then
   pass "after normalise: git status is clean on the core.symlinks=false clone"
else
   fail "after normalise: dirty tree on core.symlinks=false clone: ${false_status}"
fi

## --- core.symlinks=true clone: normalise must converge to the same tree ------
true_clone="${workdir}/host_true"
git_x -c core.symlinks=true clone --quiet --recurse-submodules -- "${origin}" "${true_clone}"
git_x -C "${true_clone}" config core.symlinks true
git_x -C "${true_clone}" submodule foreach --quiet 'git config core.symlinks true' >/dev/null 2>&1 || true
run_normalize "${true_clone}"

if diff --recursive --no-dereference --exclude='.git' -- "${true_clone}" "${false_clone}" >/dev/null 2>&1; then
   pass "reproducible: core.symlinks true and false clones normalise to identical trees"
else
   fail "not reproducible: the two hosts' trees differ after normalise"
fi

## --- file MODE normalisation -------------------------------------------------
## Recheck out with a restrictive umask does not apply retroactively, so force a
## non-recorded mode and confirm the normaliser resets it to git's recorded 0644.
chmod 0640 "${false_clone}/live-build-data/d-i-branding/logo_debian.png"
run_normalize "${false_clone}"
mode_now="$(stat --format='%a' -- "${false_clone}/live-build-data/d-i-branding/logo_debian.png")"
if [ "${mode_now}" = "644" ]; then
   pass "file mode normalised to git's recorded 0644 (was forced 0640)"
else
   fail "file mode not normalised: got 0${mode_now}, expected 0644"
fi

## --- GIT_DIR robustness: a decoy GIT_DIR must not divert the git calls -------
## An inherited GIT_DIR (e.g. exported by an enclosing 'git submodule foreach')
## must not make 'git -C <tree>' read the wrong index and skip normalisation.
decoy="${workdir}/decoy"
git_x init --quiet -- "${decoy}"
gd_clone="${workdir}/host_gitdir"
git_x -c core.symlinks=false clone --quiet --recurse-submodules -- "${origin}" "${gd_clone}"
git_x -C "${gd_clone}" config core.symlinks false
git_x -C "${gd_clone}" submodule foreach --quiet 'git config core.symlinks false' >/dev/null 2>&1 || true
( export GIT_DIR="${decoy}/.git"; run_normalize "${gd_clone}" )
if [ -L "${gd_clone}/${logo}" ]; then
   pass "materialises the symlink even with a decoy GIT_DIR set (env --unset clears it)"
else
   fail "a decoy GIT_DIR diverted the git calls; symlink left un-materialised"
fi

## --- trailing-newline blob must be left alone, not mis-converted -------------
## A mode-120000 blob whose content ends in a newline is NOT a materialised
## symlink (git writes the target with no trailing newline); it must be skipped,
## not turned into a symlink with the newline silently stripped by command sub.
nl="${workdir}/nl"
git_x init --quiet -- "${nl}"
git_x -C "${nl}" config user.email 'test@example.com'
git_x -C "${nl}" config user.name 'test'
blob_sha="$(printf 'target_with_nl\n' | git_x -C "${nl}" hash-object -w --stdin)"
git_x -C "${nl}" update-index --add --cacheinfo "120000,${blob_sha},weird"
git_x -C "${nl}" commit --quiet --message 'mode-120000 blob ending in a newline'
nl_clone="${workdir}/host_nl"
git_x -c core.symlinks=false clone --quiet -- "${nl}" "${nl_clone}"
git_x -C "${nl_clone}" config core.symlinks false
run_normalize "${nl_clone}"
if [ -L "${nl_clone}/weird" ]; then
   fail "trailing-newline blob mis-converted to a symlink (command-sub ate the newline)"
else
   pass "trailing-newline blob left as a regular file, not mis-converted"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: normalize-symlinks."
