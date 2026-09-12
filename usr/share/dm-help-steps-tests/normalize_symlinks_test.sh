#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for derivative-maker 'build-steps.d/1200_prepare-build-machine'
## normalize-symlinks.
##
## WHAT IT GUARDS: an indexed symlink (mode 120000) is checked out as a REAL
## symlink on a core.symlinks=true host (plain Debian, CI) and as a REGULAR text
## file holding the target on a core.symlinks=false host (the Kicksecure/Whonix
## default, shipped by security-misc-shared /etc/gitconfig). The SAME commit thus
## yields a different working tree per host; a build that embeds it ships
## different bytes -> not reproducible.
##
## The normaliser converts to ONE form so every builder embeds the same bytes.
## The direction is REAL SYMLINK -> TEXT PLACEHOLDER: reproducibility is
## indifferent to which form, so security decides -- an inert path-string
## placeholder cannot point outside the tree or escape a chroot the way a
## materialised symlink can. An existing placeholder (already text) keeps its
## exact bytes. This drives the SHIPPED functions and fails if the direction
## flips back to text->symlink, if a submodule is skipped, or if the placeholder
## bytes/mode become non-reproducible.
##
## Throwaway git repos; no root, no network.

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

if grep --quiet --fixed-strings 'normalize-symlinks()' "${prepare}"; then
   pass "1200 defines normalize-symlinks()"
else
   fail "1200 does not define normalize-symlinks() (regressed?)"
fi

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

## Config isolation: null the system gitconfig (so the Kicksecure host's
## /etc/gitconfig core.symlinks=false cannot MASK the true_clone's compiled-default
## symlink checkout -- a plain host has no such system setting) and point --global
## at a throwaway so nothing here touches the operator's git config.
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_CONFIG_GLOBAL="${workdir}/gitconfig-global"
touch -- "${GIT_CONFIG_GLOBAL}"

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
      ## style-ok: R-120 -- this IS the safe-rm shim; 'command rm' is the only way
      ## to implement it without recursing into itself.
      # shellcheck disable=SC2317
      safe-rm() { command rm "$@"; }
      source_code_folder_dist="${clone}"
      # shellcheck disable=SC1090
      source <(sed -n \
         -e '/^normalize-symlinks() {/,/^}/p' \
         -- "${prepare}")
      normalize-symlinks
   )
}

logo='live-build-data/d-i-branding/logo_installer.png'
sublink='packages/kicksecure/testpkg/sublink'

## --- core.symlinks=true clone: the plain-Debian host with REAL symlinks -------
## The one-shot '-c core.symlinks=true' materialises REAL symlinks at checkout but
## is NOT persisted to the clone's config -- exactly like a real plain-Debian host,
## the state normalize-symlinks must flatten to text placeholders.
true_clone="${workdir}/host_true"
git_x -c core.symlinks=true clone --quiet --recurse-submodules -- "${origin}" "${true_clone}"

## CANARY: the fixture must actually produce a REAL symlink (the state to flatten).
if [ -L "${true_clone}/${logo}" ]; then
   pass "canary: core.symlinks=true clone produced a real symlink to flatten"
else
   fail "canary: core.symlinks=true clone did not produce a real symlink; this git cannot reproduce the plain-Debian state"
fi

run_normalize "${true_clone}"

## After flattening: a TEXT placeholder, not a symlink; parent AND submodule.
if [ -L "${true_clone}/${logo}" ]; then
   fail "after normalise: parent symlink still a real symlink (text->symlink regression)"
elif [ -f "${true_clone}/${logo}" ] \
   && [ "$(cat -- "${true_clone}/${logo}")" = "logo_debian.png" ]; then
   pass "after normalise: parent symlink flattened to a text placeholder holding the target"
else
   fail "after normalise: parent symlink not a correct text placeholder"
fi
if [ -L "${true_clone}/${sublink}" ]; then
   fail "after normalise: SUBMODULE symlink still a real symlink (submodules skipped?)"
elif [ -f "${true_clone}/${sublink}" ] \
   && [ "$(cat -- "${true_clone}/${sublink}")" = "real.txt" ]; then
   pass "after normalise: SUBMODULE symlink flattened to a text placeholder"
else
   fail "after normalise: submodule symlink not a correct text placeholder"
fi

## The placeholder is the target with NO trailing newline (git's blob bytes),
## else it will not match a core.symlinks=false host's checkout.
logo_target='logo_debian.png'
if [ "$(wc --bytes < "${true_clone}/${logo}")" -eq "${#logo_target}" ]; then
   pass "placeholder has no trailing newline (byte-identical to git's mode-120000 blob)"
else
   fail "placeholder byte length wrong: a trailing newline would break reproducibility"
fi

## --- core.symlinks=false clone: the Kicksecure host, ALREADY a placeholder ----
false_clone="${workdir}/host_false"
git_x -c core.symlinks=false clone --quiet --recurse-submodules -- "${origin}" "${false_clone}"
git_x -C "${false_clone}" config core.symlinks false
git_x -C "${false_clone}" submodule foreach --quiet 'git config core.symlinks false' >/dev/null 2>&1 || true

if [ -L "${false_clone}/${logo}" ]; then
   fail "canary: core.symlinks=false clone produced a real symlink; cannot test the placeholder path"
else
   pass "canary: core.symlinks=false clone materialised the symlink as a placeholder"
fi

## An existing placeholder must keep its exact CONTENT after normalise.
before_bytes="$(cat -- "${false_clone}/${logo}")"
run_normalize "${false_clone}"
after_bytes="$(cat -- "${false_clone}/${logo}")"
if [ -L "${false_clone}/${logo}" ]; then
   fail "existing placeholder was turned into a symlink (wrong direction)"
elif [ "${before_bytes}" = "${after_bytes}" ]; then
   pass "existing placeholder content left unchanged"
else
   fail "existing placeholder content was modified: '${before_bytes}' -> '${after_bytes}'"
fi

## The Kicksecure host's tree stays CLEAN: the placeholder matches the blob.
false_status="$(git_x -C "${false_clone}" status --porcelain)"
if [ -z "${false_status}" ]; then
   pass "core.symlinks=false clone: git status clean after normalise"
else
   fail "core.symlinks=false clone: dirty tree after normalise: ${false_status}"
fi

## --- reproducibility: both host kinds converge on identical bytes ------------
if diff --recursive --no-dereference --exclude='.git' -- "${true_clone}" "${false_clone}" >/dev/null 2>&1; then
   pass "reproducible: core.symlinks true (flattened) and false (untouched) trees are byte-identical"
else
   fail "not reproducible: the two hosts' trees differ after normalise"
fi

## --- GIT_DIR robustness: a decoy GIT_DIR must not skip the flatten -----------
decoy="${workdir}/decoy"
git_x init --quiet -- "${decoy}"
gd_clone="${workdir}/host_gitdir"
git_x -c core.symlinks=true clone --quiet --recurse-submodules -- "${origin}" "${gd_clone}"
git_x -C "${gd_clone}" config core.symlinks true
git_x -C "${gd_clone}" submodule foreach --quiet 'git config core.symlinks true' >/dev/null 2>&1 || true
( export GIT_DIR="${decoy}/.git"; run_normalize "${gd_clone}" )
if [ ! -L "${gd_clone}/${logo}" ] && [ -f "${gd_clone}/${logo}" ]; then
   pass "flattens the parent symlink even with a decoy GIT_DIR set (env --unset clears it)"
else
   fail "a decoy GIT_DIR diverted the git calls; parent symlink left un-flattened"
fi
## The SUBMODULE link must flatten under the decoy too: the outer enumeration is
## a separate git call, so a regression clearing GIT_DIR only on the per-tree
## calls would flatten the parent yet skip the submodule.
if [ ! -L "${gd_clone}/${sublink}" ] && [ -f "${gd_clone}/${sublink}" ]; then
   pass "flattens the SUBMODULE symlink under a decoy GIT_DIR (outer enumeration clears it too)"
else
   fail "a decoy GIT_DIR diverted the submodule enumeration; submodule symlink left un-flattened"
fi

## --- a symlink target containing a newline must survive the flatten ----------
## readlink appends its own newline; the sentinel must strip only that, keeping
## a newline that is part of the target -- else the placeholder loses bytes.
nl_clone="${workdir}/host_nl"
git_x -c core.symlinks=true clone --quiet -- "${origin}" "${nl_clone}"
git_x -C "${nl_clone}" config core.symlinks true
target_with_nl="$(printf 'a\nb')"
ln --symbolic -- "${target_with_nl}" "${nl_clone}/weird_link"
## The normaliser only touches INDEXED (mode-120000) entries, so stage it.
git_x -C "${nl_clone}" add -- weird_link
run_normalize "${nl_clone}"
## The cat comparison strips ALL trailing newlines from both sides, so it cannot
## see an extra (or missing) trailing byte in the placeholder -- exactly the
## reproducibility regression this case guards. Add a byte-exact length check
## (like the logo placeholder test above): the placeholder must be EXACTLY the
## target bytes ('a\nb', 3 bytes), never 'a\nb\n' with readlink's own newline kept.
if [ ! -L "${nl_clone}/weird_link" ] \
   && [ "$(cat -- "${nl_clone}/weird_link")" = "${target_with_nl}" ] \
   && [ "$(wc --bytes < "${nl_clone}/weird_link")" -eq "${#target_with_nl}" ]; then
   pass "a symlink target containing a newline is flattened without losing bytes (byte-exact)"
else
   fail "a newline in the symlink target was not preserved byte-exactly by the flatten"
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: normalize-symlinks."
