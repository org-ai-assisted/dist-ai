#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for developer-meta-files 'dm-prepare-release': how it locates
## the derivative-maker source tree when run as the INSTALLED copy.
##
## THE BUG IT GUARDS: run from /usr/bin -- which is what a bare
## 'dm-prepare-release' on PATH resolves to, and what dm-build-official-one's
## Phase 4 invokes -- it hardcoded "$HOME/derivative-maker" (the source carried
## an "XXX: hardcoded path" note). A build whose checkout lives anywhere else
## therefore ran to completion and then died in the RELEASE phase on a bare
##   dm-prepare-release: line 35: .../help-steps/pre: No such file or directory
## from bash's 'source' -- after the entire build. Observed with the tree at
## /workspace in the derivative-maker container.
##
## The fix is an ordered resolution, so this asserts the ORDER, not one path.
##
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

## The derivative-maker checkout under test. An explicitly named tree is the ONLY
## answer: falling back to '~/derivative-maker' reports on a DIFFERENT tree than
## the caller asked about, and a stale checkout there then reads as a defect in
## the code under test rather than as a stale checkout.
if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
   dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
   dm_checkout="${HOME}/derivative-maker"
fi

pass() {
   printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
   printf '%s\n' "FAIL: $*" >&2
   test_failures=$((test_failures + 1))
}

subject=""
for candidate in "${DM_PREPARE_RELEASE:-}" \
   "${DEVELOPER_META_FILES_DIR:-}/usr/bin/dm-prepare-release" \
   "${dm_checkout}/packages/kicksecure/developer-meta-files/usr/bin/dm-prepare-release" \
   "/usr/bin/dm-prepare-release"; do
   [ -n "${candidate}" ] || continue
   if [ -r "${candidate}" ]; then
      subject="${candidate}"
      break
   fi
done
if [ -z "${subject}" ]; then
   printf '%s\n' "SKIP: dm-prepare-release not found (set DM_PREPARE_RELEASE)." >&2
   exit 77
fi

## The resolution now lives in ONE shared library, so that is what carries the
## order; each tool is checked for USING it rather than for repeating it.
lib=""
for candidate in "$(dirname -- "$(dirname -- "${subject}")")/libexec/developer-meta-files/source-tree-lib.bsh" \
   "${DEVELOPER_META_FILES_DIR:-}/usr/libexec/developer-meta-files/source-tree-lib.bsh"; do
   if [ -r "${candidate}" ]; then
      lib="${candidate}"
      break
   fi
done
if [ -z "${lib}" ]; then
   fail "source-tree-lib.bsh not found; the shared resolver is what every tool depends on"
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
pass "shared resolver source-tree-lib.bsh exists"

block="$(sed -n '/^derivative_maker_source_tree_resolve()/,/^}/p' -- "${lib}")"
if [ -z "${block}" ]; then
   printf '%s\n' "FAILED: could not extract derivative_maker_source_tree_resolve." >&2
   exit 1
fi

## --- the hardcoded path must no longer be the only answer ------------------
case "${block}" in
   *'source_code_folder_dist'*)
      pass "resolver consults source_code_folder_dist, the build's own variable"
      ;;
   *)
      fail "resolver ignores source_code_folder_dist, so a tree outside \$HOME cannot be found"
      ;;
esac

## Order matters: the build's own variable must win over the convention.
authoritative_at="$(printf '%s\n' "${block}" | grep --line-number --max-count=1 -- 'source_code_folder_dist' | cut -d: -f1 || true)"
fallback_at="$(printf '%s\n' "${block}" | grep --line-number --max-count=1 --extended-regexp -- '\$\{?HOME\}?/derivative-maker' | cut -d: -f1 || true)"
if [ -n "${authoritative_at}" ] && [ -n "${fallback_at}" ]; then
   if [ "${authoritative_at}" -lt "${fallback_at}" ]; then
      pass "source_code_folder_dist is consulted BEFORE the \$HOME convention"
   else
      fail "the \$HOME convention is consulted first, so it wins even when the build named the tree"
   fi
else
   fail "could not locate both branches (authoritative='${authoritative_at}' fallback='${fallback_at}')"
fi

## --- CANARY: the conventional fallback must still exist --------------------
if printf '%s\n' "${block}" | grep --quiet --extended-regexp -- '\$\{?HOME\}?/derivative-maker'; then
   pass "canary: the ~/derivative-maker convention is still honoured as a fallback"
else
   fail "canary broken: the conventional location was removed, not deprioritised"
fi

## --- a missing tree must be NAMED, not surfaced as a bash sourcing error ---
case "${block}" in
   *'no derivative-maker source tree at'*)
      pass "an unresolvable tree fails with a named error"
      ;;
   *)
      fail "an unresolvable tree still reaches 'source' and dies on bash's 'No such file or directory', after the whole build"
      ;;
esac
case "${block}" in
   *"Set 'source_code_folder_dist'"*)
      pass "the error says what to set"
      ;;
   *)
      fail "the error does not say how to fix it"
      ;;
esac

## --- every build-path tool must USE the resolver, not repeat the assumption -
## These two are what dm-build-official-one's Phase 4 invokes as the INSTALLED
## copies, so they are the ones a build actually depends on.
tool_dir="$(dirname -- "${subject}")"
for tool_name in dm-prepare-release dm-upload-images; do
   tool="${tool_dir}/${tool_name}"
   if [ ! -r "${tool}" ]; then
      fail "${tool_name} not found beside ${subject}"
      continue
   fi
   if grep --quiet --fixed-strings -- 'derivative_maker_source_tree_resolve' "${tool}"; then
      pass "${tool_name} uses the shared resolver"
   else
      fail "${tool_name} does not use the shared resolver"
   fi
   ## A leftover hardcoded source line is the actual defect, so look for that
   ## rather than for the string appearing anywhere (comments explain it).
   if grep --quiet --extended-regexp -- '^[[:space:]]*source[[:space:]]+"?\$\{?HOME\}?/derivative-maker' "${tool}"; then
      fail "${tool_name} still sources from a hardcoded \$HOME/derivative-maker"
   else
      pass "${tool_name} sources nothing from a hardcoded \$HOME/derivative-maker"
   fi
done

## --- the resolver must be sourced BEFORE the tool's own 'cd' ---------------
## Its cwd branch is captured at source time, so a tool that cd's first offers it
## /usr/bin instead of the tree and the branch can never fire. dm-upload-images
## did exactly that, and the whole release phase failed on it.
for tool_name in dm-prepare-release dm-upload-images; do
   tool="${tool_dir}/${tool_name}"
   [ -r "${tool}" ] || continue
   source_at="$(grep --line-number --max-count=1 -- 'source-tree-lib.bsh' "${tool}" | cut -d: -f1 || true)"
   cd_at="$(grep --line-number --max-count=1 --extended-regexp -- '^[[:space:]]*cd -- ' "${tool}" | cut -d: -f1 || true)"
   if [ -z "${source_at}" ]; then
      fail "${tool_name} never sources source-tree-lib.bsh"
   elif [ -z "${cd_at}" ]; then
      pass "${tool_name} never cd's, so the resolver's cwd branch is unaffected"
   elif [ "${source_at}" -lt "${cd_at}" ]; then
      pass "${tool_name} sources the resolver before its own cd"
   else
      fail "${tool_name} cd's (line ${cd_at}) before sourcing the resolver (line ${source_at}); the cwd branch would see that directory, not the tree"
   fi
done

## --- behavioural: the cwd branch actually resolves a tree ------------------
## The regression was silent: every branch missed and the tool reported an
## unresolvable tree even though cwd WAS a checkout.
fake_tree="$(mktemp --directory)"
mkdir --parents -- "${fake_tree}/help-steps"
printf '%s\n' '## stub' > "${fake_tree}/help-steps/pre"
resolved="$(cd -- "${fake_tree}" && env --unset=source_code_folder_dist bash -c '
   source "$1"
   derivative_maker_source_tree_resolve /usr/bin || exit 1
   printf "%s\n" "${derivative_maker_source_code_dir}"
' _ "${lib}" 2>&1 || true)"
if [ "${resolved}" = "${fake_tree}" ]; then
   pass "cwd branch resolves a checkout in the invocation directory"
else
   fail "cwd branch did not resolve the invocation directory: got '${resolved}', wanted '${fake_tree}'"
fi
safe-rm --recursive --force -- "${fake_tree}"

## --- a copy INSIDE a tree binds to that tree, and nothing else -------------
## dm-prepare-release signs release artifacts, so a copy that lives in a checkout
## must operate on THAT checkout. If it honoured $source_code_folder_dist it
## could sign artifacts from a different tree than the code doing the signing.
real_root="$(mktemp --directory)"
other_tree="$(mktemp --directory)"
mkdir --parents -- "${real_root}/help-steps" "${other_tree}/help-steps" \
   "${real_root}/packages/kicksecure/developer-meta-files/usr/bin"
printf '%s\n' '## stub' > "${real_root}/help-steps/pre"
printf '%s\n' '## stub' > "${other_tree}/help-steps/pre"

resolved="$(env source_code_folder_dist="${other_tree}" bash -c '
   source "$1"
   derivative_maker_source_tree_resolve "$2" || exit 1
   printf "%s\n" "${derivative_maker_source_code_dir}"
' _ "${lib}" "${real_root}/packages/kicksecure/developer-meta-files/usr/bin" 2>&1 || true)"
if [ "${resolved}" = "${real_root}" ]; then
   pass "a copy inside a tree binds to THAT tree, ignoring source_code_folder_dist"
else
   fail "in-tree copy resolved to '${resolved}', wanted '${real_root}'"
fi

## --- a copy NOT inside a tree must fall through -----------------------------
## A standalone developer-meta-files checkout has the same '<repo>/usr/bin' shape
## with no tree above it. Treating the shape alone as in-tree bound the resolver
## to an unrelated directory and made every later source unreachable -- so an
## operator who correctly set source_code_folder_dist was still refused.
standalone="$(mktemp --directory)"
mkdir --parents -- "${standalone}/usr/bin"
resolved="$(env source_code_folder_dist="${other_tree}" bash -c '
   source "$1"
   derivative_maker_source_tree_resolve "$2" || exit 1
   printf "%s\n" "${derivative_maker_source_code_dir}"
' _ "${lib}" "${standalone}/usr/bin" 2>&1 || true)"
if [ "${resolved}" = "${other_tree}" ]; then
   pass "a copy NOT inside a tree falls through to source_code_folder_dist"
else
   fail "standalone copy resolved to '${resolved}', wanted '${other_tree}'"
fi
safe-rm --recursive --force -- "${real_root}" "${other_tree}" "${standalone}"

## --- behavioural: an unresolvable tree exits non-zero, and says so ----------
## Run the real script with HOME pointed at an empty dir, no source_code_folder_dist,
## and a cwd that is not a checkout: every branch must miss.
workdir="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${workdir}"
}
trap cleanup EXIT

rc=0
out="$(cd -- "${workdir}" && env --unset=source_code_folder_dist HOME="${workdir}" \
   bash -- "${subject}" --target source 2>&1)" || rc="$?"
if [ "${rc}" -ne 0 ]; then
   pass "unresolvable tree: exits non-zero (${rc})"
else
   fail "unresolvable tree: exited 0"
fi
case "${out}" in
   *"No such file or directory"*)
      fail "unresolvable tree: still surfaces bash's raw sourcing error -- ${out}"
      ;;
   *"no derivative-maker source tree at"*)
      pass "unresolvable tree: reports the named error, not a raw sourcing failure"
      ;;
   *)
      fail "unresolvable tree: unexpected output -- ${out}"
      ;;
esac

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: prepare-release tree location."
