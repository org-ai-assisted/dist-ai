#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression guard for the "make_source_package_name: unbound variable"
## abort on the `genmkfile git-tag-push` path.
##
## git-tag-push is classified __git_only, so make_get_variables (which sets
## make_source_package_name from debian/changelog) is deliberately skipped.
## make_git_push_shared with-tags then runs make_git_tag_shared, which reads
## ${make_source_package_name} under `set -o nounset` -- aborting unless the
## dispatcher initialized the label up front. Drives the REAL genmkfile
## against a throwaway non-package repo + bare remote and asserts the abort is
## gone and the branch+tag actually push. No root, no network, no gpg.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Resolve the genmkfile binary under test. The runner exports GENMKFILE_BIN;
## fall back to a derivative-maker checkout.
locate_genmkfile() {
   local candidate
   for candidate in \
      "${GENMKFILE_BIN:-}" \
      "${HOME:-}/derivative-maker/packages/kicksecure/genmkfile/usr/bin/genmkfile"
   do
      [ -n "${candidate}" ] || continue
      if test -x "${candidate}"; then
         printf '%s\n' "${candidate}"
         return 0
      fi
   done
   return 1
}

if ! genmkfile_bin="$(locate_genmkfile)"; then
   ## genmkfile is the REQUIRED unit under test; absent = env bug, not a skip.
   printf '%s\n' 'FATAL: genmkfile binary not found (set GENMKFILE_BIN).' >&2
   exit 1
fi

## Capability gate: this suite tests the genmkfile CHECKOUT (wired via GENMKFILE_BIN). If
## nothing was wired and only the installed /usr/bin/genmkfile resolved -- which drifts from the
## tree under review -- SKIP rather than report a confusing FAIL against a possibly-stale
## subject nobody is changing.
if [ -z "${GENMKFILE_BIN:-}" ] && [ "${genmkfile_bin}" = "/usr/bin/genmkfile" ]; then
   printf '%s\n' "SKIP: no genmkfile checkout wired (set GENMKFILE_BIN); not testing the installed copy." >&2
   exit 77  ## style-ok: allow-skip: no wired checkout -> subject not under review, not a regression
fi

if ! test -r /usr/libexec/helper-scripts/parallel.bsh; then
   ## helper-scripts is a REQUIRED runtime dep of the target; absent = env bug.
   printf '%s\n' 'FATAL: helper-scripts parallel.bsh missing (required dependency).' >&2
   exit 1
fi

test_root="$(mktemp --directory)"
# shellcheck disable=SC2317
cleanup() { safe-rm -r -f -- "${test_root}"; }
trap cleanup EXIT

repo="${test_root}/repo"
mkdir -p -- "${repo}"
git -C "${repo}" init -q -b ai
## Neutralize the operator's global hooksPath: genmkfile's internal `git push`
## runs inside this repo and would otherwise trip a wrong-target pre-push guard
## on the throwaway bare remote below. This fixture tests genmkfile, not the
## operator's hooks.
git -C "${repo}" config core.hooksPath /dev/null
git -C "${repo}" config user.email a@b.c
git -C "${repo}" config user.name a
git -C "${repo}" commit -q --allow-empty -m c1
## git-tag-push pushes the tag(s) at the branch tip; a lightweight tag is
## enough to exercise the path (signing is a separate target).
git -C "${repo}" tag t1
git init -q --bare "${test_root}/r1.git"
git -C "${repo}" remote add org-ai-assisted "${test_root}/r1.git"

tests_total=0
tests_failed=0
pass() { printf '%s\n' "PASS  $1"; }
fail() { tests_failed=$(( tests_failed + 1 )); printf '%s\n' "FAIL  $1" >&2; }
count() { tests_total=$(( tests_total + 1 )); }

remote_ref() { git --git-dir="${test_root}/r1.git" rev-parse --verify --quiet "$1" || true; }

## Run the REAL git-tag-push in the non-package repo; capture output + rc.
rc=0
out="$( cd -- "${repo}" \
   && make_git_push_remotes="org-ai-assisted" make_git_push_branches="ai" \
      "${genmkfile_bin}" git-tag-push 2>&1 )" || rc=$?

## T1: the regression -- the unbound-variable abort must not appear.
count
if [[ "${out}" == *'make_source_package_name: unbound variable'* ]]; then
   fail "T1 git-tag-push still aborts on unbound make_source_package_name; out=[${out}]"
else
   pass 'T1 git-tag-push does not abort on unbound make_source_package_name'
fi

## T2: the full __git_only path succeeds (proves it is not merely a different
## silent failure) -- branch and tag both land on the remote.
count
loc="$(git -C "${repo}" rev-parse ai)"
if [ "${rc}" -eq 0 ] \
   && [ "$(remote_ref 'refs/heads/ai')" = "${loc}" ] \
   && [ "$(remote_ref 'refs/tags/t1^{commit}')" = "${loc}" ]; then
   pass 'T2 git-tag-push pushes branch + tag in a non-package repo'
else
   fail "T2 git-tag-push did not push branch+tag (rc=${rc}); out=[${out}]"
fi

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "git_tag_push_unbound_source_name_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "git_tag_push_unbound_source_name_test: ${tests_total} pass, 0 fail, 0 skip"
