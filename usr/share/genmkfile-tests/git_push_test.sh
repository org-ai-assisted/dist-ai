#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Drives the REAL `genmkfile git-push` target (the tag-less sibling of
## git-tag-push) against throwaway repos + bare remotes. Asserts:
##   - it pushes a branch with NO tag at tip, in a NON-package repo
##     (no debian/control), proving it is exempt from make_get_variables;
##   - a re-run with nothing changed is a NO-OP -- it skips a remote whose
##     tracking ref already equals the local tip and invokes NO `git push`
##     (the anti-hammer guarantee);
##   - only a genuinely-behind remote is pushed when the tip advances;
##   - missing-remote and detached-HEAD inputs error loudly.
## No root, no network (remotes are local bare repos).

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
git -C "${repo}" config user.email a@b.c
git -C "${repo}" config user.name a
git -C "${repo}" commit -q --allow-empty -m c1
git init -q --bare "${test_root}/r1.git"
git init -q --bare "${test_root}/r2.git"
git -C "${repo}" remote add org-ai-assisted "${test_root}/r1.git"
git -C "${repo}" remote add gitlab-adrelanos "${test_root}/r2.git"

tests_total=0
tests_failed=0
pass() { printf '%s\n' "PASS  $1"; }
fail() { tests_failed=$(( tests_failed + 1 )); printf '%s\n' "FAIL  $1" >&2; }
count() { tests_total=$(( tests_total + 1 )); }

## Run `genmkfile git-push` inside ${repo}; echo combined output.
run_push() {
   ( cd -- "${repo}" \
     && make_git_push_remotes="$1" make_git_push_branches="$2" \
        "${genmkfile_bin}" git-push ) 2>&1
}

remote_tip() { git --git-dir="$1" rev-parse --verify --quiet ai || true; }

## T1: first push, no tag, non-package repo -> both remotes get ai.
count
out="$(run_push "org-ai-assisted gitlab-adrelanos" "ai" || true)"
loc="$(git -C "${repo}" rev-parse ai)"
if [ "$(remote_tip "${test_root}/r1.git")" = "${loc}" ] \
   && [ "$(remote_tip "${test_root}/r2.git")" = "${loc}" ]; then
   pass 'T1 pushes branch (no tag) to all remotes in a non-package repo'
else
   fail "T1 remotes not at local tip; out=[${out}]"
fi

## T2: re-run with nothing changed -> skip, and NO `git push` invoked.
count
out="$(run_push "org-ai-assisted gitlab-adrelanos" "ai" || true)"
if [[ "${out}" == *'already at remote'* ]] \
   && [[ "${out}" != *'git push --atomic'* ]]; then
   pass 'T2 up-to-date re-run is a no-op (anti-hammer: no git push)'
else
   fail "T2 did not skip cleanly; out=[${out}]"
fi

## T3: advance tip -> the behind remote IS pushed.
count
git -C "${repo}" commit -q --allow-empty -m c2
out="$(run_push "org-ai-assisted gitlab-adrelanos" "ai" || true)"
loc="$(git -C "${repo}" rev-parse ai)"
if [ "$(remote_tip "${test_root}/r1.git")" = "${loc}" ] \
   && [[ "${out}" == *'git push --atomic'* ]]; then
   pass 'T3 advanced tip is pushed'
else
   fail "T3 advanced tip not pushed; out=[${out}]"
fi

## T4: default branch = current branch when make_git_push_branches unset.
count
if ( cd -- "${repo}" && make_git_push_remotes="org-ai-assisted" "${genmkfile_bin}" git-push ) >/dev/null 2>&1; then
   pass 'T4 defaults to the current branch'
else
   fail 'T4 default-current-branch push failed'
fi

## T5: a missing remote errors loudly.
count
if run_push "does-not-exist" "ai" >/dev/null 2>&1; then
   fail 'T5 missing remote did not error'
else
   pass 'T5 missing remote errors'
fi

## T6: detached HEAD with no branch given errors loudly.
count
git -C "${repo}" checkout -q --detach
if ( cd -- "${repo}" && make_git_push_remotes="org-ai-assisted" "${genmkfile_bin}" git-push ) >/dev/null 2>&1; then
   fail 'T6 detached HEAD did not error'
else
   pass 'T6 detached HEAD errors'
fi
git -C "${repo}" checkout -q ai

## T7: inside a cowbuilder build shell (make_use_cowbuilder=true) git-push must
## NOT demand make_cowbuilder_dist_folder -- it is a pure git op needing no
## DISTDIR/DESTDIR, so make_get_distdir's cowbuilder gate must not run for it.
count
if ( cd -- "${repo}" && make_use_cowbuilder=true \
      make_git_push_remotes="org-ai-assisted" make_git_push_branches="ai" \
      "${genmkfile_bin}" git-push ) >/dev/null 2>&1; then
   pass 'T7 git-push ignores make_use_cowbuilder (no DISTDIR demanded)'
else
   fail 'T7 git-push tripped on cowbuilder config'
fi

## T8: a trailing '--' / '' argv token must not poison target classification --
## git-push stays a pure git op (no make_get_variables on a non-package repo).
count
if ( cd -- "${repo}" && make_git_push_remotes="org-ai-assisted" make_git_push_branches="ai" \
      "${genmkfile_bin}" git-push -- ) >/dev/null 2>&1; then
   pass 'T8 git-push tolerates a trailing -- (no make_get_variables abort)'
else
   fail 'T8 git-push -- aborted (classifier poison)'
fi

## T9: a NEWLINE-separated make_git_push_remotes (e.g. from "$(git remote)") must push
## ALL remotes, not just the first. Regression: read -a on a here-string stops at the
## first newline, silently dropping every remote after line 1 (no push, no error).
count
git -C "${repo}" commit -q --allow-empty -m c3
nl_remotes="$(printf '%s\n%s' org-ai-assisted gitlab-adrelanos)"
out="$(run_push "${nl_remotes}" "ai" || true)"
loc="$(git -C "${repo}" rev-parse ai)"
if [ "$(remote_tip "${test_root}/r1.git")" = "${loc}" ] \
   && [ "$(remote_tip "${test_root}/r2.git")" = "${loc}" ]; then
   pass 'T9 newline-separated remotes are all pushed (no silent drop)'
else
   fail "T9 newline-separated remotes not all at tip (r2 dropped?); out=[${out}]"
fi

if [ "${tests_failed}" -ne 0 ]; then
   printf '%s\n' "git_push_test: ${tests_failed}/${tests_total} FAILED" >&2
   exit 1
fi
printf '%s\n' "git_push_test: ${tests_total} pass, 0 fail, 0 skip"
