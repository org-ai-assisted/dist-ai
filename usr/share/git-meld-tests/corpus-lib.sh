#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Data-driven adversarial suite backed by the git-diffs-lie corpus
## (github.com/output-lies/git-diffs-lie). Every branch there
## differs from 'master' by exactly one safe surprise; manifest.tsv states the
## expected review-tool behavior per branch. This suite regenerates the corpus
## from its own generator (no network) and asserts each row against the
## terminal-safe reviewer git-diff-review.
##
## manifest.tsv assert vocabulary:
##   neutralized <hex> -- the raw byte sequence must be ABSENT from the output
##                        (rendered inert), so it can never reach the terminal
##   failclosed   -    -- the tool must exit non-zero (refuse to render)
##   shows       <str> -- <str> must appear in the output (surprise surfaced)
##   refname     <hex> -- the BRANCH NAME is the payload; a name scan must flag it
##
## Usage: corpus-lib.sh [<dir-with-git-diff-review>]
##   GIT_DIFFS_LIE_DIR=<checkout> overrides corpus discovery.
## Exit 77 == SKIP (git-diff-review or the corpus not available).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

bindir="${1:-/usr/bin}"
gdr="${bindir}/git-diff-review"

## Discover the corpus BEFORE HOME is redirected for isolation.
real_home="${HOME}"
corpus_src="${GIT_DIFFS_LIE_DIR:-}"
if [ -z "${corpus_src}" ]; then
   for cand in \
      "${real_home}/git-diffs-lie" \
      "${real_home}/private-sources/git-diffs-lie" ; do
      if [ -f "${cand}/tools/build-corpus.sh" ]; then
         corpus_src="${cand}"
         break
      fi
   done
fi

if [ ! -x "${gdr}" ] || [ -z "${corpus_src}" ] \
   || [ ! -f "${corpus_src}/tools/build-corpus.sh" ]; then
   printf '%s\n' \
      "corpus-lib: git-diff-review or git-diffs-lie corpus missing; skipping." >&2
   exit 77
fi

## Optional name scanner for the refname cases.
unicode_show="$( command -v unicode-show || true )"
if [ -z "${unicode_show}" ] && [ -n "${HELPER_SCRIPTS_PATH:-}" ] \
   && [ -x "${HELPER_SCRIPTS_PATH}/usr/bin/unicode-show" ]; then
   unicode_show="${HELPER_SCRIPTS_PATH}/usr/bin/unicode-show"
fi

printf '%s\n' "== git-diffs-lie corpus suite =="
printf '%s\n' "  git-diff-review: ${gdr}"
printf '%s\n' "  corpus source:   ${corpus_src}"

work="$( mktemp --directory )"
export HOME="${work}/home"
mkdir --parents -- "${HOME}"
# shellcheck disable=SC2317
cleanup() { rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## Regenerate a fresh corpus from the shipped generator (self-isolating: it
## pins GIT_CONFIG_GLOBAL=/dev/null and a neutral identity).
corpus="${work}/corpus"
bash "${corpus_src}/tools/build-corpus.sh" "${corpus}" >/dev/null
cd -- "${corpus}"

fails=0
pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1" >&2; fails=$(( fails + 1 )); }

out_file="${work}/out"

## hex_to_pcre <hexpairs> -- "e280ae" -> "\xe2\x80\xae" for grep -P.
hex_to_pcre() { printf '%s' "$1" | sed 's/../\\x&/g'; }

## name_is_flagged <branch> -- true if a ref-name scan flags the branch name.
name_is_flagged() {
   if [ -n "${unicode_show}" ]; then
      printf '%s' "$1" | "${unicode_show}" >/dev/null 2>&1 && return 1 || return 0
   fi
   ## Fallback: any byte outside 7-bit ASCII is the (only) payload here.
   printf '%s' "$1" | LC_ALL=C grep --quiet --perl-regexp '[^\x00-\x7f]'
}

while IFS="$( printf '\t' )" read -r branch class assert arg _summary; do
   case "${branch}" in ''|'#'*) continue ;; esac

   if [ "${class}" = refname ]; then
      if name_is_flagged "${branch}"; then
         pass "refname flagged: ${assert} case"
      else
         fail "refname NOT flagged: ${assert} case"
      fi
      continue
   fi

   rc=0
   "${gdr}" "master..${branch}" </dev/null >"${out_file}" 2>&1 || rc=$?

   case "${assert}" in
      neutralized)
         ## Absence of the raw bytes is trivially true if the tool crashed or
         ## printed nothing, so also require a clean exit AND positive evidence
         ## the diff was actually rendered (the reviewer's per-file banner).
         ## Otherwise a broken tool would "pass" every neutralized row.
         pat="$( hex_to_pcre "${arg}" )"
         if [ "${rc}" != 0 ]; then
            fail "${branch}: tool exited ${rc}; expected a clean neutralized render"
         elif ! grep --quiet --text --fixed-strings -- 'per-file diffs' "${out_file}"; then
            fail "${branch}: no rendered diff; cannot confirm neutralization"
         else
            ## grep: 0 == found (leaked), 1 == absent (good), >=2 == grep error.
            ## Without capturing rc, a grep error (>=2) would be read as "absent".
            leak_rc=0
            LC_ALL=C grep --quiet --text --perl-regexp "${pat}" "${out_file}" || leak_rc=$?
            if [ "${leak_rc}" = 0 ]; then
               fail "${branch}: raw bytes (${arg}) LEAKED to output"
            elif [ "${leak_rc}" -ge 2 ]; then
               fail "${branch}: grep error (rc ${leak_rc}) checking for leaked bytes"
            else
               pass "${branch}: payload neutralized (${arg} absent from a rendered diff)"
            fi
         fi
         ;;
      failclosed)
         ## A non-zero exit alone is not enough -- a tool that merely crashed on
         ## the fixture would "pass". Require the deliberate refusal message too.
         if [ "${rc}" = 0 ]; then
            fail "${branch}: did NOT fail closed (exit 0)"
         elif ! grep --quiet --text --ignore-case --fixed-strings -- 'failing closed' "${out_file}"; then
            fail "${branch}: exited ${rc} without the expected refusal message"
         else
            pass "${branch}: failed closed (exit ${rc}, refusal message present)"
         fi
         ;;
      shows)
         if grep --quiet --text --ignore-case --fixed-strings -- "${arg}" "${out_file}"; then
            pass "${branch}: surfaced ('${arg}')"
         else
            fail "${branch}: did NOT surface ('${arg}')"
         fi
         ;;
      *)
         fail "${branch}: unknown assert '${assert}'"
         ;;
   esac
done < manifest.tsv

printf '%s\n' "  corpus suite failures: ${fails}"
exit "${fails}"
