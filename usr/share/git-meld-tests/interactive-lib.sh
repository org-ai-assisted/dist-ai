#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Interactive-consent tests for the terminal-safe reviewer git-diff-review.
## Contract: on FATAL (undecodable / non-UTF-8) content it prompts on /dev/tty
## ("continue past neutralized content? [y/N]") and must CONTINUE on 'y' (exit
## 0) and FAIL CLOSED on 'n' (non-zero). Only git-diff-review (which sets
## git_review_display_fatal_content and neutralizes everything through stcat)
## prompts; the non-interactive path is covered elsewhere. Needs a pseudo-tty,
## so it drives the wrapper through git-meld-tests-pty.py.
##
## Usage: interactive-lib.sh [<dir-with-git-diff-review>]
## Exit 77 == SKIP (git-diff-review or python3 not available).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

mydir="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" && pwd )"
bindir="${1:-/usr/bin}"
gdr="${bindir}/git-diff-review"
pyhelper="${mydir}/git-meld-tests-pty.py"

if [ ! -x "${gdr}" ] || ! command -v python3 >/dev/null 2>&1 || [ ! -f "${pyhelper}" ]; then
   printf '%s\n' "interactive-lib: git-diff-review / python3 / pty helper missing; skipping." >&2
   exit 77
fi

printf '%s\n' "== git-diff-review interactive-consent suite =="
printf '%s\n' "  git-diff-review: ${gdr}"

work="$( mktemp --directory )"
export HOME="${work}/home"
mkdir --parents -- "${HOME}"
git config --global user.email t@example.com
git config --global user.name test
git config --global init.defaultBranch master
# shellcheck disable=SC2317
cleanup() { rm --recursive --force -- "${work}"; }
trap cleanup EXIT

fails=0
pass() { printf '  PASS  %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1" >&2; fails=$(( fails + 1 )); }

## Repo whose HEAD~1..HEAD change is undecodable (fatal) content.
repo="${work}/r"
git init -q "${repo}"
cd -- "${repo}"
printf 'ok\n' > bad.txt
git add -A
git commit -qm base
printf 'x \xff\xfe y\n' > bad.txt
git add -A
git commit -qm bad

pty_code() {
   ## $1 = answer fed to the prompt; echoes git-diff-review's exit code.
   local out
   out="$( cd -- "${repo}" && python3 "${pyhelper}" "$1" "${gdr}" HEAD~1 HEAD 2>/dev/null )"
   printf '%s' "${out}" | sed -n 's/^PTY_EXITCODE=//p'
}

y_code="$( pty_code y )"
if [ "${y_code}" = 0 ]; then
   pass "interactive: 'y' continues past fatal content (exit 0)"
else
   fail "interactive: 'y' did not continue (exit '${y_code}')"
fi

n_code="$( pty_code n )"
if [ -n "${n_code}" ] && [ "${n_code}" != 0 ]; then
   pass "interactive: 'n' fails closed (exit '${n_code}')"
else
   fail "interactive: 'n' did not fail closed (exit '${n_code}')"
fi

printf '\n==== interactive FAILURES: %s ====\n' "${fails}"
[ "${fails}" -eq 0 ]
