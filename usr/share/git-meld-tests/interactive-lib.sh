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

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.sh
source "${HELPER_SCRIPTS_PATH:-}"/usr/libexec/helper-scripts/has.sh

mydir="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" && pwd )"
bindir="${1:-/usr/bin}"
gdr="${bindir}/git-diff-review"
pyhelper="${mydir}/git-meld-tests-pty.py"

if [ ! -x "${gdr}" ] || ! has python3 || [ ! -f "${pyhelper}" ]; then
   printf '%s\n' "FATAL: interactive-lib: git-diff-review / python3 / pty helper missing." >&2
   exit 1
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
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

fails=0
pass() { printf '%s\n' "  PASS  $1"; }
fail() { printf '%s\n' "  FAIL  $1" >&2; fails=$(( fails + 1 )); }

## Repo whose HEAD~1..HEAD change is undecodable (fatal) content.
repo="${work}/r"
git init -q "${repo}"
cd -- "${repo}"
printf '%s\n' 'ok' > bad.txt
git add -A
git commit -qm base
printf '%b' 'x \xff\xfe y\n' > bad.txt
git add -A
git commit -qm bad

## The review tools must never spawn a pager. On a terminal git pages the
## diffstat of 'git diff --stat' unless '--no-pager' is given, and the pager then
## waits for a keypress no automated consumer can send. GIT_PAGER points at a
## stub that records the call and otherwise behaves like 'cat', so a regression
## is a named FAIL here instead of a hang.
pager_log="${work}/pager.log"
pager_stub="${work}/pager-stub"
pager_log_q="$(printf '%q' "${pager_log}")"
{
   printf '%s\n' '#!/bin/bash'
   printf '%s\n' "printf \"PAGER-CALLED\\n\" >> ${pager_log_q}"
   printf '%s\n' 'exec cat'
} > "${pager_stub}"
chmod +x -- "${pager_stub}"
export GIT_PAGER="${pager_stub}"
true > "${pager_log}"

pty_code() {
   ## $1 = answer fed to the prompt; echoes git-diff-review's exit code, or
   ## 'timeout' when the tool never exited (see git-meld-tests-pty.py).
   local out
   out="$( cd -- "${repo}" && python3 "${pyhelper}" "$1" "${gdr}" HEAD~1 HEAD 2>/dev/null )"
   printf '%s' "${out}" | sed -n 's/^PTY_EXITCODE=//p'
}

y_code="$( pty_code y )"
if [ "${y_code}" = 0 ]; then
   pass "interactive: 'y' continues past fatal content (exit 0)"
elif [ "${y_code}" = timeout ]; then
   fail "interactive: 'y' never returned; the tool is stuck on a prompt or a pager"
else
   fail "interactive: 'y' did not continue (exit '${y_code}')"
fi

if [ -s "${pager_log}" ]; then
   fail "a pager was spawned under a tty (missing '--no-pager'); an unattended review would hang"
else
   pass "no pager spawned under a tty"
fi

n_code="$( pty_code n )"
if [ "${n_code}" = timeout ]; then
   fail "interactive: 'n' never returned; the tool is stuck on a prompt or a pager"
elif [ -n "${n_code}" ] && [ "${n_code}" != 0 ]; then
   pass "interactive: 'n' fails closed (exit '${n_code}')"
else
   fail "interactive: 'n' did not fail closed (exit '${n_code}')"
fi

printf '%s\n' '' "==== interactive FAILURES: ${fails} ===="
[ "${fails}" -eq 0 ]
