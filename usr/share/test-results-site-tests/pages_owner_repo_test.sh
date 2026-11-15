#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Unit-tests pages_owner_repo_from_url (the shared Pages owner/repo derivation) by SOURCING the
## real lib -- no copy. The derivation feeds the github-pages deployment API and a log line, so a
## misparse either queries the wrong repo (false "not live") or, for a credentialed URL, LEAKS the
## token into logs/argv. Guards: standard forms, a UPPERCASE host, embedded credentials (stripped),
## ssh-over-443, an explicit port, and trailing .git/slash -- the exact URL shapes the reviewers hit.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
repo_root="$(cd -- "${script_dir}/../../.." && pwd)"
lib="${repo_root}/usr/libexec/dist-ai/pages-confirm.bsh"
[ -r "${lib}" ] || lib='/usr/libexec/dist-ai/pages-confirm.bsh'
if [ ! -r "${lib}" ]; then
   printf '%s\n' "pages-confirm.bsh not found" >&2
   exit 1
fi
# shellcheck source=../../libexec/dist-ai/pages-confirm.bsh
source "${lib}"

pass=0
fail=0
check() {
   ## $1 input url, $2 expected owner/repo
   local got
   got="$(pages_owner_repo_from_url "$1")"
   if [ "${got}" = "$2" ]; then
      printf '%s\n' "PASS: '$1' -> '${got}'"
      pass=$((pass + 1))
   else
      printf '%s\n' "FAIL: '$1'" "  expected: '$2'" "  actual:   '${got}'" >&2
      fail=$((fail + 1))
   fi
}

want='org-ai-assisted/org-ai-assisted.github.io'

## scp-like (our default) and https.
check "git@github.com:org-ai-assisted/org-ai-assisted.github.io.git" "${want}"
check "https://github.com/org-ai-assisted/org-ai-assisted.github.io.git" "${want}"
check "https://github.com/org-ai-assisted/org-ai-assisted.github.io" "${want}"

## Case-insensitive host AND embedded credentials: the token must NOT survive into owner/repo.
check "https://alice:ghp_SECRET@GITHUB.COM/org-ai-assisted/org-ai-assisted.github.io.git" "${want}"
check "https://x-access-token:ghp_SECRET@github.com/org-ai-assisted/org-ai-assisted.github.io" "${want}"

## A host-port form must not leak the port digits into owner/repo (GitHub serves ssh on 443).
check "ssh://git@ssh.github.com:443/org-ai-assisted/org-ai-assisted.github.io.git" "${want}"
check "https://github.com:443/org-ai-assisted/org-ai-assisted.github.io.git" "${want}"
check "ssh://git@github.com:22/org-ai-assisted/org-ai-assisted.github.io.git" "${want}"

## Trailing slash and surrounding whitespace.
check "https://github.com/org-ai-assisted/org-ai-assisted.github.io.git/" "${want}"
check "  git@github.com:org-ai-assisted/org-ai-assisted.github.io.git  " "${want}"

## No credential must EVER appear in the output (explicit, belt-and-braces on the leak class).
leaky="$(pages_owner_repo_from_url 'https://alice:ghp_SECRET@GITHUB.COM/org-ai-assisted/org-ai-assisted.github.io.git')"
case "${leaky}" in
   *ghp_SECRET*)
      printf '%s\n' "FAIL: credential leaked into owner/repo: '${leaky}'" >&2
      fail=$((fail + 1))
      ;;
   *)
      printf '%s\n' "PASS: credential stripped from owner/repo"
      pass=$((pass + 1))
      ;;
esac

printf '%s\n' "" "${pass} pass, ${fail} fail, 0 skip"
[ "${fail}" -eq 0 ]
