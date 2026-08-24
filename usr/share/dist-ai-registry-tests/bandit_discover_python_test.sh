#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for ci/bandit-discover-python.sh, which emits a NUL-separated
## list of Python sources (by .py extension OR a python shebang) for bandit,
## excluding .git/, the .github/dmf + .github/dist-ai CI helper checkouts, and
## every submodule path in .gitmodules.
##
## WHY this exists: the submodule exclusion is the load-bearing, easy-to-break
## part. 'git config -z' NUL-separates entries but puts a NEWLINE between key and
## value, so a naive newline-delimited read splits mid-record and produces a
## garbage exclude path -- leaving the REAL submodule sources in the list, where
## bandit scans vendored code and files its defects against the consumer. This
## pins: .py + shebang discovery, and exclusion of .git, both helper checkouts,
## and .gitmodules submodule paths (including a nested 'libs/foo' path). It FAILS
## against the old newline-delimited parse.
##
## Source-tree test: set DIST_AI_REPO, or run it from a checkout. No source tree
## is FATAL (exit 1), not a skip. Needs 'git'. No root, no network.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

[ -v TMP ] || TMP=/tmp

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

repo="${DIST_AI_REPO:-}"
if [ -z "${repo}" ]; then
   candidate="${script_dir}/../../.."
   if [ -f "${candidate}/ci/bandit-discover-python.sh" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi

if [ -z "${repo}" ] || [ ! -f "${repo}/ci/bandit-discover-python.sh" ]; then
   printf '%s\n' 'FATAL: bandit-discover-python-test: no dist-ai source tree (set DIST_AI_REPO).' >&2
   exit 1
fi

discover="${repo}/ci/bandit-discover-python.sh"

if ! type -P git >/dev/null; then
   printf '%s\n' 'FAIL: bandit-discover-python-test: git not on PATH; the discovery cannot run' >&2
   exit 1
fi

work_dir="$(mktemp --directory -- "${TMP}/bandit-discover-python-test.XXXXXX")"

## Reached only via the EXIT trap; shellcheck cannot see that path (SC2317).
# shellcheck disable=SC2317
cleanup_work_dir() {
   safe-rm --recursive --force -- "${work_dir}" || true
   return 0
}

trap cleanup_work_dir EXIT

failures=0

fail() {
   printf '%s\n' "FAIL: $1" >&2
   failures=$(( failures + 1 ))
}

## Build a fixture tree.
tree="${work_dir}/tree"
mkdir -p -- \
   "${tree}/pkg" \
   "${tree}/.git/hooks" \
   "${tree}/.github/dmf" \
   "${tree}/.github/dist-ai" \
   "${tree}/vendored" \
   "${tree}/libs/foo"

## Included: .py by extension.
printf '%s\n' 'x = 1' > "${tree}/a.py"
printf '%s\n' 'y = 2' > "${tree}/pkg/b.py"
## Included: no extension, python shebang.
printf '%s\n' '#!/usr/bin/python3' 'z = 3' > "${tree}/tool_noext"
chmod +x -- "${tree}/tool_noext"
## Excluded: no extension, non-python shebang.
printf '%s\n' '#!/bin/bash' 'echo hi' > "${tree}/run_noext"
## Excluded: inside .git / helper checkouts.
printf '%s\n' 'g = 1' > "${tree}/.git/hooks/hook.py"
printf '%s\n' 'd = 1' > "${tree}/.github/dmf/d.py"
printf '%s\n' 'e = 1' > "${tree}/.github/dist-ai/e.py"
## Excluded: submodule sources named in .gitmodules (incl. a nested path).
printf '%s\n' 'v = 1' > "${tree}/vendored/v.py"
printf '%s\n' 'f = 1' > "${tree}/libs/foo/f.py"
printf '%s\n' \
   '[submodule "vendored"]' '  path = vendored' '  url = https://example.com/v.git' \
   '[submodule "libs/foo"]' '  path = libs/foo' '  url = https://example.com/f.git' \
   > "${tree}/.gitmodules"

## Run discovery in the tree; collect the NUL-separated output into an array.
declare -a found
mapfile -d '' -t found < <( cd -- "${tree}" && bash -- "${discover}" )

## Membership over the (leading './'-stripped) result paths.
contains() {
   local needle="$1" item
   for item in "${found[@]}"; do
      if [ "${item#./}" = "${needle}" ]; then
         return 0
      fi
   done
   return 1
}

## ---- included ------------------------------------------------------------
for want in 'a.py' 'pkg/b.py' 'tool_noext'; do
   if ! contains "${want}"; then
      fail "expected '${want}' in the discovered set"
   fi
done

## ---- excluded ------------------------------------------------------------
for unwant in 'run_noext' '.git/hooks/hook.py' '.github/dmf/d.py' \
   '.github/dist-ai/e.py' 'vendored/v.py' 'libs/foo/f.py'; do
   if contains "${unwant}"; then
      fail "'${unwant}' should have been excluded but was discovered"
   fi
done

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "bandit-discover-python-test: ${failures} check(s) failed" >&2
   exit 1
fi

printf '%s\n' 'bandit-discover-python-test: all checks passed'
