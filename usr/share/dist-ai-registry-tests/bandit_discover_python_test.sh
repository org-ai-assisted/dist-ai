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
## part -- and it must not be spoofable. Exclusion is driven by ACTUAL gitlinks
## (index mode 160000), NOT .gitmodules text: .gitmodules is attacker-controlled
## committed data, so a crafted `path = src` (a real source dir) or `path = *`
## (a glob) there could exclude real code and bypass the scan. This pins: .py +
## shebang discovery; exclusion of .git and both helper checkouts; exclusion of
## REAL gitlink paths (including a nested 'libs/foo'); and that a .gitmodules-only
## spoof (path=src, path=*) does NOT exclude real source. It FAILS against a
## .gitmodules-driven exclude.
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

## Build a fixture git tree. An arbitrary but valid object id for the gitlinks
## (git's empty-tree hash); the referenced commit need not exist locally.
gitlink_oid='4b825dc642cb6eb9a060e54bf8d69288fbee4904'
tree="${work_dir}/tree"
mkdir -p -- \
   "${tree}/pkg" \
   "${tree}/.github/dmf" \
   "${tree}/.github/dist-ai" \
   "${tree}/realsub" \
   "${tree}/libs/foo" \
   "${tree}/src"
git -C "${tree}" init --quiet

## Included: .py by extension.
printf '%s\n' 'x = 1' > "${tree}/a.py"
printf '%s\n' 'y = 2' > "${tree}/pkg/b.py"
## Included: no extension, python shebang.
printf '%s\n' '#!/usr/bin/python3' 'z = 3' > "${tree}/tool_noext"
chmod +x -- "${tree}/tool_noext"
## Excluded: no extension, non-python shebang.
printf '%s\n' '#!/bin/bash' 'echo hi' > "${tree}/run_noext"
## Excluded: inside .git / helper checkouts.
printf '%s\n' 'g = 1' > "${tree}/.git/hook.py"
printf '%s\n' 'd = 1' > "${tree}/.github/dmf/d.py"
printf '%s\n' 'e = 1' > "${tree}/.github/dist-ai/e.py"
## REAL submodules: gitlinks (mode 160000) in the index -> excluded (incl. a
## nested path).
printf '%s\n' 'v = 1' > "${tree}/realsub/v.py"
printf '%s\n' 'f = 1' > "${tree}/libs/foo/f.py"
git -C "${tree}" update-index --add --cacheinfo "160000,${gitlink_oid},realsub"
git -C "${tree}" update-index --add --cacheinfo "160000,${gitlink_oid},libs/foo"
## SPOOF: .gitmodules names a real source dir (src) and a glob (*). Neither is a
## gitlink, so discovery must IGNORE .gitmodules and still scan src -- and the
## '*' must not glob-exclude everything (pkg/b.py stays in).
printf '%s\n' 's = 1' > "${tree}/src/s.py"
printf '%s\n' \
   '[submodule "spoof-src"]' '  path = src' '  url = https://example.com/s.git' \
   '[submodule "spoof-glob"]' '  path = *' '  url = https://example.com/g.git' \
   '[submodule "realsub"]' '  path = realsub' '  url = https://example.com/v.git' \
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

## ---- included (incl. the .gitmodules-spoofed 'src' real source) -----------
for want in 'a.py' 'pkg/b.py' 'tool_noext' 'src/s.py'; do
   if ! contains "${want}"; then
      fail "expected '${want}' in the discovered set"
   fi
done

## ---- excluded (real gitlinks + .git + helper checkouts + non-py shebang) --
for unwant in 'run_noext' '.git/hook.py' '.github/dmf/d.py' \
   '.github/dist-ai/e.py' 'realsub/v.py' 'libs/foo/f.py'; do
   if contains "${unwant}"; then
      fail "'${unwant}' should have been excluded but was discovered"
   fi
done

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "bandit-discover-python-test: ${failures} check(s) failed" >&2
   exit 1
fi

printf '%s\n' 'bandit-discover-python-test: all checks passed'
