#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test: every python3 entry point in usr/bin must carry the
## shell-invocation guard, and that guard must actually neutralize a shell
## invocation.
##
## WHY this exists: a python entry point run under a shell (`bash tool`,
## `sh tool`) has its shebang ignored, so the shell executes the module's
## `import` statements as commands. `import` is ImageMagick (/usr/bin/import),
## which calls XGrabServer and then blocks on interactive region-select --
## freezing every GUI client on the VM while the text CLI stays up. This
## actually happened (a `bash usr/bin/dist-ai-style ...` typo froze the VM).
## The guard, placed before the first import,
##     "exec" "python3" "-Bsu" "$0" "$@"
## is a no-op string literal under python3 but re-execs under any shell, so a
## shell invocation can never reach an `import` line.
##
## Two layers:
##   STATIC   -- the real shipped entry points each carry the guard (catches a
##               NEW unguarded tool, systemic, no execution needed).
##   BEHAVIOR -- a fixture proves the guard neutralizes a shell run, with a
##               CANARY (the same fixture WITHOUT the guard) that MUST still be
##               shell-executed; a test that stops detecting the bug fails loud.
## The behavioral layer is X-safe: it shadows `import` with a harmless sentinel
## stub and unsets DISPLAY, so nothing can ever reach a real X server.
##
## Source-tree lint: needs the checkout (DIST_AI_REPO or run from a checkout).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if ! test -r /usr/libexec/helper-scripts/has.bsh ; then
   printf '%s\n' "FATAL: python_entrypoint_shell_guard_test: helper-scripts has.bsh is not installed" >&2
   exit 1
fi
# shellcheck source=../../../helper-scripts/usr/libexec/helper-scripts/has.bsh
source /usr/libexec/helper-scripts/has.bsh

if ! has safe-rm ; then
   printf '%s\n' "FATAL: python_entrypoint_shell_guard_test: safe-rm not on PATH" >&2
   exit 1
fi

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

## Resolve the dist-ai source tree: an explicit override, else the checkout this
## script lives in (usr/share/<suite>/ -> repo root).
repo="${DIST_AI_REPO:-}"
if [ -z "${repo}" ]; then
   candidate="${script_dir}/../../.."
   if [ -f "${candidate}/usr/bin/dist-ai-tests-all" ] && [ -d "${candidate}/debian" ]; then
      repo="$(cd -- "${candidate}" && pwd)"
   fi
fi
if [ -z "${repo}" ] || [ ! -d "${repo}/usr/bin" ]; then
   printf '%s\n' 'FATAL: python_entrypoint_shell_guard_test: no dist-ai source tree (set DIST_AI_REPO).' >&2
   exit 1
fi

## The canonical guard line. The real entry points and the fixtures below must
## all use this exact text -- changing the idiom means changing it in one place
## and re-running this test.
guard_line='"exec" "python3" "-Bsu" "$0" "$@"'

failures=0
checks=0

fail() {
   printf '%s\n' "FAIL: $1" >&2
   failures=$(( failures + 1 ))
}

## ---- STATIC: every python3 entry point carries the guard ------------------

shopt -s nullglob
entrypoints=()
for candidate in "${repo}"/usr/bin/*; do
   [ -f "${candidate}" ] || continue
   IFS= read -r first_line < "${candidate}" || continue
   case "${first_line}" in
      '#!'*python*)
         entrypoints+=( "${candidate}" )
         ;;
   esac
done

if [ "${#entrypoints[@]}" -eq 0 ]; then
   fail "no python3 entry points found under ${repo}/usr/bin -- glob or detection broke"
fi

for entry in "${entrypoints[@]}"; do
   checks=$(( checks + 1 ))
   if ! grep --fixed-strings --quiet --line-regexp -- "${guard_line}" "${entry}"; then
      fail "$(basename -- "${entry}"): missing shell-invocation guard line -- a shell invocation would execute its import lines (ImageMagick import -> XGrabServer -> X freeze)"
      continue
   fi
   ## The guard must precede the first python statement, i.e. no bare `import`
   ## line may appear ABOVE it (a shell reaching an import before the guard is
   ## the whole bug).
   guard_ln="$(grep --fixed-strings --line-number -- "${guard_line}" "${entry}" | head -n 1 | cut -d: -f1)"
   first_import_ln="$(grep --extended-regexp --line-number '^[[:space:]]*(import|from)[[:space:]]' "${entry}" | head -n 1 | cut -d: -f1)"
   if [ -n "${first_import_ln}" ] && [ "${first_import_ln}" -lt "${guard_ln}" ]; then
      fail "$(basename -- "${entry}"): an import at line ${first_import_ln} precedes the guard at line ${guard_ln}"
   fi
done

## ---- BEHAVIOR: the guard neutralizes a shell run (with canary) ------------

tmp_root="$(mktemp --directory)"
cleanup() {
   safe-rm --recursive --force -- "${tmp_root}"
}
trap cleanup EXIT

## A harmless stand-in for /usr/bin/import: if a SHELL ever executes a fixture's
## `import` line, this runs and records it. It never touches X.
stub_dir="${tmp_root}/stub"
mkdir --parents -- "${stub_dir}"
sentinel="${tmp_root}/sentinel"
printf '%s\n' '#!/bin/sh' 'printf "%s\n" SHELL_RAN_IMPORT >> "${GUARD_TEST_SENTINEL}"' \
   > "${stub_dir}/import"
chmod 0755 -- "${stub_dir}/import"

## Write a python fixture. $1=path, $2=with_guard(yes|no).
write_fixture() {
   local path with_guard
   path="$1"
   with_guard="$2"
   {
      printf '%s\n' '#!/usr/bin/python3 -Bsu'
      if [ "${with_guard}" = 'yes' ]; then
         printf '%s\n' "${guard_line}"
      fi
      printf '%s\n' 'import os, sys'
      printf '%s\n' 'open(sys.argv[1], "w").write("PYTHON_RAN")'
   } > "${path}"
   chmod 0755 -- "${path}"
}

## Run FIXTURE under INTERP with import shadowed and DISPLAY unset; MARKER is the
## file the python body writes. Never aborts the suite on the child's exit code.
run_fixture() {
   local interp fixture marker
   interp="$1"
   fixture="$2"
   marker="$3"
   safe-rm --force -- "${marker}" "${sentinel}"
   env -u DISPLAY \
      PATH="${stub_dir}:${PATH}" \
      GUARD_TEST_SENTINEL="${sentinel}" \
      "${interp}" "${fixture}" "${marker}" >/dev/null 2>&1 || true
}

marker_reads() { # marker expected
   [ -f "$1" ] && [ "$(cat -- "$1")" = "$2" ]
}

guarded="${tmp_root}/guarded.py"
unguarded="${tmp_root}/unguarded.py"
write_fixture "${guarded}" yes
write_fixture "${unguarded}" no
marker="${tmp_root}/marker"

## Control: guarded fixture under python3 directly must run its body.
checks=$(( checks + 1 ))
run_fixture python3 "${guarded}" "${marker}"
marker_reads "${marker}" PYTHON_RAN \
   || fail "guarded fixture under python3 did not run its body (guard broke python execution)"

## Guarded under a shell: must re-exec python3 (body runs) and NEVER hit the stub.
for interp in bash sh; do
   checks=$(( checks + 1 ))
   run_fixture "${interp}" "${guarded}" "${marker}"
   if ! marker_reads "${marker}" PYTHON_RAN; then
      fail "guarded fixture under ${interp} did not re-exec python3 (body did not run)"
   fi
   if [ -s "${sentinel}" ]; then
      fail "guarded fixture under ${interp} executed the import stub -- guard failed to neutralize the shell"
   fi
done

## CANARY: unguarded under bash MUST hit the stub (the bug reproduces). If it
## does not, this whole test proves nothing.
checks=$(( checks + 1 ))
run_fixture bash "${unguarded}" "${marker}"
if [ ! -s "${sentinel}" ]; then
   fail "CANARY: unguarded fixture under bash did NOT execute the import stub -- the test can no longer detect the bug it guards against"
fi

if [ "${failures}" -ne 0 ]; then
   printf '%s\n' "python_entrypoint_shell_guard_test: ${failures} failure(s) across ${checks} checks" >&2
   exit 1
fi
printf '%s\n' "python_entrypoint_shell_guard_test: PASS (${#entrypoints[@]} entry points, ${checks} checks)"
