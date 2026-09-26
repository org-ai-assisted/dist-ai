#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression: compat-shot.py must build the compatibility fixture and RUN every program (and
## every verify tool a multi-tool row claims) for real, so the picture the site captures actually
## backs the page's "each program was run and its output verified" claim. The compat figures are
## now REAL secure-terminal windows captured by comparison-capture.sh (labwc + grim) -- that render
## needs a compositor and is not CI-testable -- but the fixture build + the run/verify contract is
## pure and IS tested here, no Qt, no display.
##
## Checks:
##   1. `compat-shot.py --fixture-dir <dir>` exits 0: it builds the fixture AND runs run_verify,
##      which executes every row's shot command (rc-checked against expect_rc) plus every verify
##      tool (rc 0) in a throwaway fixture copy. A NameError, a broken fixture, a missing/failing
##      tool -> non-zero here.
##   2. the emitted table has one `name<TAB>line_editing<TAB>command` row per --list name.
##   3. DRIFT (site checkout only): every listed shot is referenced by the compatibility page as
##      compatibility/shots/<name>.webp, and every committed compat webp is a listed shot -- so the
##      generator's set and the page cannot drift apart.
##   4. CANARY (silent-green): _run_checked must RAISE on a command whose exit != expected, so a
##      missing/failing tool can never silently back the "was run and verified" claim.
##
## Subject: compat-shot.py in secure-terminal-shots/. Its fixture RUNS the programs below; any
## absent is an environment bug -> exit 1 (FATAL, R-220), never a skip.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## style-ok: allow-python-interpreter -- python3 -c canary against the generator module

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

shots_dir=''
for cand in \
   "${SECURE_TERMINAL_SHOTS_DIR:-}" \
   "${script_dir}/../secure-terminal-shots" \
   "${script_dir}/../../share/secure-terminal-shots" \
   '/usr/share/secure-terminal-shots'; do
   if [ -n "${cand}" ] && [ -d "${cand}" ] && [ -f "${cand}/compat-shot.py" ]; then
      shots_dir="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${shots_dir}" ]; then
   printf '%s\n' 'FATAL: secure-terminal-shots dir not found (set SECURE_TERMINAL_SHOTS_DIR)' >&2
   exit 1
fi
gen="${shots_dir}/compat-shot.py"

## The fixture RUNS these for real; a missing one is an environment bug, not a skip (R-220).
for tool in bash ls cat cp find tar grep gzip zcat sed diff cmp awk git python3; do
   if ! type -P "${tool}" >/dev/null 2>&1; then
      printf '%s\n' "FATAL: required fixture program '${tool}' not found on PATH (install it in the test env)" >&2
      exit 1
   fi
done
if ! python3 -c 'import tqdm' 2>/dev/null; then
   printf '%s\n' 'FATAL: python3 tqdm module not importable (the tqdm progress emitter needs it)' >&2
   exit 1
fi

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

pass=0
fail=0
check() {  ## $1=label $2=rc (0 pass)
   if [ "$2" -eq 0 ]; then
      printf '%s\n' "PASS: $1"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $1"
      fail=$(( fail + 1 ))
   fi
}

## 1. Build the fixture + run/verify every program. Table -> stdout, captured for check 2.
rc=0
"${gen}" --fixture-dir "${work}" >"${work}/table.tsv" 2>"${work}/gen.log" || rc=$?
check 'compat-shot.py --fixture-dir builds the fixture and runs/verifies every program (exit 0)' "${rc}"
if [ "${rc}" -ne 0 ]; then
   sed 's/^/    /' "${work}/gen.log" >&2 || true
fi

## 2. One well-formed table row per listed name.
names="$("${gen}" --list)"
for name in ${names}; do
   if grep --quiet --extended-regexp "^${name}"$'\t'"(full|read-safe|append-only)"$'\t'. "${work}/table.tsv"; then
      rc=0
   else
      rc=1
   fi
   check "table has a well-formed row for '${name}'" "${rc}"
done

## 3. DRIFT: the page references every listed shot, and no stale webp (site checkout only).
page=''
for cand in \
   "${SECURE_TERMINAL_SITE_REPO:-}" \
   "${HOME}/private-sources/secure-terminal.github.io"; do
   if [ -n "${cand}" ] && [ -f "${cand}/compatibility/index.html" ]; then
      page="${cand}/compatibility/index.html"
      break
   fi
done
if [ -n "${page}" ]; then
   for name in ${names}; do
      if grep --quiet --fixed-strings "compatibility/shots/${name}.webp" "${page}"; then rc=0; else rc=1; fi
      check "compatibility page references shots/${name}.webp (no drift)" "${rc}"
   done
   site_shots="$(dirname -- "${page}")/shots"
   # shellcheck disable=SC2086
   names_sp=" $(printf '%s ' ${names}) "
   shopt -s nullglob
   for webp in "${site_shots}"/*.webp; do
      base="$(basename -- "${webp}" .webp)"
      case "${names_sp}" in
         *" ${base} "*)
            rc=0
            ;;
         *)
            rc=1
            ;;
      esac
      check "committed compat shot ${base}.webp is a generator program (not hand-added)" "${rc}"
   done
else
   printf '%s\n' 'note: secure-terminal.github.io checkout not found; page-drift check not applicable here'
fi

## 4. CANARY (silent-green): _run_checked RAISES when a command's exit != expected. Import the
## generator module (no Qt import in it) and assert `false` (exit 1, expected 0) raises.
canary_rc=0
python3 - "${gen}" "${work}" <<'PY' || canary_rc=$?
import importlib.util, sys
gen, work = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location('compat_shot', gen)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
env = mod._fixture_env(work)
try:
    mod._run_checked('false', work, env, 0)   # exits 1, expected 0 -> must raise
except RuntimeError:
    sys.exit(0)
sys.stderr.write('canary: _run_checked did NOT raise on a failing command\n')
sys.exit(1)
PY
check '_run_checked fails loud on a command that did not run cleanly (no silent-green)' "${canary_rc}"

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: compat-shot.py builds the fixture and runs/verifies every compatibility program'
