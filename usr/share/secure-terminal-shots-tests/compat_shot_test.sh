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
## The progress-bar figures `cat` byte-stable demos committed in terminal-safe-corpus; the fixture
## copies them in, so the corpus checkout is a REQUIRED input (R-220), never a skip.
safe_corpus=''
for cand in \
   "${SAFE_CORPUS_REPO:-}" \
   "${HOME}/private-sources/terminal-safe-corpus" \
   "${script_dir}/../../../../terminal-safe-corpus"; do
   if [ -n "${cand}" ] && [ -f "${cand}/demos/progress-crbar-safe-to-cat.txt" ]; then
      safe_corpus="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${safe_corpus}" ]; then
   printf '%s\n' 'FATAL: terminal-safe-corpus not found (set SAFE_CORPUS_REPO); it supplies the progress-bar demo bytes' >&2
   exit 1
fi
export SAFE_CORPUS_REPO="${safe_corpus}"

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

## 2. The emitted table's name column must be EXACTLY the --list set: one row per name, no
## duplicate and no extra/unlisted rows. The old check grepped per --list name (presence only),
## so a duplicate row (grep stops at the first match) or an unlisted extra row (never visited)
## slipped through. Compare the complete sorted name column against the sorted --list -- a
## difference is a missing row, an extra/unlisted row, OR a duplicate (each changes the multiset).
names="$("${gen}" --list)"
# shellcheck disable=SC2086
printf '%s\n' ${names} | sort >"${work}/list.names"

## Sorted table name column vs the sorted --list; rc 0 iff they match exactly. Reused below on a
## DOCTORED table (the canary) so a regression that weakens it back to presence-only is caught.
table_names_match() {  ## $1=table.tsv
   cut -f1 -- "$1" | sort >"${work}/table.names"
   diff -- "${work}/list.names" "${work}/table.names"
}

if table_names_match "${work}/table.tsv" >"${work}/table.namediff" 2>&1; then rc=0; else rc=1; fi
check 'table name column is exactly the --list set (no missing, extra/unlisted, or duplicate rows)' "${rc}"
[ "${rc}" -eq 0 ] || sed 's/^/    /' "${work}/table.namediff" >&2 || true

## Each row well-formed: name<TAB>{full|read-safe|append-only}<TAB>command.
for name in ${names}; do
   if grep --quiet --extended-regexp "^${name}"$'\t'"(full|read-safe|append-only)"$'\t'. "${work}/table.tsv"; then
      rc=0
   else
      rc=1
   fi
   check "table has a well-formed row for '${name}'" "${rc}"
done

## 2-canary (silent-green): the set check MUST reject a table carrying a duplicate row AND an
## unlisted extra row -- exactly what the old presence-only grep accepted. Doctor a copy, assert
## it is rejected.
{
   cat -- "${work}/table.tsv"
   head --lines 1 -- "${work}/table.tsv"                ## duplicate the first row
   printf '%s\n' "zz-not-a-listed-shot"$'\t'"full"$'\t'"cat x"         ## an unlisted extra row
} >"${work}/table.doctored"
if table_names_match "${work}/table.doctored" >/dev/null 2>&1; then rc=1; else rc=0; fi
check 'table validation rejects a duplicate row + an unlisted extra row (no silent-green)' "${rc}"

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
   printf -v names_sp '%s ' ${names}
   names_sp=" ${names_sp} "
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

## 5. CANARY (idempotent cleanup): run_verify must clear a stale .verify from a prior interrupted
## run, and must ALWAYS remove its own scratch -- even when a verify command raises mid-run -- so a
## leftover .verify can never break the next run_verify against the same fixture dir.
scratch_rc=0
python3 - "${gen}" <<'PY' || scratch_rc=$?
import importlib.util, os, sys, tempfile, types
gen = sys.argv[1]
spec = importlib.util.spec_from_file_location('compat_shot', gen)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# A -- a stale .verify from a prior run is cleared, not fatal. No program runs (all_programs=[]),
# so the only thing under test is the mkdir/cleanup contract. PRE-FIX: os.mkdir -> FileExistsError.
mod.all_programs = lambda: []
root = tempfile.mkdtemp()
open(os.path.join(root, 'dummy'), 'w').close()
stale = os.path.join(root, '.verify')
os.mkdir(stale)
open(os.path.join(stale, 'leftover'), 'w').close()   # non-empty stale dir from a prior run
mod.run_verify(root, mod._fixture_env(root))
if os.path.exists(stale):
    sys.stderr.write('canary A: run_verify left .verify behind on success\n')
    sys.exit(1)

# B -- a verify command raising mid-run still cleans up. PRE-FIX (no finally): .verify lingers.
mod.all_programs = lambda: [types.SimpleNamespace(command='false', expect_rc=0, verify=[])]
root = tempfile.mkdtemp()
open(os.path.join(root, 'dummy'), 'w').close()
scratch = os.path.join(root, '.verify')
try:
    mod.run_verify(root, mod._fixture_env(root))
except RuntimeError:
    pass
else:
    sys.stderr.write('canary B: run_verify did NOT raise on a failing verify command\n')
    sys.exit(1)
if os.path.exists(scratch):
    sys.stderr.write('canary B: run_verify left .verify behind after a mid-run failure\n')
    sys.exit(1)
sys.exit(0)
PY
check 'run_verify clears a stale scratch and always cleans up its own (no lingering .verify)' "${scratch_rc}"

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: compat-shot.py builds the fixture and runs/verifies every compatibility program'
