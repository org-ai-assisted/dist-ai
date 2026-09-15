#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression + CANARY for cov-debug-missing.py, the coverage miss-attribution helper
## (COVERAGE_DEBUG_MISSING). It must distinguish a real, constant coverage gap from a
## combine/measurement DROP -- and it must NOT get that backwards when its own raw-data side
## channel is empty. Three cases over a synthetic package with one never-called function:
##   A (the fixed bug): raw dir EMPTY -> the union cross-check cannot run, so drop=unknown and
##      NO DEBUG-COMBINE-DROP. On the pre-fix helper the empty union mismatched every real
##      gap -> drop=yes + DEBUG-COMBINE-DROP, i.e. a real gap FALSELY reported as a flake.
##   B: raw files present, combined == union -> drop=no (a correctly-classified real gap).
##   C: combined built from a SUBSET of the raw files (a genuine drop) -> drop=yes +
##      DEBUG-COMBINE-DROP (the true positive still fires).
##
## Subject: usr/share/dist-ai-tests-common/cov-debug-missing.py. Needs importable coverage;
## absent -> exit 1 (FATAL): a required subject/dep is an environment bug (R-220). Pure
## coverage-data analysis, no Qt/compositor -- runs anywhere.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## style-ok: allow-python-interpreter -- coverage runs + the helper are python3

script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"

helper=''
for cand in \
   "${COV_DEBUG_MISSING:-}" \
   "${script_dir}/../dist-ai-tests-common/cov-debug-missing.py" \
   '/usr/share/dist-ai-tests-common/cov-debug-missing.py'; do
   if [ -n "${cand}" ] && [ -f "${cand}" ]; then
      helper="$(readlink --canonicalize -- "${cand}")"
      break
   fi
done
if [ -z "${helper}" ]; then
   printf '%s\n' 'FATAL: cov-debug-missing.py not found (set COV_DEBUG_MISSING)' >&2
   exit 1
fi
if ! python3 -c 'import coverage' 2>/dev/null; then
   printf '%s\n' 'FATAL: python3 coverage not importable' >&2
   exit 1
fi

work="$(mktemp --directory)"
cleanup() { safe-rm --recursive --force -- "${work}" 2>/dev/null || true; }
trap cleanup EXIT

pass=0
fail=0
ok() {  ## $1=condition-rc(0=pass) $2=label
   if [ "$1" = '0' ]; then
      printf '%s\n' "PASS: $2"
      pass=$(( pass + 1 ))
   else
      printf '%s\n' "FAIL: $2"
      fail=$(( fail + 1 ))
   fi
}
has() { grep --quiet -- "$2" "$1"; }   ## file, fixed-ish pattern (grep BRE)

## Synthetic package: a() covered by driveA, b() by driveB, never() by no one.
pkg="${work}/pkg"
mkdir --parents -- "${pkg}"
cat > "${pkg}/mod.py" <<'PY'
def a():
    return 1
def b():
    return 2
def never():
    return 3
PY
printf '%s\n' 'import mod' 'mod.a()' > "${work}/driveA.py"
printf '%s\n' 'import mod' 'mod.b()' > "${work}/driveB.py"

raw="${work}/raw"
mkdir --parents -- "${raw}"
export PYTHONPATH="${pkg}"
export PYTHONDONTWRITEBYTECODE=1
COVERAGE_FILE="${raw}/.coverage" python3 -m coverage run --parallel-mode --source="${pkg}" -- \
   "${work}/driveA.py" >/dev/null 2>&1
COVERAGE_FILE="${raw}/.coverage" python3 -m coverage run --parallel-mode --source="${pkg}" -- \
   "${work}/driveB.py" >/dev/null 2>&1
## Two parallel data files now sit in "${raw}".
mapfile -t raw_files < <(printf '%s\n' "${raw}"/.coverage.*)
[ "${#raw_files[@]}" -ge 2 ] || { printf '%s\n' 'FATAL: expected >= 2 parallel data files' >&2; exit 1; }

combine_into() {  ## $1=dest .coverage  $2..=raw files to combine (copied, consumed)
   local dest="$1"; shift
   local dir; dir="$(dirname -- "${dest}")"
   mkdir --parents -- "${dir}"
   safe-rm --force -- "${dir}"/.coverage*
   cp --preserve -- "$@" "${dir}/"
   COVERAGE_FILE="${dest}" python3 -m coverage combine >/dev/null 2>&1
}

## ---- Case A: empty raw dir -> drop=unknown, NO combine-drop (the fixed inversion) --------
empty_raw="${work}/raw_empty"
mkdir --parents -- "${empty_raw}"
combine_into "${work}/A/.coverage" "${raw_files[@]}"
outA="${work}/outA.txt"
python3 "${helper}" "${work}/A/.coverage" "${empty_raw}" "${pkg}" > "${outA}" 2>&1 || true
if has "${outA}" 'drop=unknown'; then ok 0 'A: empty raw dir -> drop=unknown (real gap NOT called a flake)'; else ok 1 'A: empty raw dir -> drop=unknown (real gap NOT called a flake)'; fi
if has "${outA}" 'DEBUG-COMBINE-DROP'; then ok 1 'A: empty raw dir emits NO DEBUG-COMBINE-DROP'; else ok 0 'A: empty raw dir emits NO DEBUG-COMBINE-DROP'; fi
if has "${outA}" 'DEBUG-MISSING mod.py'; then ok 0 'A: the real miss is still reported (DEBUG-MISSING)'; else ok 1 'A: the real miss is still reported (DEBUG-MISSING)'; fi

## ---- Case B: full raw union, combined == union -> drop=no ---------------------------------
outB="${work}/outB.txt"
python3 "${helper}" "${work}/A/.coverage" "${raw}" "${pkg}" > "${outB}" 2>&1 || true
if has "${outB}" 'drop=no'; then ok 0 'B: full raw union of a real gap -> drop=no'; else ok 1 'B: full raw union of a real gap -> drop=no'; fi
if has "${outB}" 'DEBUG-UNION-MISSING mod.py'; then ok 0 'B: the manual union is reported (DEBUG-UNION-MISSING)'; else ok 1 'B: the manual union is reported (DEBUG-UNION-MISSING)'; fi

## ---- Case C: combined from a SUBSET (genuine drop) vs full raw union -> drop=yes ----------
combine_into "${work}/C/.coverage" "${raw_files[0]}"   ## only driveA -> combined also misses b()'s line
outC="${work}/outC.txt"
python3 "${helper}" "${work}/C/.coverage" "${raw}" "${pkg}" > "${outC}" 2>&1 || true
if has "${outC}" 'drop=yes'; then ok 0 'C: combined missing a line the raw union covers -> drop=yes'; else ok 1 'C: combined missing a line the raw union covers -> drop=yes'; fi
if has "${outC}" 'DEBUG-COMBINE-DROP'; then ok 0 'C: a genuine combine drop emits DEBUG-COMBINE-DROP'; else ok 1 'C: a genuine combine drop emits DEBUG-COMBINE-DROP'; fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: cov-debug-missing distinguishes a real gap from a combine drop, and never infers a drop from absent raw data'
