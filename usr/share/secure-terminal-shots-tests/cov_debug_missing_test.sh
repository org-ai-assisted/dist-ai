#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression + CANARY for cov-debug-missing.py, the coverage miss-attribution helper
## (COVERAGE_DEBUG_MISSING). It must distinguish a real, constant coverage gap from a
## combine/measurement DROP -- and it must NOT get that backwards when its own raw-data side
## channel is empty, incomplete, or the data is recorded relative. Cases over synthetic
## packages:
##   A (the fixed bug): raw dir EMPTY -> the union cross-check cannot run, so drop=unknown and
##      NO DEBUG-COMBINE-DROP. On the pre-fix helper the empty union mismatched every real
##      gap -> drop=yes + DEBUG-COMBINE-DROP, i.e. a real gap FALSELY reported as a flake.
##   B: raw files present, combined == union -> drop=no (a correctly-classified real gap).
##   C: combined built from a SUBSET of the raw files (a genuine drop) -> drop=yes +
##      DEBUG-COMBINE-DROP (the true positive still fires).
##   D: same-named files in different subpackages keyed distinctly (no basename collision).
##   E: a raw dir path with a glob metachar is read literally (glob.escape).
##   F: a measured source gone from disk -> skipped, no crash (never fails the gate).
##   G: combined covering MORE than the raw snapshot is NOT a false drop (direction-aware).
##   H: a module the union NEVER MEASURED (an incomplete snapshot) is NOT a drop. Pre-fix,
##      absent-from-union was indistinguishable from union-covered-fully -> DEBUG-COMBINE-DROP
##      + drop=yes falsely. Post-fix the union's MEASURED set gates the drop check.
##   I: relative_files data (coverage's cross-machine mode) is resolved against the record
##      root -> the real miss is reported. Pre-fix, record-root-relative paths resolved
##      against the tool's cwd -> filtered out -> combined=0, a silent false negative.
##   J: a truncated/corrupt combined data file -> skipped, no crash (never fails the gate).
##      Pre-fix, cov.load() raised DataError -> traceback + exit 1.
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

## ---- Case D: same-named files in different subpackages keyed distinctly (basename bug) ----
## Two 'dup.py' in different subpackages, each with an uncovered body line. The pre-fix
## helper keyed by basename -> both collapsed to 'dup.py' -> one file's gaps silently dropped.
pkg2="${work}/pkg2"
mkdir --parents -- "${pkg2}/sub1" "${pkg2}/sub2"
printf '%s\n' 'def never():' '    return 1' > "${pkg2}/sub1/dup.py"
printf '%s\n' 'def never():' '    return 2' > "${pkg2}/sub2/dup.py"
printf '%s\n' 'import sub1.dup' 'import sub2.dup' > "${work}/driveD.py"
rawD="${work}/rawD"
mkdir --parents -- "${rawD}"
PYTHONPATH="${pkg2}" COVERAGE_FILE="${rawD}/.coverage" python3 -m coverage run \
   --parallel-mode --source="${pkg2}" -- "${work}/driveD.py" >/dev/null 2>&1
combine_into "${work}/D/.coverage" "${rawD}"/.coverage.*
outD="${work}/outD.txt"
python3 "${helper}" "${work}/D/.coverage" "${rawD}" "${pkg2}" > "${outD}" 2>&1 || true
if has "${outD}" 'sub1/dup.py' && has "${outD}" 'sub2/dup.py'; then
   ok 0 'D: same-named files in different subpackages keyed distinctly (no basename collision)'
else
   ok 1 'D: same-named files in different subpackages keyed distinctly (no basename collision)'
fi

## ---- Case E: a raw dir path containing a glob metachar must still be read (glob.escape) ---
## Pre-fix: glob read '[abc]' as a character class -> no match -> raw_files=0 -> a real gap
## FALSELY reported as drop=unknown. Post-fix: the dir is escaped and read literally.
brk="${work}/raw[abc]"
mkdir --parents -- "${brk}"
cp --preserve -- "${raw_files[@]}" "${brk}/"
outE="${work}/outE.txt"
python3 "${helper}" "${work}/A/.coverage" "${brk}" "${pkg}" > "${outE}" 2>&1 || true
if has "${outE}" 'raw_files=2'; then
   ok 0 'E: raw dir path with a glob metachar is read literally (glob.escape)'
else
   ok 1 'E: raw dir path with a glob metachar is read literally (glob.escape)'
fi

## ---- Case F: a measured source file gone from disk -> skipped, no crash (never-fails) ----
## The tool's docstring promises best-effort diagnostics that never fail the gate. A cleaned
## build/tmp dir between the coverage run and this later invocation makes coverage.py raise
## NoSource; the pre-fix helper let it propagate -> traceback + exit 1.
pkgF="${work}/pkgF"
mkdir --parents -- "${pkgF}"
printf '%s\n' 'def never():' '    return 1' > "${pkgF}/gone.py"
printf '%s\n' 'import gone' > "${work}/driveF.py"
rawF="${work}/rawF"
mkdir --parents -- "${rawF}"
PYTHONPATH="${pkgF}" COVERAGE_FILE="${rawF}/.coverage" python3 -m coverage run \
   --parallel-mode --source="${pkgF}" -- "${work}/driveF.py" >/dev/null 2>&1
combine_into "${work}/F/.coverage" "${rawF}"/.coverage.*
safe-rm --recursive --force -- "${pkgF}"   ## the measured source is gone before the debug run
outF="${work}/outF.txt"
rcF=0
python3 "${helper}" "${work}/F/.coverage" "${rawF}" "${pkgF}" > "${outF}" 2>&1 || rcF=$?
if [ "${rcF}" -eq 0 ] && ! has "${outF}" 'Traceback'; then
   ok 0 'F: a deleted measured source is skipped, not a crash (never fails the gate)'
else
   ok 1 "F: deleted measured source crashed (rc=${rcF})"
fi

## ---- Case G: combined covers MORE than the raw snapshot -> NOT a drop (direction-blind) ---
## never() is covered by a raw file folded into the combined data but NOT archived into the
## raw dir passed in. combined misses nothing; union (raw dir) misses never(). That is an
## incomplete raw snapshot, NOT a combine drop -- the pre-fix `combined != union` flagged it.
printf '%s\n' 'import mod' 'mod.never()' > "${work}/driveG.py"
rawGx="${work}/rawGx"
mkdir --parents -- "${rawGx}"
COVERAGE_FILE="${rawGx}/.coverage" python3 -m coverage run --parallel-mode --source="${pkg}" -- \
   "${work}/driveG.py" >/dev/null 2>&1
combine_into "${work}/G/.coverage" "${raw_files[@]}" "${rawGx}"/.coverage.*
outG="${work}/outG.txt"
python3 "${helper}" "${work}/G/.coverage" "${raw}" "${pkg}" > "${outG}" 2>&1 || true
if has "${outG}" 'drop=no'; then
   ok 0 'G: combined covering MORE than the raw snapshot is NOT a false drop'
else
   ok 1 'G: combined covering more than the raw snapshot falsely flagged as a drop'
fi
if has "${outG}" 'DEBUG-COMBINE-DROP'; then
   ok 1 'G: no false DEBUG-COMBINE-DROP when the raw snapshot is merely incomplete'
else
   ok 0 'G: no false DEBUG-COMBINE-DROP when the raw snapshot is merely incomplete'
fi

## ---- Case H: a module the union NEVER MEASURED is NOT a drop (absent-from-union) ---------
## modm covered-but-incomplete by driveM, modo by driveO -- recorded WITHOUT a whole-package
## --source, so a raw file measures ONLY the module it imports (with --source every file
## always counts as measured on every side and the bug cannot arise). The raw snapshot passed
## in holds only modo's file, so the union never MEASURES modm. Pre-fix: modm absent from the
## union dict was read as union-covered-fully -> DEBUG-COMBINE-DROP modm.py + drop=yes, a real
## gap in an unmeasured module falsely blamed on combine. Post-fix: the union's MEASURED set
## gates the check -> no drop for modm.
pkgH="${work}/pkgH"
mkdir --parents -- "${pkgH}"
printf '%s\n' 'def m():' '    return 1' 'def mn():' '    return 2' > "${pkgH}/modm.py"
printf '%s\n' 'def o():' '    return 1' 'def on():' '    return 2' > "${pkgH}/modo.py"
printf '%s\n' 'import modm' 'modm.m()' > "${work}/driveM.py"
printf '%s\n' 'import modo' 'modo.o()' > "${work}/driveO.py"
rawM="${work}/rawM"; mkdir --parents -- "${rawM}"
PYTHONPATH="${pkgH}" COVERAGE_FILE="${rawM}/.coverage" python3 -m coverage run \
   --parallel-mode -- "${work}/driveM.py" >/dev/null 2>&1
rawO="${work}/rawO"; mkdir --parents -- "${rawO}"
PYTHONPATH="${pkgH}" COVERAGE_FILE="${rawO}/.coverage" python3 -m coverage run \
   --parallel-mode -- "${work}/driveO.py" >/dev/null 2>&1
combine_into "${work}/H/.coverage" "${rawM}"/.coverage.* "${rawO}"/.coverage.*
snapH="${work}/snapH"; mkdir --parents -- "${snapH}"
cp --preserve -- "${rawO}"/.coverage.* "${snapH}/"   ## union measures ONLY modo, never modm
outH="${work}/outH.txt"
python3 "${helper}" "${work}/H/.coverage" "${snapH}" "${pkgH}" > "${outH}" 2>&1 || true
if has "${outH}" 'drop=no' && ! has "${outH}" 'DEBUG-COMBINE-DROP modm.py'; then
   ok 0 'H: a module the union never measured is NOT a false combine-drop'
else
   ok 1 'H: a module the union never measured falsely flagged as a combine-drop'
fi

## ---- Case I: relative_files data resolved against the record root (not the tool cwd) ------
## Recorded with relative_files=True (coverage's recommended cross-machine/container combine
## mode) from the proj root, so measured_files() yields record-root-relative paths. Pre-fix:
## realpath() resolved them against the TOOL's cwd -> the containment filter dropped them ->
## combined=0, a real gap silently reported as none. Post-fix: the tool chdir's to the
## combined data file's dir (the record root) so the paths resolve. Invoked from a NEUTRAL
## cwd below so the pre-fix cwd-relative resolution genuinely fails.
projI="${work}/projI"
mkdir --parents -- "${projI}/pkg"
printf '%s\n' 'def a():' '    return 1' 'def never():' '    return 3' > "${projI}/pkg/mod.py"
printf '%s\n' 'import mod' 'mod.a()' > "${projI}/drive.py"
printf '%s\n' '[run]' 'relative_files = True' > "${projI}/.coveragerc"
( cd "${projI}" && PYTHONPATH="${projI}/pkg" COVERAGE_FILE="${projI}/.coverage" python3 \
   -m coverage run --parallel-mode --rcfile=.coveragerc --source=pkg -- drive.py >/dev/null 2>&1 )
rawI="${projI}/rawI"; mkdir --parents -- "${rawI}"
cp --preserve -- "${projI}"/.coverage.* "${rawI}/"
( cd "${projI}" && COVERAGE_FILE="${projI}/.coverage" python3 -m coverage combine \
   --rcfile=.coveragerc >/dev/null 2>&1 )
outI="${work}/outI.txt"
## Invoke from ${work} (NOT projI): pre-fix resolves relative paths here and finds nothing.
( cd "${work}" && python3 "${helper}" "${projI}/.coverage" "${rawI}" "${projI}/pkg" ) \
   > "${outI}" 2>&1 || true
if has "${outI}" 'DEBUG-MISSING mod.py' && has "${outI}" 'combined=1'; then
   ok 0 'I: relative_files data resolved against the record root (real miss reported)'
else
   ok 1 'I: relative_files data not resolved -> real miss silently dropped'
fi

## ---- Case J: a corrupt combined data file -> skipped, no crash (never fails the gate) -----
## The tool's docstring promises best-effort diagnostics that never fail the gate. A
## truncated/corrupt .coverage makes cov.load() raise DataError; the pre-fix helper let it
## propagate -> traceback + exit 1.
badJ="${work}/bad.coverage"
printf '%s' 'this is not a sqlite coverage database at all' > "${badJ}"
rawJ="${work}/rawJ"; mkdir --parents -- "${rawJ}"
outJ="${work}/outJ.txt"
rcJ=0
python3 "${helper}" "${badJ}" "${rawJ}" "${pkg}" > "${outJ}" 2>&1 || rcJ=$?
if [ "${rcJ}" -eq 0 ] && ! has "${outJ}" 'Traceback'; then
   ok 0 'J: a corrupt combined data file is skipped, not a crash (never fails the gate)'
else
   ok 1 "J: corrupt combined data crashed (rc=${rcJ})"
fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: cov-debug-missing distinguishes a real gap from a combine drop, and never infers a drop from absent raw data'
