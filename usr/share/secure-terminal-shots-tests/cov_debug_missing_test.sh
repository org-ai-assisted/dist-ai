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
##   I: relative_files data (coverage's cross-machine mode), recorded with NO sibling
##      .coveragerc, resolves against the record root -> the EXACT real miss is reported.
##      chdir alone leaves the reporting object at relative_files=False -> analysis returns
##      every line missing (a silent wrong answer); the fix enables relative mode explicitly.
##   J: a truncated/corrupt combined data file -> skipped, no crash (never fails the gate).
##   K: a malformed sibling .coveragerc next to the data file -> NOT read (config_file=False),
##      no crash. It raises ConfigError (not a CoverageException), which would exit 1.
##   L: EVERY raw piece unreadable -> drop=unknown, NO false drop=no. Same "no usable
##      cross-check data" condition as an empty raw dir; a bare glob-hit count would misreport
##      a confident drop=no.
##   M: combined that DROPPED a whole file the union measured -> drop=yes + DEBUG-COMBINE-DROP
##      (the combined-side dual of H: absent-from-combined != combined-covered-fully).
##   N: a source filename containing a newline cannot forge an extra output record (control
##      chars in a key are escaped -> every DEBUG-* record stays one physical line).
##   O: a readable-but-IRRELEVANT raw dir (valid coverage measuring only unrelated sources,
##      nothing under pkg_dir) -> drop=unknown, NOT a confident drop=no. Readable is not
##      relevant: a stale/mismatched snapshot cannot cross-check the package.
##   P: the key escaping is INJECTIVE -- a file literally named with the chars '\x0a' and one
##      with a real newline byte are DISTINCT keys, not one silently clobbering the other. The
##      escape char '\' must itself be escaped, else a real gap vanishes from the report.
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
## Recorded with relative_files=True (coverage's cross-machine/container combine mode) via an
## rcfile OUTSIDE the proj root, so NO sibling .coveragerc sits next to the data file -- the
## tool must handle relative data on its own, not by accidentally auto-loading a co-located
## config. measured_files() yields record-root-relative paths. Two failure modes this guards:
## a plain realpath()-vs-tool-cwd drops them (combined=0), and a chdir that does not also
## enable relative mode makes analysis report EVERY line missing (mod.py 1-4, a silent wrong
## answer). Post-fix reports the EXACT miss (mod.py 4). Invoked from a NEUTRAL cwd.
projI="${work}/projI"
mkdir --parents -- "${projI}/pkg"
printf '%s\n' 'def a():' '    return 1' 'def never():' '    return 3' > "${projI}/pkg/mod.py"
printf '%s\n' 'import mod' 'mod.a()' > "${projI}/drive.py"
rcI="${work}/relconfig.rc"   ## OUTSIDE projI -- no sibling config next to the data file
printf '%s\n' '[run]' 'relative_files = True' > "${rcI}"
( cd "${projI}" && PYTHONPATH="${projI}/pkg" COVERAGE_FILE="${projI}/.coverage" python3 \
   -m coverage run --parallel-mode --rcfile="${rcI}" --source=pkg -- drive.py >/dev/null 2>&1 )
rawI="${projI}/rawI"; mkdir --parents -- "${rawI}"
cp --preserve -- "${projI}"/.coverage.* "${rawI}/"
( cd "${projI}" && COVERAGE_FILE="${projI}/.coverage" python3 -m coverage combine \
   --rcfile="${rcI}" >/dev/null 2>&1 )
outI="${work}/outI.txt"
## Invoke from ${work} (NOT projI): pre-fix resolves relative paths here and finds nothing.
( cd "${work}" && python3 "${helper}" "${projI}/.coverage" "${rawI}" "${projI}/pkg" ) \
   > "${outI}" 2>&1 || true
if has "${outI}" 'DEBUG-MISSING mod.py 4$' && ! has "${outI}" 'mod.py 1-4'; then
   ok 0 'I: relative_files data (no sibling config) resolves to the EXACT miss, not all-missing'
else
   ok 1 'I: relative_files data mis-resolved (dropped or reported all-missing)'
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

## ---- Case K: a malformed sibling .coveragerc next to the data file -> not read, no crash --
## The chdir toward relative_files support must not make coverage auto-read an on-disk config:
## a malformed .coveragerc raises ConfigError (NOT a CoverageException), which the corrupt-data
## guard would not catch -> traceback + exit 1. config_file=False must keep it best-effort.
dirK="${work}/K"; mkdir --parents -- "${dirK}"
combine_into "${dirK}/.coverage" "${raw_files[@]}"   ## a valid combined file (real gap in mod)
printf '%s\n' '[run]' 'relative_files = not-a-bool' > "${dirK}/.coveragerc"
rawK="${work}/rawK"; mkdir --parents -- "${rawK}"
outK="${work}/outK.txt"
rcK=0
python3 "${helper}" "${dirK}/.coverage" "${rawK}" "${pkg}" > "${outK}" 2>&1 || rcK=$?
if [ "${rcK}" -eq 0 ] && ! has "${outK}" 'Traceback' && ! has "${outK}" 'ConfigError'; then
   ok 0 'K: a malformed sibling .coveragerc is not read (config_file=False), no crash'
else
   ok 1 "K: malformed sibling config crashed (rc=${rcK})"
fi

## ---- Case L: EVERY raw piece unreadable -> drop=unknown, NO false drop=no -----------------
## A corrupt raw piece is skipped. If ALL are corrupt the union has zero usable data -- the
## SAME "cannot cross-check" condition as an empty raw dir, which must read drop=unknown, not
## a confident drop=no. A bare glob-hit count (raw_files>0) would misreport drop=no.
rawL="${work}/rawL"; mkdir --parents -- "${rawL}"
printf '%s' 'not a sqlite coverage db 1' > "${rawL}/.coverage.bad1"
printf '%s' 'not a sqlite coverage db 2' > "${rawL}/.coverage.bad2"
outL="${work}/outL.txt"
python3 "${helper}" "${work}/A/.coverage" "${rawL}" "${pkg}" > "${outL}" 2>&1 || true
if has "${outL}" 'drop=unknown' && ! has "${outL}" 'DEBUG-COMBINE-DROP'; then
   ok 0 'L: all raw pieces unreadable -> drop=unknown (no false confident verdict)'
else
   ok 1 'L: all-unreadable raw pieces misreported (expected drop=unknown)'
fi

## ---- Case M: combined DROPPED a whole file the union measured -> drop=yes -----------------
## The combined-side dual of H: a file measured by the raw union but absent from combined is a
## combine drop of the ENTIRE file, not "combined covered it fully". Combined built from a raw
## piece that measures ONLY modo; the union (raw dir) measures both modm and modo. Pre-fix,
## modm absent from combined -> c_set empty -> no drop flagged.
pkgM="${work}/pkgM"
mkdir --parents -- "${pkgM}"
printf '%s\n' 'def m():' '    return 1' 'def mn():' '    return 2' > "${pkgM}/modm.py"
printf '%s\n' 'def o():' '    return 1' 'def on():' '    return 2' > "${pkgM}/modo.py"
printf '%s\n' 'import modm' 'modm.m()' > "${work}/driveMm.py"
printf '%s\n' 'import modo' 'modo.o()' > "${work}/driveMo.py"
rawMm="${work}/rawMm"; mkdir --parents -- "${rawMm}"
PYTHONPATH="${pkgM}" COVERAGE_FILE="${rawMm}/.coverage" python3 -m coverage run \
   --parallel-mode -- "${work}/driveMm.py" >/dev/null 2>&1
rawMo="${work}/rawMo"; mkdir --parents -- "${rawMo}"
PYTHONPATH="${pkgM}" COVERAGE_FILE="${rawMo}/.coverage" python3 -m coverage run \
   --parallel-mode -- "${work}/driveMo.py" >/dev/null 2>&1
combine_into "${work}/M/.coverage" "${rawMo}"/.coverage.*   ## combined measures ONLY modo
unionM="${work}/unionM"; mkdir --parents -- "${unionM}"
cp --preserve -- "${rawMm}"/.coverage.* "${rawMo}"/.coverage.* "${unionM}/"  ## union measures both
outM="${work}/outM.txt"
python3 "${helper}" "${work}/M/.coverage" "${unionM}" "${pkgM}" > "${outM}" 2>&1 || true
if has "${outM}" 'drop=yes' && has "${outM}" 'DEBUG-COMBINE-DROP modm.py'; then
   ok 0 'M: a whole file dropped from combined is flagged (combined-side measured gate)'
else
   ok 1 'M: a whole file dropped from combined was NOT flagged'
fi

## ---- Case N: a source filename with a line-break char cannot forge an output record -------
## POSIX filenames may contain any byte; coverage keys measurement off co_filename, so a file
## measured via runpy keeps that name. An unescaped key splits its DEBUG-MISSING record across
## lines -- a line-oriented consumer then reads a forged second record. Two files: one with a
## LF (0x0a) and one with a UNICODE LINE SEPARATOR (U+2028). The invariant is checked with
## Python str.splitlines() (what a real consumer uses), NOT grep -- GNU grep breaks only on
## 0x0a, so it cannot even see a U+2028 split. PYTHONUTF8=1 makes the odd bytes decode to the
## line-break code points deterministically regardless of the C locale.
pkgN="${work}/pkgN"
mkdir --parents -- "${pkgN}"
nlfile="${pkgN}/$(printf 'weird\nname').py"                 ## LF in the name
lsfile="${pkgN}/ls$(printf '\xe2\x80\xa8')name.py"          ## U+2028 (UTF-8 e2 80 a8) in the name
printf '%s\n' 'def never():' '    return 1' > "${nlfile}"
printf '%s\n' 'def never():' '    return 1' > "${lsfile}"
## Pass the odd paths via the environment (env values carry arbitrary bytes safely), never
## embedded into python source -- coverage keys measurement off co_filename.
printf '%s\n' 'import os, runpy' \
   "runpy.run_path(os.environ['NLFILE'], run_name='nl_mod')" \
   "runpy.run_path(os.environ['LSFILE'], run_name='ls_mod')" > "${work}/driveN.py"
rawN="${work}/rawN"; mkdir --parents -- "${rawN}"
NLFILE="${nlfile}" LSFILE="${lsfile}" PYTHONUTF8=1 PYTHONPATH="${pkgN}" \
   COVERAGE_FILE="${rawN}/.coverage" python3 -m coverage run --parallel-mode -- \
   "${work}/driveN.py" >/dev/null 2>&1
combine_into "${work}/N/.coverage" "${rawN}"/.coverage.*
outN="${work}/outN.txt"
PYTHONUTF8=1 python3 "${helper}" "${work}/N/.coverage" "${rawN}" "${pkgN}" > "${outN}" 2>&1 || true
## Every str.splitlines() line must be blank or start with a DEBUG- record; a split filename
## tail (e.g. 'name.py 2') would be a forgeable extra line.
rcN=0
PYTHONUTF8=1 python3 - "${outN}" > /dev/null 2>&1 <<'PY' || rcN=$?
import sys
data = open(sys.argv[1], encoding='utf-8', errors='surrogateescape').read()
bad = [ln for ln in data.splitlines() if ln and not ln.startswith('DEBUG-')]
sys.exit(1 if bad else 0)
PY
if [ -s "${outN}" ] && [ "${rcN}" -eq 0 ]; then
   ok 0 'N: LF and U+2028 in a source filename cannot forge an extra output record'
else
   ok 1 'N: a line-break char in a filename split the output into a forgeable extra line'
fi

## ---- Case O: readable-but-irrelevant raw data -> drop=unknown, not a false drop=no --------
## The union side is judged by RELEVANCE, not mere readability. A valid, readable raw piece
## that measured only an UNRELATED package (a stale/mismatched snapshot) measures nothing under
## pkg_dir -> the cross-check cannot run, same as an empty raw dir. Counting readable pieces
## alone would skip the drop=unknown guard and print a confident, wrong drop=no for a real gap.
pkgO="${work}/pkgO"; mkdir --parents -- "${pkgO}"
otherO="${work}/otherO"; mkdir --parents -- "${otherO}"
printf '%s\n' 'def a():' '    return 1' 'def never():' '    return 3' > "${pkgO}/mod.py"
printf '%s\n' 'def foo():' '    return 42' > "${otherO}/unrelated.py"
printf '%s\n' 'import mod' 'mod.a()' > "${work}/drivePkgO.py"
printf '%s\n' 'import unrelated' 'unrelated.foo()' > "${work}/driveOtherO.py"
combO="${work}/O"; mkdir --parents -- "${combO}"
PYTHONPATH="${pkgO}" COVERAGE_FILE="${combO}/.coverage" python3 -m coverage run \
   --parallel-mode --source="${pkgO}" -- "${work}/drivePkgO.py" >/dev/null 2>&1
COVERAGE_FILE="${combO}/.coverage" python3 -m coverage combine >/dev/null 2>&1
rawO="${work}/rawO_irrel"; mkdir --parents -- "${rawO}"
PYTHONPATH="${otherO}" COVERAGE_FILE="${rawO}/.coverage" python3 -m coverage run \
   --parallel-mode --source="${otherO}" -- "${work}/driveOtherO.py" >/dev/null 2>&1
outO="${work}/outO.txt"
python3 "${helper}" "${combO}/.coverage" "${rawO}" "${pkgO}" > "${outO}" 2>&1 || true
if has "${outO}" 'drop=unknown' && ! has "${outO}" 'DEBUG-COMBINE-DROP' \
   && has "${outO}" 'DEBUG-MISSING mod.py'; then
   ok 0 'O: readable-but-irrelevant raw data -> drop=unknown (real gap not falsely cleared)'
else
   ok 1 'O: irrelevant raw data misreported (expected drop=unknown, real miss still shown)'
fi

## ---- Case P: key escaping is injective -- '\x0a'-literal vs real-LF names do not collide ---
## Two files whose REAL names differ only by "the 4 chars backslash-x-0-a" vs "one LF byte".
## If '\' is not itself escaped, both escape to the identical key 'weird\x0aname.py' and the
## later-sorted one silently overwrites the other in the results dict -> a real gap vanishes
## (combined=1). With the escape char escaped they stay distinct keys (combined=2).
pkgP="${work}/pkgP"; mkdir --parents -- "${pkgP}"
litfile="${pkgP}/$(printf 'weird\\x0aname.py')"   ## literal chars: backslash x 0 a
nlfile2="${pkgP}/$(printf 'weird\nname.py')"       ## a real newline byte
printf '%s\n' 'def never():' '    return 1' > "${litfile}"
printf '%s\n' 'def never():' '    return 1' > "${nlfile2}"
printf '%s\n' 'import os, runpy' \
   "runpy.run_path(os.environ['LITFILE'], run_name='lit_mod')" \
   "runpy.run_path(os.environ['NLFILE2'], run_name='nl2_mod')" > "${work}/driveP.py"
rawP="${work}/rawP"; mkdir --parents -- "${rawP}"
LITFILE="${litfile}" NLFILE2="${nlfile2}" PYTHONPATH="${pkgP}" \
   COVERAGE_FILE="${rawP}/.coverage" python3 -m coverage run --parallel-mode -- \
   "${work}/driveP.py" >/dev/null 2>&1
combine_into "${work}/P/.coverage" "${rawP}"/.coverage.*
outP="${work}/outP.txt"
python3 "${helper}" "${work}/P/.coverage" "${rawP}" "${pkgP}" > "${outP}" 2>&1 || true
if has "${outP}" 'combined=2'; then
   ok 0 'P: distinct filenames escaping-collision-free (injective key, no silent clobber)'
else
   ok 1 'P: two distinct filenames collided to one key (a real gap silently dropped)'
fi

printf '%s\n' '' "${pass} pass, ${fail} fail, 0 skip"
if [ "${fail}" -ne 0 ]; then
   exit 1
fi
printf '%s\n' 'OK: cov-debug-missing distinguishes a real gap from a combine drop, and never infers a drop from absent raw data'
