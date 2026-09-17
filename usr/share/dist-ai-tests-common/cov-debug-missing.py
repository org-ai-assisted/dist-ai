#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Attribute a coverage MISS so a sub-100% gate run is self-diagnosing instead of a bare
## "total of 99 is less than fail-under=100". Answers the flake-vs-gap question empirically:
## a line the COMBINED data reports missing is either
##   - missing in every pre-combine parallel data file too  -> a real coverage gap (no suite
##     recorded it), OR
##   - present in a MANUAL union of those same parallel files but absent from `coverage
##     combine`'s result -> a combine/measurement DROP (a flake: some suite DID record the
##     line, but it was lost merging).
## Comparing the two missing sets tells them apart in a SINGLE run; comparing the per-run
## summary across many runs tells a flaky line (varies) from a real gap (constant).
##
##   cov-debug-missing.py <combined-data-file> <raw-parallel-dir> <pkg-dir>
##
## Emits greppable one-line records (stable, easy to diff across runs):
##   DEBUG-MISSING <module.py> <line-spec>            per module the COMBINED data misses
##   DEBUG-UNION-MISSING <module.py> <line-spec>      per module a MANUAL union still misses
##   DEBUG-COMBINE-DROP <module.py> combine=<spec> union=<spec>   combine lost data the union kept
##   DEBUG-MISSING-SUMMARY combined=<n> union=<n> drop=<yes|no|unknown>   one line per run
## drop=unknown means no pre-combine data was preserved (raw_files=0), so gap-vs-drop could
## not be cross-checked -- never inferred as a drop from an absent union.
## Read-only; never fails the gate (best-effort diagnostics).

import glob
import os
import sys
import tempfile

import coverage
from coverage.sqldata import CoverageData


def _missing_by_module(data_file, pkg_dir):
    """{package_relative_path: (missing_line_set, missing_formatted)} for every measured
    package source file that has at least one missing line, using coverage's own statement
    analysis of the combined data."""
    cov = coverage.Coverage(data_file=data_file)
    cov.load()
    pkg_real = os.path.realpath(pkg_dir)
    out = {}
    for measured in sorted(cov.get_data().measured_files()):
        if os.path.realpath(measured).startswith(pkg_real + os.sep):
            try:
                ## analysis2 -> (filename, statements, excluded, missing, missing_formatted)
                _, _, _, missing, missing_fmt = cov.analysis2(measured)
            except coverage.CoverageException:
                ## Best-effort diagnostics: a measured file gone from disk (a cleaned
                ## build/tmp dir between the coverage run and this later invocation)
                ## raises NoSource -- but the docstring promises this never fails the
                ## gate, so skip the unreadable file rather than crash.
                continue
            if missing:
                ## Key by the path RELATIVE to the package, not basename: two files with
                ## the same name in different subpackages (e.g. a/__init__.py and
                ## b/__init__.py) would otherwise collide and silently drop one's gaps.
                ## Store the missing-line SET (for a direction-aware drop check) plus the
                ## formatted string (for display).
                key = os.path.relpath(os.path.realpath(measured), pkg_real)
                out[key] = (frozenset(missing), missing_fmt)
    return out


def _manual_union_missing(raw_dir, pkg_dir):
    """Same, but from a MANUAL union of the raw pre-combine parallel data files -- the
    independent cross-check against `coverage combine`."""
    ## glob.escape the DIRECTORY: a raw_dir path containing a glob metacharacter
    ## ('[', '*', '?') would otherwise be mis-read (e.g. '[abc]' as a char class),
    ## match nothing, and falsely report every gap as a combine drop. The
    ## '.coverage.*' pattern stays a real glob.
    raw_files = sorted(glob.glob(os.path.join(glob.escape(raw_dir), ".coverage.*")))
    if not raw_files:
        return {}, 0
    merged_fd, merged_path = tempfile.mkstemp(prefix="cov-union-", suffix=".coverage")
    os.close(merged_fd)
    try:
        merged = CoverageData(basename=merged_path)
        for raw in raw_files:
            piece = CoverageData(basename=raw)
            piece.read()
            merged.update(piece)
        merged.write()
        return _missing_by_module(merged_path, pkg_dir), len(raw_files)
    finally:
        try:
            os.remove(merged_path)
        except OSError:
            pass


def main():
    if len(sys.argv) != 4:
        sys.stderr.write("cov-debug-missing.py <combined-data-file> <raw-parallel-dir> <pkg-dir>\n")
        return 2
    combined_data, raw_dir, pkg_dir = sys.argv[1], sys.argv[2], sys.argv[3]

    combined = _missing_by_module(combined_data, pkg_dir)
    union, n_raw = _manual_union_missing(raw_dir, pkg_dir)

    for module in sorted(combined):
        print("DEBUG-MISSING %s %s" % (module, combined[module][1]))

    if n_raw == 0:
        # No pre-combine parallel data was preserved, so the union cross-check cannot run.
        # Do NOT infer a combine-drop from an empty union -- that would flag every real,
        # constant coverage gap as a flake (the exact inversion this tool exists to avoid).
        # Report the combined misses as-is and mark the drop verdict unknown.
        print("DEBUG-MISSING-SUMMARY combined=%d union=n/a raw_files=0 "
              "drop=unknown (no pre-combine data preserved; cross-check skipped)"
              % len(combined))
        return 0

    for module in sorted(union):
        print("DEBUG-UNION-MISSING %s %s" % (module, union[module][1]))

    drop = False
    ## A combine DROP is combine LOSING coverage the raw union HELD: the combined data is
    ## missing a line the union is NOT missing (combined covered less than the raw files
    ## did). The REVERSE -- union missing MORE than combined -- just means the raw-dir
    ## snapshot passed in was incomplete (a parallel raw file was not archived into it),
    ## NOT a drop, so a bare `combined != union` mismatch would false-positive on it.
    for module in sorted(set(combined) | set(union)):
        c_set, c_fmt = combined.get(module, (frozenset(), ""))
        u_set, u_fmt = union.get(module, (frozenset(), ""))
        if c_set - u_set:
            drop = True
            print("DEBUG-COMBINE-DROP %s combine=%r union=%r" % (module, c_fmt, u_fmt))

    print("DEBUG-MISSING-SUMMARY combined=%d union=%d raw_files=%d drop=%s"
          % (len(combined), len(union), n_raw, "yes" if drop else "no"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
