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
##
## A DROP is only ever inferred where the union actually MEASURED the module: a module the
## raw snapshot never measured (an incomplete snapshot) is undecidable, not a drop -- the
## per-module analogue of the raw_files=0 guard.
##
## relative_files: coverage records paths relative to the record root when
## relative_files=True (its recommended mode for combining across machines/containers -- this
## tool's scenario), and resolves them against cwd. main() chdir's to the combined data
## file's directory (the record root in coverage's canonical combine layout) so both the
## containment filter and analysis2 resolve those paths; a wrong guess fails SAFE (NoSource
## -> skip), never a silent all-missing. Absolute-path data ignores cwd -> unaffected.
##
## Read-only; never fails the gate (best-effort diagnostics): corrupt/unreadable data and a
## vanished source are skipped, never a crash.

import glob
import os
import sys
import tempfile

import coverage
from coverage.sqldata import CoverageData


def _missing_by_module(data_file, pkg_dir):
    """({package_relative_path: (missing_line_set, missing_formatted)}, measured_key_set)
    for package source files, using coverage's own statement analysis. The dict holds only
    files WITH missing lines (for display + the drop check); measured_key_set holds EVERY
    package file coverage measured (even fully covered ones), so the drop check can tell
    'union covered it fully' from 'union never MEASURED it'. Best-effort: corrupt data or a
    vanished source is skipped, never a crash."""
    cov = coverage.Coverage(data_file=data_file)
    try:
        cov.load()
    except coverage.CoverageException:
        ## A truncated/corrupt .coverage data file raises DataError -- but the docstring
        ## promises this never fails the gate, so report nothing rather than crash.
        return {}, set()
    pkg_real = os.path.realpath(pkg_dir)
    out = {}
    measured_keys = set()
    for measured in sorted(cov.get_data().measured_files()):
        ## main() has chdir'd to the record root, so realpath resolves a relative_files
        ## path against that root (and an absolute path is unaffected by cwd).
        real = os.path.realpath(measured)
        if real.startswith(pkg_real + os.sep):
            try:
                ## analysis2 -> (filename, statements, excluded, missing, missing_formatted).
                ## Pass the path AS RECORDED so coverage's own data lookup matches (a
                ## relative morf resolves against cwd == the record root).
                _, _, _, missing, missing_fmt = cov.analysis2(measured)
            except coverage.CoverageException:
                ## A measured file gone from disk (a cleaned build/tmp dir between the
                ## coverage run and this later invocation), or unresolvable against the
                ## record root, raises NoSource -- skip the unreadable file rather than
                ## crash. Excluded from measured_keys too, so it is judged on neither side.
                continue
            ## Key by the path RELATIVE to the package, not basename: two files with the
            ## same name in different subpackages (e.g. a/__init__.py and b/__init__.py)
            ## would otherwise collide and silently drop one's gaps.
            key = os.path.relpath(real, pkg_real)
            measured_keys.add(key)
            if missing:
                ## Store the missing-line SET (for a direction-aware drop check) plus the
                ## formatted string (for display).
                out[key] = (frozenset(missing), missing_fmt)
    return out, measured_keys


def _manual_union_missing(raw_dir, pkg_dir):
    """Same, but from a MANUAL union of the raw pre-combine parallel data files -- the
    independent cross-check against `coverage combine`. Returns
    (missing_dict, measured_key_set, n_raw)."""
    ## glob.escape the DIRECTORY: a raw_dir path containing a glob metacharacter
    ## ('[', '*', '?') would otherwise be mis-read (e.g. '[abc]' as a char class),
    ## match nothing, and falsely report every gap as a combine drop. The
    ## '.coverage.*' pattern stays a real glob.
    raw_files = sorted(glob.glob(os.path.join(glob.escape(raw_dir), ".coverage.*")))
    if not raw_files:
        return {}, set(), 0
    merged_fd, merged_path = tempfile.mkstemp(prefix="cov-union-", suffix=".coverage")
    os.close(merged_fd)
    try:
        merged = CoverageData(basename=merged_path)
        for raw in raw_files:
            piece = CoverageData(basename=raw)
            try:
                piece.read()
            except coverage.CoverageException:
                ## A corrupt raw piece never fails the gate: skip it, keep the readable
                ## ones so the cross-check still runs on what survived.
                continue
            merged.update(piece)
        merged.write()
        missing, measured = _missing_by_module(merged_path, pkg_dir)
        return missing, measured, len(raw_files)
    finally:
        try:
            os.remove(merged_path)
        except OSError:
            pass


def main():
    if len(sys.argv) != 4:
        sys.stderr.write("cov-debug-missing.py <combined-data-file> <raw-parallel-dir> <pkg-dir>\n")
        return 2
    ## Resolve to absolute BEFORE the chdir below, so relative argv paths survive it.
    combined_data = os.path.realpath(sys.argv[1])
    raw_dir = os.path.realpath(sys.argv[2])
    pkg_dir = os.path.realpath(sys.argv[3])

    ## relative_files data records paths relative to the record root and coverage resolves
    ## them against cwd. In coverage's canonical combine layout the combined data file sits
    ## at that root, so chdir there once: it anchors BOTH the combined-data pass and the
    ## merged-union pass (same relative paths, same root). A wrong guess fails SAFE
    ## (analysis2 -> NoSource -> skip), never the silent all-missing that an absolute-join
    ## lookup would produce against relative-keyed data. Absolute-path data ignores cwd.
    try:
        os.chdir(os.path.dirname(combined_data))
    except OSError:
        pass

    combined, _ = _missing_by_module(combined_data, pkg_dir)
    union, union_measured, n_raw = _manual_union_missing(raw_dir, pkg_dir)

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
    for module in sorted(set(combined) | set(union)):
        if module not in union_measured:
            ## The union never MEASURED this module (an incomplete raw snapshot: a parallel
            ## raw file that measures it was not archived into the raw dir). gap-vs-drop is
            ## undecidable for it -- never infer a drop, the per-module analogue of the
            ## raw_files=0 guard. A module the union measured but fully covered IS in
            ## union_measured (u_set empty), so a genuine drop against it still fires below.
            continue
        c_set, c_fmt = combined.get(module, (frozenset(), ""))
        u_set, u_fmt = union.get(module, (frozenset(), ""))
        ## A combine DROP is combine LOSING coverage the raw union HELD: the combined data
        ## is missing a line the union is NOT missing (combined covered less than the raw
        ## files did). The REVERSE -- union missing MORE than combined -- just means the raw
        ## snapshot was incomplete, NOT a drop, so a bare `combined != union` mismatch would
        ## false-positive on it.
        if c_set - u_set:
            drop = True
            print("DEBUG-COMBINE-DROP %s combine=%r union=%r" % (module, c_fmt, u_fmt))

    print("DEBUG-MISSING-SUMMARY combined=%d union=%d raw_files=%d drop=%s"
          % (len(combined), len(union), n_raw, "yes" if drop else "no"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
