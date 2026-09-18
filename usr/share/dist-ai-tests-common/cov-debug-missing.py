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
##
## drop=unknown means no USABLE pre-combine data was preserved (raw dir empty, or every raw
## piece unreadable), so gap-vs-drop could not be cross-checked -- never inferred as a drop
## from an absent/empty union, which would flag every real, constant gap as a flake.
##
## A DROP is only ever inferred where the union actually MEASURED the module, symmetrically:
##   - union measured it, combined did NOT measure it at all -> combine lost the whole file.
##   - both measured it, combined misses a line the union COVERS -> combine lost that line.
## A module the union never measured (an incomplete raw snapshot) is undecidable, not a drop
## -- the per-module analogue of the drop=unknown guard. The REVERSE (union missing MORE than
## combined -- an incomplete snapshot) is likewise not a drop.
##
## relative_files: coverage records paths relative to the record root when relative_files=True
## (its recommended mode for combining across machines/containers). When the data is keyed
## that way this tool enables relative mode on its OWN reporting object and chdir's to the
## record root (the combined data file's directory, in coverage's canonical combine layout)
## so analysis resolves those paths; a wrong root fails SAFE (NoSource -> skip), never a
## silent all-missing. It never reads an on-disk coverage config (config_file=False), so a
## malformed sibling .coveragerc/pyproject next to the data cannot crash the gate.
##
## Read-only; never fails the gate (best-effort diagnostics): corrupt/unreadable data, a
## vanished source, and a filename with control characters are all handled without a crash or
## a forged output record.

import glob
import os
import sys
import tempfile

import coverage
from coverage.sqldata import CoverageData

## Escape control characters (incl. NUL, newline, CR, tab, DEL) so every DEBUG-* record
## stays a single physical line. A POSIX filename may legally contain a newline; without this
## a crafted source path under pkg_dir could split its record and forge an extra line (e.g. a
## fake "drop=no" summary) into the greppable output stream.
_CTRL = {c: "\\x%02x" % c for c in list(range(0x20)) + [0x7f]}


def _safe(text):
    return text.translate(_CTRL)


def _analysis_missing(data_file, pkg_dir, root):
    """({package_relative_path: (missing_line_set, missing_formatted)}, measured_key_set) for
    package source files, using coverage's own statement analysis. The dict holds only files
    WITH missing lines (for display + the drop check); measured_key_set holds EVERY package
    file coverage measured (even fully covered ones), so the drop check can tell 'covered it
    fully' from 'never MEASURED it' on both sides. Best-effort: corrupt data, a vanished
    source, or a malformed sibling config is skipped, never a crash."""
    pkg_real = os.path.realpath(pkg_dir)
    ## Peek at the stored keys to decide whether the data is relative_files (record-root
    ## relative) vs absolute -- this also catches a truncated/corrupt data file (DataError)
    ## before any analysis.
    probe = CoverageData(basename=data_file)
    try:
        probe.read()
        stored = probe.measured_files()
    except coverage.CoverageException:
        return {}, set()
    is_relative = any(not os.path.isabs(m) for m in stored)
    ## config_file=False: never read an on-disk .coveragerc/pyproject (a malformed one raises
    ## ConfigError -- NOT a CoverageException -- and would crash the gate). relative_files is
    ## set explicitly instead of inferred from a config, so a relative lookup is deterministic.
    cov = coverage.Coverage(data_file=data_file, config_file=False)
    if is_relative:
        cov.config.relative_files = True
    prev_cwd = os.getcwd()
    out = {}
    measured_keys = set()
    try:
        if is_relative:
            ## coverage resolves relative morfs against cwd; anchor to the record root.
            try:
                os.chdir(root)
            except OSError:
                return {}, set()
        try:
            cov.load()
        except coverage.CoverageException:
            return {}, set()
        for measured in sorted(cov.get_data().measured_files()):
            real = os.path.realpath(measured)
            if not real.startswith(pkg_real + os.sep):
                continue
            try:
                ## analysis2 -> (filename, statements, excluded, missing, missing_formatted).
                ## Pass the path AS RECORDED so coverage's data lookup matches; a relative
                ## morf resolves against cwd == the record root (source + data both). A wrong
                ## root or a source gone from disk raises NoSource -> skip (never all-missing).
                _, _, _, missing, missing_fmt = cov.analysis2(measured)
            except coverage.CoverageException:
                continue
            ## Key by the path RELATIVE to the package, not basename: two files with the same
            ## name in different subpackages (a/__init__.py, b/__init__.py) would otherwise
            ## collide and silently drop one's gaps. Control-char-safe for one-line records.
            key = _safe(os.path.relpath(real, pkg_real))
            measured_keys.add(key)
            if missing:
                out[key] = (frozenset(missing), missing_fmt)
    finally:
        os.chdir(prev_cwd)
    return out, measured_keys


def _manual_union_missing(raw_dir, pkg_dir, root):
    """Same, but from a MANUAL union of the raw pre-combine parallel data files -- the
    independent cross-check against `coverage combine`. Returns
    (missing_dict, measured_key_set, n_raw, n_usable): n_raw is how many raw files were found,
    n_usable how many were actually readable and merged (a corrupt piece is skipped)."""
    ## glob.escape the DIRECTORY: a raw_dir path containing a glob metacharacter
    ## ('[', '*', '?') would otherwise be mis-read (e.g. '[abc]' as a char class), match
    ## nothing, and falsely report every gap as a combine drop. The '.coverage.*' pattern
    ## stays a real glob.
    raw_files = sorted(glob.glob(os.path.join(glob.escape(raw_dir), ".coverage.*")))
    if not raw_files:
        return {}, set(), 0, 0
    merged_fd, merged_path = tempfile.mkstemp(prefix="cov-union-", suffix=".coverage")
    os.close(merged_fd)
    try:
        merged = CoverageData(basename=merged_path)
        n_usable = 0
        for raw in raw_files:
            piece = CoverageData(basename=raw)
            try:
                piece.read()
            except coverage.CoverageException:
                ## A corrupt raw piece never fails the gate: skip it, keep the readable ones.
                continue
            merged.update(piece)
            n_usable += 1
        merged.write()
        missing, measured = _analysis_missing(merged_path, pkg_dir, root)
        return missing, measured, len(raw_files), n_usable
    finally:
        try:
            os.remove(merged_path)
        except OSError:
            pass


def main():
    if len(sys.argv) != 4:
        sys.stderr.write("cov-debug-missing.py <combined-data-file> <raw-parallel-dir> <pkg-dir>\n")
        return 2
    ## Resolve to absolute before any chdir inside the analysis helpers.
    combined_data = os.path.realpath(sys.argv[1])
    raw_dir = os.path.realpath(sys.argv[2])
    pkg_dir = os.path.realpath(sys.argv[3])
    ## Record root for relative_files data: the combined data file's directory in coverage's
    ## canonical combine layout. Both the combined pass and the merged-union pass share it
    ## (the raw pieces record against the same root).
    root = os.path.dirname(combined_data)

    combined, combined_measured = _analysis_missing(combined_data, pkg_dir, root)
    union, union_measured, n_raw, n_usable = _manual_union_missing(raw_dir, pkg_dir, root)

    for module in sorted(combined):
        print("DEBUG-MISSING %s %s" % (module, combined[module][1]))

    if n_usable == 0:
        ## No USABLE pre-combine data (dir empty, or every piece unreadable), so the union
        ## cross-check cannot run. Do NOT infer a combine-drop from an empty union -- that
        ## would flag every real, constant gap as a flake (the exact inversion this tool
        ## exists to avoid). Report the combined misses as-is; drop verdict unknown.
        if n_raw == 0:
            reason = "no pre-combine data preserved"
        else:
            reason = "all %d raw piece(s) unreadable" % n_raw
        print("DEBUG-MISSING-SUMMARY combined=%d union=n/a raw_files=%d "
              "drop=unknown (%s; cross-check skipped)" % (len(combined), n_raw, reason))
        return 0

    for module in sorted(union):
        print("DEBUG-UNION-MISSING %s %s" % (module, union[module][1]))

    drop = False
    ## A combine DROP is combine LOSING coverage the raw union HELD. Judge only modules the
    ## union actually MEASURED (a module the union never measured is an incomplete snapshot,
    ## undecidable -- never a drop). Two drop shapes:
    for module in sorted(union_measured):
        u_set, u_fmt = union.get(module, (frozenset(), ""))
        if module not in combined_measured:
            ## Combined never measured a file the union did -> combine lost the whole file.
            drop = True
            print("DEBUG-COMBINE-DROP %s combine=%r union=%r" % (module, "(absent)", u_fmt))
            continue
        c_set, c_fmt = combined.get(module, (frozenset(), ""))
        ## Both measured it: a drop is a line combined misses that the union COVERS. The
        ## REVERSE (union missing more) is just an incomplete snapshot, not a drop, so a bare
        ## `combined != union` mismatch would false-positive on it.
        if c_set - u_set:
            drop = True
            print("DEBUG-COMBINE-DROP %s combine=%r union=%r" % (module, c_fmt, u_fmt))

    print("DEBUG-MISSING-SUMMARY combined=%d union=%d raw_files=%d drop=%s"
          % (len(combined), len(union), n_raw, "yes" if drop else "no"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
