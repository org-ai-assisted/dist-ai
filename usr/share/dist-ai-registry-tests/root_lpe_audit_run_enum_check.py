#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Assertion checker for root_lpe_audit_run_enum_test.sh.

Targeted unit canary for dm-root-lpe-audit's run_enum contract. Imports the REAL
tool (argv[1]) as a module and calls run_enum directly with a tool_dir holding a
STUB dm-root-scripts-enum (a controlled test INPUT, not a copy of the subject).

run_enum must FAIL CLOSED on UNUSABLE enumerator output -- no output, non-JSON or
undecodable bytes, or a non-object document -- so a broken enum run cannot look
clean. It must NOT key fail-close on the exit CODE: the enum prints a complete
report and then exits nonzero as a "wrong root?" advisory, and the audit's own
root-guarded scan must still run on that report, so a nonzero exit with a valid
JSON object must be RETURNED, not aborted (else real LPE findings are silently
dropped -- a false negative on a security tool). Asserts:
  1. no output (nonzero exit)          -> SystemExit;
  2. non-JSON text                     -> clean SystemExit (not a traceback);
  3. non-UTF-8 bytes                   -> clean SystemExit (not a traceback);
  4. valid JSON that is not an object  -> clean SystemExit (not a later crash);
  5. valid JSON object with NONZERO exit -> run_enum RETURNS it (no false negative);
  6. valid JSON object with exit 0     -> run_enum RETURNS it (positive control);
  7. report with non-empty parse_errors -> SystemExit (degraded, incomplete scan);
  8. report with non-empty walk_errors  -> SystemExit (degraded, incomplete scan);
  9. report with EMPTY error lists + nonzero exit -> RETURNED (the legitimate
     zero-entries advisory is complete, not degraded -- must not fail closed).
Prints 'N pass, N fail'.
"""

import importlib.util
import os
import shutil
import stat
import sys
import tempfile
from importlib.machinery import SourceFileLoader


def load_subject(path):
    ## Explicit loader: the tool has no .py extension, so spec_from_file_location
    ## cannot infer one. __name__ != "__main__" so the module's main() does not run
    ## on import; its own sys.path insert (resolved from __file__) finds dist_ai.
    name = "dm_root_lpe_audit_under_test"
    loader = SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def make_stub_dir(enum_name, body, temp_dirs):
    stub_dir = tempfile.mkdtemp(prefix="lpe-run-enum-")
    temp_dirs.append(stub_dir)
    stub = os.path.join(stub_dir, enum_name)
    with open(stub, "wb") as handle:
        handle.write(body)
    os.chmod(stub, os.stat(stub).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return stub_dir


def expect_systemexit(module, stub_dir, description, checks):
    try:
        module.run_enum("unused-dm-root", stub_dir)
    except SystemExit:
        checks.append((description, True))
    except BaseException as exc:  # noqa: BLE001
        checks.append(("%s (got %s instead)" % (description, type(exc).__name__),
                       False))
    else:
        checks.append(("%s (returned normally, not fail-closed)" % description,
                       False))


def expect_return(module, stub_dir, description, checks):
    try:
        out = module.run_enum("unused-dm-root", stub_dir)
    except BaseException as exc:  # noqa: BLE001
        checks.append(("%s (raised %s)" % (description, type(exc).__name__), False))
    else:
        checks.append((description, isinstance(out, dict) and out.get("ok") is True))


## Stub enum bodies (written verbatim as bytes). 0xFF is invalid UTF-8.
NO_OUTPUT_EXIT_NONZERO = b"#!/bin/sh\nexit 1\n"
INVALID_JSON_EXIT_ZERO = b"#!/bin/sh\nprintf '%s\\n' 'this is { not json'\nexit 0\n"
NON_UTF8_EXIT_ZERO = b"#!/bin/sh\nprintf '\\377'\nexit 0\n"
VALID_JSON_NON_OBJECT = b"#!/bin/sh\nprintf '%s\\n' '[1, 2, 3]'\nexit 0\n"
VALID_OBJECT_EXIT_NONZERO = b'#!/bin/sh\nprintf \'%s\\n\' \'{"ok": true}\'\nexit 3\n'
VALID_OBJECT_EXIT_ZERO = b'#!/bin/sh\nprintf \'%s\\n\' \'{"ok": true}\'\nexit 0\n'
DEGRADED_PARSE_ERRORS = (b'#!/bin/sh\nprintf \'%s\\n\''
                         b' \'{"ok": true, "parse_errors": ["x"], "walk_errors": []}\'\n'
                         b'exit 1\n')
DEGRADED_WALK_ERRORS = (b'#!/bin/sh\nprintf \'%s\\n\''
                        b' \'{"ok": true, "parse_errors": [], "walk_errors": ["x"]}\'\n'
                        b'exit 1\n')
COMPLETE_EMPTY_ERRORS_EXIT_NONZERO = (
    b'#!/bin/sh\nprintf \'%s\\n\''
    b' \'{"ok": true, "parse_errors": [], "walk_errors": []}\'\nexit 1\n')


def main(argv):
    if len(argv) != 2:
        print("FATAL: usage: root_lpe_audit_run_enum_check.py <dm-root-lpe-audit>",
              file=sys.stderr)
        return 1
    subject = argv[1]
    if not os.path.isfile(subject):
        print("FATAL: subject not found: %s" % subject, file=sys.stderr)
        return 1

    module = load_subject(subject)
    enum_name = module.ENUM_TOOL  ## real constant -> no drift from the subject

    checks: list[tuple[str, bool]] = []
    temp_dirs: list[str] = []
    try:
        expect_systemexit(
            module, make_stub_dir(enum_name, NO_OUTPUT_EXIT_NONZERO, temp_dirs),
            "no output -> SystemExit", checks)
        expect_systemexit(
            module, make_stub_dir(enum_name, INVALID_JSON_EXIT_ZERO, temp_dirs),
            "non-JSON output -> clean SystemExit (no traceback)", checks)
        expect_systemexit(
            module, make_stub_dir(enum_name, NON_UTF8_EXIT_ZERO, temp_dirs),
            "non-UTF-8 output -> clean SystemExit (no traceback)", checks)
        expect_systemexit(
            module, make_stub_dir(enum_name, VALID_JSON_NON_OBJECT, temp_dirs),
            "valid non-object JSON -> clean SystemExit (no later crash)", checks)
        expect_return(
            module, make_stub_dir(enum_name, VALID_OBJECT_EXIT_NONZERO, temp_dirs),
            "nonzero exit with valid JSON object -> returned (no false negative)",
            checks)
        expect_return(
            module, make_stub_dir(enum_name, VALID_OBJECT_EXIT_ZERO, temp_dirs),
            "exit 0 with valid JSON object -> returned (positive control)", checks)
        expect_systemexit(
            module, make_stub_dir(enum_name, DEGRADED_PARSE_ERRORS, temp_dirs),
            "report with parse_errors -> SystemExit (degraded, incomplete)", checks)
        expect_systemexit(
            module, make_stub_dir(enum_name, DEGRADED_WALK_ERRORS, temp_dirs),
            "report with walk_errors -> SystemExit (degraded, incomplete)", checks)
        expect_return(
            module,
            make_stub_dir(enum_name, COMPLETE_EMPTY_ERRORS_EXIT_NONZERO, temp_dirs),
            "empty error lists + nonzero exit -> returned (complete advisory)",
            checks)
    finally:
        for stub_dir in temp_dirs:
            shutil.rmtree(stub_dir, ignore_errors=True)

    passed = 0
    failed = 0
    for description, ok in checks:
        if ok:
            passed += 1
            print("PASS: %s" % description)
        else:
            failed += 1
            print("FAIL: %s" % description)
    print("")
    print("root-lpe-audit-run-enum: %d pass, %d fail" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
