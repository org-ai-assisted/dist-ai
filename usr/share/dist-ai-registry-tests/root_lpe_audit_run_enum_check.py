#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Assertion checker for root_lpe_audit_run_enum_test.sh.

Targeted unit canary for dm-root-lpe-audit's run_enum fail-closed contract.
Imports the REAL tool (argv[1]) as a module and calls run_enum directly with a
tool_dir holding a STUB dm-root-scripts-enum (a controlled test INPUT, not a copy
of the subject). A security-inventory tool must FAIL CLOSED: a degraded enum run
(nonzero exit, or non-JSON stdout) must stop the audit, never look clean. Asserts:
  1. enum exits nonzero but prints valid JSON -> SystemExit (not silently accepted);
  2. enum exits 0 but prints invalid JSON   -> SystemExit (clean, not a traceback);
  3. positive control: enum exits 0 with valid JSON -> run_enum returns the dict
     (proves the stub harness really drives run_enum, so 1+2 are not vacuous).
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
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def make_stub_dir(enum_name, body, temp_dirs):
    stub_dir = tempfile.mkdtemp(prefix="lpe-run-enum-")
    temp_dirs.append(stub_dir)
    stub = os.path.join(stub_dir, enum_name)
    with open(stub, "w", encoding="utf-8") as handle:
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


VALID_JSON_EXIT_NONZERO = '#!/bin/sh\nprintf \'%s\\n\' \'{"ok": true}\'\nexit 3\n'
INVALID_JSON_EXIT_ZERO = '#!/bin/sh\nprintf \'%s\\n\' \'this is { not json\'\nexit 0\n'
VALID_JSON_EXIT_ZERO = '#!/bin/sh\nprintf \'%s\\n\' \'{"ok": true}\'\nexit 0\n'


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

    checks = []
    temp_dirs = []
    try:
        expect_systemexit(
            module,
            make_stub_dir(enum_name, VALID_JSON_EXIT_NONZERO, temp_dirs),
            "enum exits nonzero with valid JSON -> SystemExit", checks)
        expect_systemexit(
            module,
            make_stub_dir(enum_name, INVALID_JSON_EXIT_ZERO, temp_dirs),
            "enum emits invalid JSON -> clean SystemExit (no traceback)", checks)
        expect_return(
            module,
            make_stub_dir(enum_name, VALID_JSON_EXIT_ZERO, temp_dirs),
            "enum exits 0 with valid JSON -> run_enum returns the parsed dict",
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
