#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Assertion checker for root_lpe_audit_resolve_test.sh.

Targeted unit canary for dm-root-lpe-audit's target RESOLUTION. Imports the REAL
tool (argv[1]) as a module and drives build_index + resolve_targets over a small
synthetic file tree (controlled INPUT, not a copy of the subject).

The pinned contract: a BARE command (no '/') resolves the way root's shell does,
via PATH, so among several shippers of one basename the one installed onto a PATH
command dir wins. Without this a real '/usr/bin/foo' is dropped as "ambiguous"
merely because a bash-completion data file or an off-PATH libexec helper ships
the same basename -- silently removing a root-reachable script from the audited
surface (a false negative on a security-inventory tool). Asserts:
  1. PATH shipper beats a same-name bash-completion data file (apt-get-noninteractive);
  2. PATH shipper beats a same-name off-PATH libexec helper (onion-time-pre-script);
  3. a helper shipped ONLY off PATH still resolves by its unique basename (no regression);
  4. two PATH shippers of one basename stay unresolved (genuine collision, not a guess);
  5. an ABSOLUTE token still resolves by exact install path (off-PATH dir included);
  6. only the FIRST token of the program string is resolved (args ignored).
Cases 1 and 2 FAIL on the pre-fix tool (it returned [] for both). Prints 'N pass, N fail'.
"""

import os
import sys
from importlib.machinery import SourceFileLoader
import importlib.util


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


## (tree file identity, source rel path). The abs is an opaque token returned
## verbatim by resolve_targets; only the rel path (its FHS install location) matters.
FIXTURE = [
    ("F_apt_bin",      "usr/bin/apt-get-noninteractive"),
    ("F_apt_comp",     "usr/share/bash-completion/completions/apt-get-noninteractive"),
    ("F_onion_bin",    "usr/bin/onion-time-pre-script"),
    ("F_onion_lx",     "usr/libexec/helper-scripts/onion-time-pre-script"),
    ("F_only_lx",      "usr/libexec/pkg/onlyhelper"),
    ("F_dup_bin",      "usr/bin/dup"),
    ("F_dup_sbin",     "usr/sbin/dup"),
]


def check(description, got, want, checks):
    checks.append((description, got == want))


def main(argv):
    if len(argv) != 2:
        print("FATAL: usage: root_lpe_audit_resolve_check.py <dm-root-lpe-audit>",
              file=sys.stderr)
        return 1
    subject = argv[1]
    if not os.path.isfile(subject):
        print("FATAL: subject not found: %s" % subject, file=sys.stderr)
        return 1

    module = load_subject(subject)
    ## No submodules: each rel path installs from the tree root (parts[0] is the
    ## FHS top), exercising the real build_index / install_path_for / component_for.
    by_path, by_base = module.build_index(FIXTURE, [])

    def resolve(program):
        return sorted(module.resolve_targets(program, by_path, by_base))

    checks: list[tuple[str, bool]] = []
    check("PATH shipper beats bash-completion data file",
          resolve("apt-get-noninteractive"), ["F_apt_bin"], checks)
    check("PATH shipper beats off-PATH libexec helper",
          resolve("onion-time-pre-script"), ["F_onion_bin"], checks)
    check("off-PATH-only helper resolves by unique basename (no regression)",
          resolve("onlyhelper"), ["F_only_lx"], checks)
    check("two PATH shippers stay unresolved (genuine collision)",
          resolve("dup"), [], checks)
    check("absolute token resolves by exact install path (off-PATH)",
          resolve("/usr/libexec/helper-scripts/onion-time-pre-script"),
          ["F_onion_lx"], checks)
    check("only the first token is resolved (args ignored)",
          resolve("apt-get-noninteractive --yes pkg"), ["F_apt_bin"], checks)

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
    print("root-lpe-audit-resolve: %d pass, %d fail" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
