#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Assertion checker for root_lpe_audit_resolve_test.sh.

Targeted unit canary for dm-root-lpe-audit's target RESOLUTION. Imports the REAL
tool (argv[1]) as a module and drives build_index + resolve_targets over a small
synthetic file tree (controlled INPUT, not a copy of the subject).

The pinned contract: a BARE command (no '/') resolves the way its invoker would
search -- root's PATH for a shell/exec target, udevd's helper dirs for a udev
rule -- so among several shippers of one basename the one installed into a search
dir wins. A token CONTAINING '/' is a filesystem path: it resolves ONLY by its
exact install path, never guessed from the basename. Without this a real
'/usr/bin/foo' is dropped as "ambiguous" (a false negative on a security-inventory
tool) or a '/'-path silently audits the wrong file. Asserts:
  1. PATH shipper beats a same-name bash-completion data file (apt-get-noninteractive);
  2. PATH shipper beats a same-name off-PATH libexec helper (onion-time-pre-script);
  3. a helper shipped ONLY off the search path still resolves by its unique basename;
  4. two PATH shippers of one basename stay unresolved (genuine collision, not a guess);
  5. an ABSOLUTE token present in by_path resolves by exact install path (off-PATH dir);
  6. only the FIRST token of the program string is resolved (args ignored);
  7. a /usr/games shipper is NOT a root-PATH rival -- the /usr/bin shipper wins;
  8. a relative '/'-token is unresolved, not basename-guessed;
  9. an ABSOLUTE token absent from by_path is unresolved, not basename-guessed;
 10. an ABSOLUTE token present in by_path resolves exactly;
 11. a udev bare program prefers the /usr/lib/udev shipper over /usr/bin;
 12. the same bare name as a shell target prefers the /usr/bin shipper.
Cases 1, 2, 7, 8, 9 FAIL on the pre-fix tool. Prints 'N pass, N fail'.
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
    ## games dir is NOT root PATH: a /usr/bin vs /usr/games basename must not collide.
    ("F_real_bin",     "usr/bin/realcmd"),
    ("F_real_game",    "usr/games/realcmd"),
    ## udev program resolves against udevd's helper dirs, not root PATH.
    ("F_udev_bin",     "usr/bin/udevprog"),
    ("F_udev_hlp",     "usr/lib/udev/udevprog"),
    ## unique basename shipped only under /usr/bin -- used to prove a '/'-token is
    ## resolved by exact path, never guessed from the basename.
    ("F_slash_bin",    "usr/bin/slashcmd"),
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

    def resolve_udev(program):
        return sorted(module.resolve_targets(
            program, by_path, by_base, module.UDEV_HELPER_DIRS))

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
    ## games dir is not root PATH: /usr/bin shipper wins, /usr/games is not a rival.
    check("games dir is not a PATH collision (/usr/bin wins)",
          resolve("realcmd"), ["F_real_bin"], checks)
    ## a token with '/' is a path, resolved ONLY by exact install path.
    check("relative '/'-token is not basename-guessed (unresolved)",
          resolve("./slashcmd"), [], checks)
    check("absolute token missing from by_path is unresolved (not basename-guessed)",
          resolve("/opt/x/slashcmd"), [], checks)
    check("absolute token present in by_path resolves exactly",
          resolve("/usr/bin/slashcmd"), ["F_slash_bin"], checks)
    ## udev program resolves against udevd's helper dirs, not root PATH.
    check("udev bare program prefers the udev helper-dir shipper",
          resolve_udev("udevprog"), ["F_udev_hlp"], checks)
    check("same bare name on root PATH prefers the /usr/bin shipper",
          resolve("udevprog"), ["F_udev_bin"], checks)

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
