#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## The REAL strings.bsh must carry NO symlink-follow LPE sink. br_add_to_file
## produces "${file}_br" via an mktemp temp + atomic 'mv --no-target-directory'
## (rename REPLACES a symlink at the destination, never follows it), NOT the old
## in-place 'touch'/'tee -a' that open the final name directly. Drives the
## shipped dist_ai.lpe_sinks scanner over the real file (no copy). FAILS on the
## pre-fix touch/tee code (two symlink-follow findings at the br_add_to_file
## lines). Used by br_add_to_file_no_symlink_follow_test.sh.

import os
import sys

_LIB = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.realpath(__file__)))),
    "lib", "python3", "dist-packages")
if os.path.isdir(_LIB) and _LIB not in sys.path:
    sys.path.insert(0, _LIB)

from dist_ai import bash_ast, lpe_sinks  # noqa: E402


def main(argv):
    if len(argv) != 2:
        print("FATAL: usage: %s <strings.bsh>" % argv[0], file=sys.stderr)
        return 2
    path = argv[1]
    try:
        with open(path, "r", encoding="utf-8") as handle:
            source = handle.read()
    except OSError as exc:
        print("FATAL: cannot read '%s': %s" % (path, exc), file=sys.stderr)
        return 2
    try:
        tree = bash_ast.parse_normalized(source)
    except bash_ast.BashParseError as exc:
        print("FATAL: cannot parse '%s': %s" % (path, exc), file=sys.stderr)
        return 2
    symlink = [finding for finding in lpe_sinks.iter_findings(tree, source)
               if finding["rule"] == "symlink-follow"]
    if symlink:
        for finding in symlink:
            print("FAIL: symlink-follow at line %s: %s"
                  % (finding["line"], finding["tainted_operand"]))
        print("")
        print("%d fail" % len(symlink))
        return 1
    print("PASS: strings.bsh carries no symlink-follow sink")
    print("")
    print("1 pass, 0 fail")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
