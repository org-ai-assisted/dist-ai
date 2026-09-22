#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Parser assertions for helper-scripts config_builder.config_file_to_config_state
(issue #85):
  - whitespace around '=' is stripped, so 'key = value' and 'key=value' are the
    same key (pre-fix they were distinct: a later override silently failed and
    BOTH keys were emitted);
  - a header line may carry an optional trailing '#' comment ('[section] # c')
    without a crash (pre-fix the anchored regex missed it, the line had no '=',
    and it raised ValueError);
  - only a comment may follow the ']': any other trailing content is rejected
    (the anchor is kept, NOT simply dropped).
Imports the REAL module off the checkout (PYTHONPATH set by the .sh wrapper to
<repo>/usr/lib/python3/dist-packages). Exit 0 = all pass, 1 = a failure.
"""

import sys
import tempfile
from pathlib import Path

from config_builder import config_builder as cb

fails = 0


def check(cond: bool, msg: str) -> None:
    global fails
    print(("PASS: " if cond else "FAIL: ") + msg)
    if not cond:
        fails += 1


def write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


## --- (a) whitespace around '=' + cross-file override -------------------------
merge_dir = Path(tempfile.mkdtemp())
write(merge_dir / "10-base.conf", "[main]\nkey=original\n")
write(merge_dir / "20-override.conf", "[main]\nkey = override\n")
merged_out = merge_dir / "merged.conf"
cb.build_config_file(merge_dir, merged_out)
merged = cb.config_file_to_config_state(merged_out)
check(
    merged.get("main") == {"key": "override"},
    "'key = override' overrides 'key=original' (whitespace around '=' stripped)",
)

## single file: stripping applies to both key and value
single_file = Path(tempfile.mkdtemp()) / "s.conf"
write(single_file, "[main]\n  spaced  =   val  \n")
check(
    cb.config_file_to_config_state(single_file).get("main") == {"spaced": "val"},
    "whitespace around both key and value is stripped",
)

## --- (b) header with an optional trailing comment ---------------------------
comment_file = Path(tempfile.mkdtemp()) / "h.conf"
write(comment_file, "[section] # a comment\nx=1\n")
comment_state: dict = {}
raised = False
try:
    comment_state = cb.config_file_to_config_state(comment_file)
except ValueError:
    raised = True
check(not raised, "'[section] # comment' does not raise")
check(
    (not raised) and comment_state.get("section") == {"x": "1"},
    "'[section] # comment' parses to header 'section'",
)

## no-space form '[sec]#c' too
nospace_file = Path(tempfile.mkdtemp()) / "h2.conf"
write(nospace_file, "[sec]#c\ny=2\n")
check(
    cb.config_file_to_config_state(nospace_file).get("sec") == {"y": "2"},
    "'[sec]#c' parses to header 'sec'",
)

## --- (c) non-comment trailing content after ']' is rejected -----------------
junk_file = Path(tempfile.mkdtemp()) / "j.conf"
write(junk_file, "[section] junk\n")
raised = False
try:
    cb.config_file_to_config_state(junk_file)
except ValueError:
    raised = True
check(raised, "'[section] junk' is rejected (anchor kept, not treated as header)")

## --- empty header still rejected (with or without a trailing comment) -------
for label, body in (("[]", "[]\n"), ("[] # c", "[] # c\n")):
    empty_file = Path(tempfile.mkdtemp()) / "e.conf"
    write(empty_file, body)
    raised = False
    try:
        cb.config_file_to_config_state(empty_file)
    except ValueError:
        raised = True
    check(raised, f"empty header '{label}' raises")

print("")
print(f"config_builder_parser: {'0 fail' if fails == 0 else str(fails) + ' fail'}")
sys.exit(1 if fails else 0)
