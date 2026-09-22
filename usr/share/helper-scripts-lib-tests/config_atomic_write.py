#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atomic-write assertions for helper-scripts config_builder + append_shared.

Imports the REAL modules off the checkout (PYTHONPATH is set by the .sh wrapper to
<repo>/usr/lib/python3/dist-packages) and asserts:
  - config_builder.write_config_file leaves the ORIGINAL file intact when
    serialization fails part-way (pre-fix open("w") truncated it in place);
  - write_config_file delegates to append_shared "overwrite": a symlinked output
    path is replaced (not followed), and an unwritable target dir raises;
  - append_shared writes its temp file in the TARGET's own directory, so the
    shutil.move into place is a same-filesystem rename (pre-fix used a default-TMPDIR
    temp, a non-atomic cross-filesystem move when TMPDIR is on another fs).
Exit 0 = all pass, 1 = a failure.
"""

import sys
import tempfile
from pathlib import Path
from unittest import mock

from config_builder import config_builder as cb
from append_shared import append_shared as ap

fails = 0


def check(cond: bool, msg: str) -> None:
    global fails
    print(("PASS: " if cond else "FAIL: ") + msg)
    if not cond:
        fails += 1


## --- config_builder.write_config_file ---------------------------------------
config_dir = Path(tempfile.mkdtemp())
out = config_dir / "c.conf"

cb.write_config_file({"": {"a": "1"}, "sec": {"b": "2"}}, out)
check(
    out.read_text() == "a=1\n\n[sec]\nb=2\n\n",
    "config_builder writes the expected content",
)


class Boom:
    """A value whose serialization fails, to interrupt the write part-way."""

    def __str__(self) -> str:
        raise RuntimeError("boom")


out.write_text("ORIGINAL=keepme\n")
raised = False
try:
    cb.write_config_file({"": {"k": Boom()}}, out)
except RuntimeError:
    raised = True
check(raised, "config_builder propagates a mid-serialization error")
check(
    out.read_text() == "ORIGINAL=keepme\n",
    "config_builder leaves the original intact on failure (atomic; pre-fix truncated it)",
)
check(
    sorted(p.name for p in config_dir.iterdir()) == ["c.conf"],
    "config_builder leaves no temp file behind on failure",
)

## config_builder.write_config_file delegates the write to append_shared
## "overwrite". Assert the two security-relevant properties of that path directly.

## A symlinked output path is REPLACED with a regular file, NOT followed: overwrite
## does not resolve the target, so shutil.move replaces the link rather than writing
## through it to the link's target. A follow-the-symlink regression would instead
## rewrite the decoy and leave 'out.conf' a symlink.
link_dir = Path(tempfile.mkdtemp())
decoy = link_dir / "decoy.conf"
decoy.write_text("DECOY=untouched\n")
link = link_dir / "out.conf"
link.symlink_to(decoy)
cb.write_config_file({"": {"x": "9"}}, link)
check(
    not link.is_symlink() and link.read_text() == "x=9\n\n",
    "config_builder replaces a symlinked output path with a regular file (no follow)",
)
check(
    decoy.read_text() == "DECOY=untouched\n",
    "config_builder does not write through the symlink to its target",
)

## An unwritable target directory is REFUSED (append_shared checks os.access W_OK)
## and surfaced as OSError, with nothing written -- not a silent in-place degrade.
## Force the refusal deterministically (os.access mocked) so the assertion holds
## under root too, where a real chmod 0o500 is a no-op.
ro_target = Path(tempfile.mkdtemp()) / "ro.conf"
raised_ro = False
with mock.patch.object(ap.os, "access", return_value=False):
    try:
        cb.write_config_file({"": {"y": "1"}}, ro_target)
    except OSError:
        raised_ro = True
check(raised_ro, "config_builder raises when the target dir is unwritable (no silent fallback)")
check(
    not ro_target.exists(),
    "config_builder writes nothing when the target dir is unwritable",
)

## --- append_shared: temp created in the TARGET directory ---------------------
append_dir = Path(tempfile.mkdtemp())
target = append_dir / "a.conf"
target.write_text("first\n")

real_ntf = tempfile.NamedTemporaryFile
seen_dirs = []


def spy(*args, **kwargs):
    seen_dirs.append(kwargs.get("dir"))
    return real_ntf(*args, **kwargs)


with mock.patch.object(ap, "NamedTemporaryFile", spy):
    rc = ap.append_shared("append", [str(target), "second"])

check(rc == 0, "append_shared append returns 0")
contents = target.read_text()
check("first" in contents and "second" in contents, "append_shared appended the line")
resolved_parent = str(Path(target).resolve().parent)
check(
    bool(seen_dirs) and str(seen_dirs[-1]) == resolved_parent,
    "append_shared creates its temp in the TARGET dir (same-fs move, atomic rename), not TMPDIR",
)

print("")
print(f"config_atomic_write: {'0 fail' if fails == 0 else str(fails) + ' fail'}")
sys.exit(1 if fails else 0)
