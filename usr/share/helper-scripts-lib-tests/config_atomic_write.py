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
  - append_shared creates its temp file in the TARGET's directory, so os.replace
    is an atomic same-filesystem rename (pre-fix used a default-TMPDIR temp +
    shutil.move, a non-atomic cross-filesystem copy).
Exit 0 = all pass, 1 = a failure.
"""

import os
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

## Follow an output symlink (update the target in place) rather than replacing
## the link with a regular file.
link_dir = Path(tempfile.mkdtemp())
real = link_dir / "real.conf"
real.write_text("old\n")
link = link_dir / "out.conf"
link.symlink_to(real)
cb.write_config_file({"": {"k": "v"}}, link)
check(
    link.is_symlink() and real.read_text() == "k=v\n\n",
    "config_builder follows an output symlink (updates the target, keeps the link)",
)

## Degrade to an in-place write when the target directory is not writable (an
## atomic replace is impossible there) instead of raising PermissionError.
ro_dir = Path(tempfile.mkdtemp())
ro_target = ro_dir / "c.conf"
ro_target.write_text("orig\n")
os.chmod(ro_dir, 0o555)
try:
    cb.write_config_file({"": {"k2": "v2"}}, ro_target)
    check(
        ro_target.read_text() == "k2=v2\n\n",
        "config_builder writes in place when the target dir is read-only",
    )
finally:
    os.chmod(ro_dir, 0o755)


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
    "append_shared creates its temp in the TARGET dir (atomic same-fs replace), not TMPDIR",
)

print("")
print(f"config_atomic_write: {'0 fail' if fails == 0 else str(fails) + ' fail'}")
sys.exit(1 if fails else 0)
