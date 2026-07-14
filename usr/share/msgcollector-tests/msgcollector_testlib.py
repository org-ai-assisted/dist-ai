#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Shared helpers for the msgcollector test suite.

Resolves the msgcollector script under test:
  * MSGCOLLECTOR_REPO=/path/to/msgcollector -> <repo>/usr/libexec/msgcollector/msgcollector
  * unset                                   -> /usr/libexec/msgcollector/msgcollector (installed)

The CLI-rendering logic (cli_links_to_footnotes, the <font>-to-ANSI and
<br>-to-newline conversions) is bash inside that one script; the fuzzers extract
a single function and run it in isolation, exactly like the systemcheck suite.
"""

import os
import re
import sys


def msgcollector_script() -> str:
    """Absolute path of the msgcollector script under test."""
    repo = os.environ.get("MSGCOLLECTOR_REPO", "").strip()
    if repo:
        cand = os.path.join(repo, "usr", "libexec", "msgcollector", "msgcollector")
        if os.path.isfile(cand):
            return cand
        print(f"MSGCOLLECTOR_REPO={repo!r} has no usr/libexec/msgcollector/msgcollector; "
              "skipping.", file=sys.stderr)
        sys.exit(77)
    installed = "/usr/libexec/msgcollector/msgcollector"
    if os.path.isfile(installed):
        return installed
    print("msgcollector not found (set MSGCOLLECTOR_REPO); skipping.", file=sys.stderr)
    sys.exit(77)


def read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


_FUNC_RE_TMPL = r"^%s\(\) \{\n(.*?)^\}"


def extract_bash_function(path: str, name: str) -> str:
    """Return the full definition of a top-level bash function `name` from
    `path`. Assumes the closing brace is at column 0. Raises LookupError if not
    found (which the fuzzer turns into SKIP -- an older msgcollector may predate
    the function)."""
    match = re.search(_FUNC_RE_TMPL % re.escape(name), read(path),
                      re.DOTALL | re.MULTILINE)
    if not match:
        raise LookupError(f"function {name!r} not found in {path}")
    return f"{name}() {{\n{match.group(1)}}}\n"
