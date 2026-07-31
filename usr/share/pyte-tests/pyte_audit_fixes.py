#!/usr/bin/python3 -Bsu

"""Which audited pyte defects the tree under test declares it fixes.

The pyte-tests suites run against several different pyte trees -- the
org-ai-assisted/pyte fork, upstream master, a distribution package -- and those
trees do not fix the same set of defects. The tree itself declares what it
fixes, in a manifest shipped at its root (next to the ``pyte`` package). The
expectation is therefore a DECLARATION, never a probe of the observed
behaviour: an expectation derived from what the code does could not disagree
with the code, i.e. could never go red.

Manifest: ``pyte-audit-fixes.txt``, one org-ai-assisted/pyte-audit finding id
per line; ``#`` starts a comment and blank lines are ignored. A tree shipping
no manifest declares nothing, so every audited defect is expected to reproduce
there -- the correct assumption for stock upstream and distribution builds.
"""
from __future__ import annotations

import pathlib
import types

MANIFEST_NAME = 'pyte-audit-fixes.txt'

## Every finding id in org-ai-assisted/pyte-audit. Constrains the manifest so a
## typo surfaces as an error instead of as a silently undeclared fix.
KNOWN_BUG_IDS = frozenset('ABCDEFG')


def parse_manifest(text: str) -> frozenset[str]:
    """Finding ids declared by a manifest's contents."""
    ids = set()
    for line in text.splitlines():
        entry = line.split('#', 1)[0].strip().upper()
        if entry:
            ids.add(entry)
    return frozenset(ids)


def manifest_path(pyte_module: types.ModuleType) -> pathlib.Path:
    """Where the tree providing ``pyte_module`` would ship its manifest."""
    package_dir = pathlib.Path(pyte_module.__file__).resolve().parent
    return package_dir.parent / MANIFEST_NAME


def declared_fixes(pyte_module: types.ModuleType) -> frozenset[str]:
    """Finding ids the imported pyte tree declares it fixes."""
    try:
        text = manifest_path(pyte_module).read_text(encoding='utf-8')
    except OSError:
        return frozenset()
    return parse_manifest(text)
