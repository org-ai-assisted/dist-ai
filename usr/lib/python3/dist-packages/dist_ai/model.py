## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""The rule contract for the unified style engine.

ONE rule = ONE object that knows how to DETECT its violation and, where the fix
is mechanical and structure-preserving, how to FIX it. Detection and fixing are
two methods on the same object, so a rule's constants, its waiver tag, and the
boundary of what it can safely rewrite are defined ONCE -- retiring the
detect/fix "lockstep" that a parity test used to police.

The engine (engine.py) enforces the one invariant this split must preserve: a
rule's fixable node set is a SUBSET of its detectable set. It never trusts fix()
to be exhaustive -- it applies the edits, re-reads the source, and re-runs
detect(), so whatever detect() still reports IS the residual. A rule therefore
cannot make a file pass by fixing less than it detects.

Return types are deliberately different:
  * detect(ctx) -> Iterable[Finding]  -- severity/message/line, for a human
  * fix(ctx)    -> Iterable[Edit]     -- byte-span replacements, for apply_edits
"""

import collections
from typing import Iterator

FAIL = "FAIL"
NOTE = "NOTE"

## severity: FAIL (fails the gate) or NOTE (advisory, never fails).
## rule: the R-xxx id. message/path for the human; line is 1-based or None.
Finding = collections.namedtuple(
    "Finding", ["severity", "rule", "message", "path", "line"])

## A byte-span replacement in the ORIGINAL source (offsets index UTF-8 bytes, the
## same convention bash_ast nodes carry). start/end are absolute; replacement is
## the new text for [start, end). rule is the R-xxx id that produced it, for the
## "what changed" summary. Non-overlapping edits are applied right-to-left by
## bash_ast.apply_edits.
Edit = collections.namedtuple("Edit", ["start", "end", "replacement", "rule"])


def _line_number(line):
    """Normalize a line argument to an int (or None). Accepts an int, a bash_ast
    NODE (line at node['Pos']['Line']), or a bare Pos dict (line at ['Line'])."""
    if isinstance(line, dict):
        if "Pos" in line:
            return (line.get("Pos") or {}).get("Line")
        return line.get("Line")
    return line


def fail(rule, message, path, line=None):
    """Build a FAIL finding. line may be a bash_ast node, its Pos, an int, or
    None when the location is the file itself."""
    return Finding(FAIL, rule, message, path, _line_number(line))


def note(rule, message, path=None, line=None):
    """Build a NOTE (advisory) finding."""
    return Finding(NOTE, rule, message, path, _line_number(line))


class Rule:
    """Base class for a style rule.

    Subclasses set the class attributes and override detect() (always) and fix()
    (only when the fix is mechanical and provably structure-preserving). A rule
    with no fix() blocks for a human to correct by hand.

      id         -- the R-xxx identifier, e.g. "R-172".
      waiver_tag -- the single '## style-ok: <tag>' token that suppresses this
                    rule for a file, or None if the rule has no per-file waiver
                    (or the rule emits its own skip-NOTE from detect()).
                    ctx.has_waiver(tag) is the ONE reader of the waiver grammar.
      advisory   -- True for a NOTE-only rule (informational, never fails).

    The engine decides which files a rule sees by its COLLECTION (shell / config
    / text in the registry), so applies() only owns per-rule suppression: the
    file-wide waiver and any path-keyed self-exemption a subclass adds.
    """

    id = None
    waiver_tag = None
    advisory = False

    def applies(self, ctx):
        """Run this rule on ctx? Default: suppressed only by an active file-wide
        waiver. A rule with a path self-exemption or a config-file predicate
        overrides this and calls super().applies() first."""
        if self.waiver_tag is not None and ctx.has_waiver(self.waiver_tag):
            return False
        return True

    def detect(self, ctx) -> Iterator[Finding]:
        """Yield Finding for each violation in ctx. Override in every rule."""
        raise NotImplementedError

    def fix(self, ctx) -> Iterator["Edit"]:
        """Yield Edit for each MECHANICALLY fixable violation in ctx. Default:
        nothing is auto-fixable. The returned edits must not overlap and must
        target only spans this rule is certain about (a fixable subset of what
        detect() reports); the engine re-detects to surface the rest.

        An empty GENERATOR (not a bare return), so its type matches the
        generator subclasses override it with -- a plain 'return ()' made the
        base yield a tuple and every fix() override a signature mismatch."""
        return
        yield  # pragma: no cover -- unreachable; marks this an empty generator


class ExternalRule(Rule):
    """A rule backed by an external checker (bash -n, shellcheck,
    pre-commit-hooks binaries, image-optimize) rather than our own AST logic.
    Always check-only: an external tool reports, it does not get a fix()."""

    def fix(self, ctx) -> Iterator["Edit"]:
        return
        yield  # pragma: no cover -- unreachable; empty generator
