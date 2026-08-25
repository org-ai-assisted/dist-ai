## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""The style engine: classify each file once, run the applicable rules.

  detect(ctx)      -- run the detect rules, return Findings.
  apply_fixes(ctx) -- run the fixable rules, write the result, return the change
                      counts. Two passes in the proven order: the AST rewriters
                      (R-161/172/200) splice byte spans on the parsed source
                      FIRST, then the text rules (R-001, trailing) run on the
                      result. Both express edits as byte-span Edits, so one
                      apply_edits per pass.

The fixable-subset-of-detectable invariant is not trusted to fix(): apply_fixes
mutates the file, and the gate's detect pass then re-reads it, so any violation a
fix did not (or could not) remove is reported as the residual. There is nothing
to keep in lockstep."""

from dist_ai import bash_ast
from dist_ai import context as ctxmod
from dist_ai import model
from dist_ai import rules as ruleset


def _run_rules(ctx, rules):
    for rule in rules:
        if not rule.applies(ctx):
            continue
        yield from rule.detect(ctx)


def detect(ctx, include_text=False):
    """Findings for one FileContext. Shell rules run only on a parsed shell file;
    config rules self-select by path; text rules run when INCLUDE_TEXT (the gate
    still owns their detection during migration, so the detect front leaves them
    off by default). Raises bash_ast.ShfmtMissing if shfmt is absent."""
    if ctx.source is None:
        return []
    findings = []
    if ctx.is_shell and ctx.tree is not None:
        findings.extend(_run_rules(ctx, ruleset.SHELL_RULES))
    findings.extend(_run_rules(ctx, ruleset.CONFIG_RULES))
    if include_text:
        findings.extend(_run_rules(ctx, ruleset.TEXT_RULES))
    return findings


def _fixable(rules):
    return [r for r in rules if type(r).fix is not model.Rule.fix]


def _collect_edits(ctx, rules):
    edits = []
    for rule in rules:
        if rule.applies(ctx):
            edits.extend(rule.fix(ctx))
    return edits


def _count(edits):
    counts = {}
    for edit in edits:
        counts[edit.rule] = counts.get(edit.rule, 0) + 1
    return counts


def _spans(edits):
    """The (start, end, replacement) triples apply_edits consumes -- the Edit's
    rule tag is for the change summary, not the splice."""
    return [(edit.start, edit.end, edit.replacement) for edit in edits]


def fix_source(ctx):
    """Compute the fixed source for CTX without writing. Returns (new_source,
    {rule_id: count}). Two passes: AST rewriters on the parsed shell source, then
    text rules on the result. Raises bash_ast.ShfmtMissing if a shell file must
    be parsed but shfmt is absent."""
    if ctx.source is None:
        return None, {}
    counts = {}
    source = ctx.source

    ## Pass 1: AST rewriters (need a parse). A non-shell or unparsable file skips
    ## them; the text pass still runs.
    if ctx.is_shell and ctx.tree is not None:
        ast_edits = _collect_edits(ctx, _fixable(ruleset.SHELL_RULES))
        if ast_edits:
            source = bash_ast.apply_edits(source, _spans(ast_edits))
            counts.update(_count(ast_edits))

    ## Pass 2: text rules, on the (possibly) rewritten source. A fresh context so
    ## the text rules' byte offsets index the post-pass-1 bytes.
    text_ctx = ctxmod.FileContext(ctx.path, source, abspath=ctx.abspath)
    text_ctx._binary = ctx._binary  ## reuse the git query result
    text_edits = _collect_edits(text_ctx, _fixable(ruleset.TEXT_RULES))
    if text_edits:
        source = bash_ast.apply_edits(source, _spans(text_edits))
        counts.update(_count(text_edits))

    return source, counts


def apply_fixes(ctx, check=False):
    """Fix CTX in place (unless CHECK). Returns {rule_id: count} of changes, or {}
    if already clean / nothing fixable. Writes only when the content actually
    changed. Raises bash_ast.ShfmtMissing when shfmt is required but absent."""
    new_source, counts = fix_source(ctx)
    if new_source is None or new_source == ctx.source:
        return {}
    if not check:
        try:
            with open(ctx.abspath, "wb") as handle:
                handle.write(new_source.encode("utf-8"))
        except OSError:
            ## Readable but not writable: leave it for the gate to report rather
            ## than crash the whole fix pass on one file.
            return {}
    return counts
