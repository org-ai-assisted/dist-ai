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

import os

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
    config rules self-select by path; text rules run when INCLUDE_TEXT. The shell
    and config rules need decoded source, so they are skipped for an undecodable
    file -- but the text rules run on the RAW bytes, so R-001 still catches a
    stray non-ASCII byte in a file that is not valid UTF-8 (the bash grep did).
    Raises bash_ast.ShfmtMissing if shfmt is absent."""
    findings = []
    if ctx.source is not None:
        if ctx.is_shell and ctx.tree is not None:
            findings.extend(_run_rules(ctx, ruleset.SHELL_RULES))
        findings.extend(_run_rules(ctx, ruleset.CONFIG_RULES))
    if include_text:
        findings.extend(_run_rules(ctx, ruleset.TEXT_RULES))
    return findings


def detect_message(raw, path="(commit message)"):
    """R-001 (non-ASCII) findings for a commit MESSAGE blob (raw bytes) -- not a
    tree file, so it has no path/extension and only the content-keyed rules
    apply. Line numbers are within the message. The same Confusables rule the
    files use, over the RAW bytes, so a non-ASCII byte is caught whether or not
    the message decodes as UTF-8 (the bash grep worked on bytes)."""
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError:
        source = None
    ctx = ctxmod.FileContext(path, source, raw=raw)
    ctx._binary = False  ## a message is never a .gitattributes-binary blob
    findings = []
    for rule in ruleset.MESSAGE_RULES:
        if rule.applies(ctx):
            findings.extend(rule.detect(ctx))
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
    ## A .gitattributes-binary file is EXEMPT from fixing, exactly as the former
    ## fixer's is_data_file skip -- even valid UTF-8 must be left byte-identical
    ## (the text rules already honor this via applies(); the AST rewriters did
    ## not, so a binary-attributed shell file was being rewritten).
    if ctx.is_binary:
        return ctx.source, {}
    counts = {}
    source = ctx.source

    ## Pass 1: AST rewriters (need a parse). Their edits target disjoint
    ## commands, so one apply_edits over the ORIGINAL tree is correct. A
    ## non-shell or unparsable file skips them; the text pass still runs.
    if ctx.is_shell and ctx.tree is not None:
        ast_edits = _collect_edits(ctx, _fixable(ruleset.SHELL_RULES))
        if ast_edits:
            source = bash_ast.apply_edits(source, _spans(ast_edits))
            counts.update(_count(ast_edits))

    ## Pass 2: text rules, applied ONE AT A TIME in registry order, each on the
    ## previous rule's output. They interact -- substituting a trailing no-break
    ## space to an ASCII space CREATES trailing whitespace the strip rule must
    ## then see -- so a single merged apply_edits (all computed from one
    ## snapshot) left that residue and the fix-then-check reported it.
    for rule in _fixable(ruleset.TEXT_RULES):
        tctx = ctxmod.FileContext(ctx.path, source, abspath=ctx.abspath)
        tctx._binary = ctx._binary  ## reuse the git query result
        if not rule.applies(tctx):
            continue
        edits = list(rule.fix(tctx))
        if edits:
            source = bash_ast.apply_edits(source, _spans(edits))
            counts.update(_count(edits))

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
            ## O_NOFOLLOW: from_disk refuses a symlink when the context is BUILT,
            ## but a tree scan writes each file later -- if the path is swapped
            ## for a symlink in between, a plain open() would follow it and
            ## clobber the target. Refuse at write time too (ELOOP -> OSError ->
            ## skip), so the fixer only ever writes the regular file it scanned.
            def _nofollow(path, flags):
                return os.open(path, flags | os.O_NOFOLLOW)
            with open(ctx.abspath, "wb", opener=_nofollow) as handle:
                handle.write(new_source.encode("utf-8"))
        except OSError:
            ## Not writable, or the path is now a symlink / gone: leave it for the
            ## gate to report rather than crash the whole fix pass on one file.
            return {}
    return counts
