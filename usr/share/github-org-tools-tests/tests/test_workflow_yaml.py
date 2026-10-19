#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Project-specific GitHub workflow YAML validator.

Walks .github/workflows/*.yml under the given repo root and applies
these rules:

  W-001 TIMEOUT              Every job that runs work has
                             timeout-minutes set.
  W-002 CONCURRENCY          Every non-reusable workflow has a
                             top-level concurrency: block.
  W-003 SECRETS-INHERIT      'secrets: inherit' only in the
                             documented allowlist.
  W-004 SHA-PIN              Third-party 'uses: <owner>/<repo>@
                             <ref>' must pin to a 40-char SHA AND
                             carry a '# v<tag>' provenance comment.
                             First-party orgs (org-ai-assisted,
                             Kicksecure, Whonix) and local refs are
                             exempt. Note: 'actions/*' (GitHub-
                             owned) is NOT first-party; supply-chain
                             hygiene applies to GitHub's marketplace
                             actions too.
  W-005 PERMISSIONS-CHECKOUT If a job has a non-empty permissions
                             block AND uses actions/checkout on the
                             current repo, that block must include
                             'contents: read'. Job-level permissions
                             REPLACE top-level (GitHub does not
                             merge).
  W-006 DEPRECATED           ::set-output, ::save-state, node12,
                             node16, actions/upload-artifact@v3,
                             etc.
  W-007 DEPENDABOT-MISSING   Repo has direct third-party action SHA
                             pins in its workflows but no
                             .github/dependabot.yml to track bumps.
                             Repos with zero direct refs (pure
                             '@master'-to-dmf-reusable wrappers) are
                             exempt - dmf's single Dependabot config
                             propagates SHA bumps to them.

  W-008 OWNER-GATE           Every job that runs steps carries
                             the CI-enabled gate, so a workflow of
                             ours cannot run in an org that never
                             opted in. Wrapper jobs, 'if: false'
                             kill-switches and consumer-*.yml are
                             exempt; per-repo carve-outs live in
                             .github/owner-gate-exempt.yml and must
                             state a reason.

  W-009 FORK-PR-GUARD        In a reusable (workflow_call) workflow,
                             any job that checks out a PR-controllable
                             ref -- an actions/checkout whose 'ref:' is
                             a '${{ ... }}' expression -- must carry the
                             fork-PR guard in its 'if:'. A reusable
                             cannot see its caller's trigger, so CodeQL
                             (actions/untrusted-checkout) and we assume
                             the caller MAY route pull_request_target.
                             Sanctioned forms: the guard literal
                             'head.repo.full_name == github.repository',
                             or a restriction to non-pull_request events
                             (github.event_name named, pull_request
                             absent). Anything else is flagged -- a new
                             reusable must not silently omit the guard,
                             the way reusable-coverity.yml once did.

Usage: python3 test_workflow_yaml.py <repo_root>

Exit codes:
  0  no findings
  1  one or more findings reported
  2  internal error (bad invocation, missing dep)
"""

import os
import re
import sys

try:
    import yaml  # type: ignore[import-untyped]
except ImportError:
    print('error: PyYAML not installed (apt: python3-yaml)', file=sys.stderr)
    sys.exit(2)


## 'secrets: inherit' is permitted only on these specific
## workflows. Path is relative to repo_root.
SECRETS_INHERIT_ALLOWLIST = {
    '.github/workflows/consumer-secrets-audit.yml',
}

## First-party owners are exempt from SHA-pin (G-A-004 in
## agents/github-actions.md: branch-name refs are an accepted
## single-source-of-truth pattern for our own repos). 'actions' and
## 'github' (GitHub-owned) are NOT in this set: even GitHub's own
## marketplace actions must be SHA-pinned per supply-chain hygiene.
FIRST_PARTY_OWNERS = {
    'org-ai-assisted',
    'Kicksecure',
    'Whonix',
}

## Deprecated action refs and syntax. Map of substring -> reason.
DEPRECATED_MARKERS = {
    '::set-output': 'use $GITHUB_OUTPUT instead (set-output deprecated 2022)',
    '::save-state': 'use $GITHUB_STATE instead (save-state deprecated 2022)',
    '::set-env': 'banned for security reasons (CVE-2020-15228)',
    'actions/upload-artifact@v3': 'v3 deprecated 2024; use @v4 or @v7 SHA-pinned',
    'actions/download-artifact@v3': 'v3 deprecated 2024; use @v4 SHA-pinned',
    'actions/cache@v2': 'v2 EOL; use @v4 SHA-pinned',
    'actions/cache@v3': 'v3 deprecated; use @v4 SHA-pinned',
}

## W-008: the org-wide CI switch. One organization variable on
## org-ai-assisted gates every workflow we own; unset (upstream, a
## contributor fork) means the job skips with no runner allocated and the
## run still reports green.
OWNER_GATE_LITERAL = "vars.CI_ENABLED_ORG_AI_ASSISTED == 'true'"

## W-009: the fork-PR guard. Distinctive substring of
## 'github.event.pull_request.head.repo.full_name == github.repository'
## -- the condition that makes a reusable safe to check out a
## PR-controllable ref even if a caller routes pull_request_target.
FORK_PR_GUARD_LITERAL = 'head.repo.full_name == github.repository'


def effective_condition(cond):
    """The if-expression with a single surrounding '${{ ... }}' stripped (an
    'if:' may be written with or without it)."""
    text = str(cond).strip()
    match = re.match(r'\A\$\{\{\s*(.*?)\s*\}\}\Z', text, re.DOTALL)
    return match.group(1).strip() if match else text


def strip_wrapping_parens(expr):
    """EXPR with one or more pairs of parens that enclose the WHOLE expression
    peeled off: '(a || b)' -> 'a || b', '((a))' -> 'a'. A group that only starts
    at index 0 without spanning to the end ('(a) || b') is left intact -- its
    first ')' returns the depth to 0 before the last char."""
    text = expr.strip()
    while len(text) >= 2 and text[0] == '(' and text[-1] == ')':
        depth = 0
        in_str = False
        wraps = True
        for index, char in enumerate(text):
            if in_str:
                if char == "'":
                    in_str = False
                continue
            if char == "'":
                in_str = True
            elif char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth == 0 and index != len(text) - 1:
                    wraps = False
                    break
        if not wraps:
            break
        text = text[1:-1].strip()
    return text


def top_level_or_parts(expr):
    """EXPR split on '||' at paren depth 0, outside single-quoted string
    literals. Used to require the CI-gate literal in EVERY top-level disjunct:
    'literal || true' has a disjunct ('true') that runs the job regardless of the
    gate, which a bare substring test misses. A disjunct that is itself a fully
    parenthesized group is expanded, so '(literal || true)' does not hide its
    always-true arm behind redundant parens (a W-008 gate bypass). A group that
    is only PART of a disjunct ('(literal || true) && foo') is not decomposed --
    resolving that needs a full boolean parser, out of scope here."""
    expr = strip_wrapping_parens(expr)
    parts = []
    depth = 0
    in_str = False
    start = 0
    index = 0
    while index < len(expr):
        char = expr[index]
        if in_str:
            if char == "'":
                in_str = False
        elif char == "'":
            in_str = True
        elif char == '(':
            depth += 1
        elif char == ')':
            depth = max(0, depth - 1)
        elif char == '|' and depth == 0 \
                and index + 1 < len(expr) and expr[index + 1] == '|':
            parts.append(expr[start:index])
            index += 2
            start = index
            continue
        index += 1
    parts.append(expr[start:])
    result = []
    for part in parts:
        stripped = strip_wrapping_parens(part)
        if stripped != part.strip():
            result.extend(top_level_or_parts(stripped))
        else:
            result.append(stripped)
    return result

SHA40 = re.compile(r'^[0-9a-f]{40}$')

RULE_LEGEND = [
    ('W-001 TIMEOUT',              'job missing timeout-minutes'),
    ('W-002 CONCURRENCY',          'workflow missing top-level concurrency:'),
    ('W-003 SECRETS-INHERIT',      'secrets: inherit outside allowlist'),
    ('W-004 SHA-PIN',              'third-party uses: not pinned to 40-char SHA'),
    ('W-005 PERMISSIONS-CHECKOUT', 'job-level permissions drop contents: read while using actions/checkout'),
    ('W-006 DEPRECATED',           'deprecated GitHub Actions syntax / action version'),
    ('W-007 DEPENDABOT-MISSING',   'direct third-party SHAs but no .github/dependabot.yml'),
    ('W-008 OWNER-GATE',           'job runs steps without the CI-enabled gate'),
    ('W-009 FORK-PR-GUARD',        'reusable job checks out a PR-controllable ref without the fork-PR guard'),
    ('W-YAML',                     'YAML parse error'),
]


def emit(findings, path, repo_root, rule, message):
    rel = os.path.relpath(path, repo_root)
    findings.append(f'{rel}:{rule}:{message}')


def is_workflow_call(parsed):
    on = parsed.get('on')
    if on is None:
        ## 'on' parses as Python True under YAML 1.1.
        on = parsed.get(True)
    if not isinstance(on, dict):
        return False
    return 'workflow_call' in on


def is_composite_action(parsed):
    runs = parsed.get('runs')
    if not isinstance(runs, dict):
        return False
    return runs.get('using') == 'composite'


def find_uses_lines(text):
    """Return [(line_no, uses_value, tag_comment)] for every 'uses:' line.

    tag_comment is the inline comment text after '#' on the same
    line (None if no inline comment present).
    """
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r'^\s*-?\s*uses:\s*([^\s#]+)(\s*#\s*(.+))?', line)
        if m:
            tag = m.group(3).strip() if m.group(3) else None
            out.append((i, m.group(1), tag))
    return out


def check_workflow(path, repo_root, findings):
    with open(path) as f:
        text = f.read()
    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as e:
        emit(findings, path, repo_root, 'W-YAML', f'invalid YAML: {e}')
        return
    if not isinstance(parsed, dict):
        emit(findings, path, repo_root, 'W-YAML', 'top-level is not a mapping')
        return

    ## Composite action files (.github/actions/*/action.yml) only
    ## have W-004 / W-006 applicable - no jobs:, no concurrency:,
    ## no secrets. Skip workflow-only rules for them but still walk
    ## uses: lines below.
    if not is_composite_action(parsed):
        is_reusable = is_workflow_call(parsed)
        jobs = parsed.get('jobs') or {}

        ## W-002 CONCURRENCY (reusables exempt)
        if not is_reusable and 'concurrency' not in parsed:
            emit(findings, path, repo_root, 'W-002', 'missing top-level concurrency: block')

        if isinstance(jobs, dict):
            for job_id, job in jobs.items():
                if not isinstance(job, dict):
                    continue
                check_job(path, repo_root, findings, job_id, job)

    ## W-004 SHA-PIN, W-006 DEPRECATED: walk uses: lines.
    for line_no, uses, tag_comment in find_uses_lines(text):
        for marker, reason in DEPRECATED_MARKERS.items():
            if marker in uses:
                emit(findings, path, repo_root, 'W-006',
                     f"line {line_no}: '{uses}' - {reason}")
                break

        if uses.startswith('./') or uses.startswith('docker://'):
            continue  ## local composite or docker ref
        m = re.match(r'^([^/@]+)/[^@]+@(.+)$', uses)
        if not m:
            continue
        owner = m.group(1)
        ref = m.group(2)
        if owner in FIRST_PARTY_OWNERS:
            continue
        if not SHA40.match(ref):
            emit(findings, path, repo_root, 'W-004',
                 f"line {line_no}: '{uses}' - third-party action must pin to 40-char SHA, not '@{ref}'")
            continue
        ## SHA pinned. Now require a '# v<digit>...' provenance comment.
        if not tag_comment or not re.match(r'^v?\d', tag_comment):
            emit(findings, path, repo_root, 'W-004',
                 f"line {line_no}: '{uses}' - SHA pinned but missing '# v<tag>' provenance comment "
                 f'(found: {tag_comment!r})')


def check_job(path, repo_root, findings, job_id, job):
    ## W-001 TIMEOUT: standalone jobs (with steps) must have
    ## timeout-minutes. Wrapper jobs (only 'uses:') are governed
    ## by the called reusable's timeout.
    if 'steps' in job and 'timeout-minutes' not in job:
        emit(findings, path, repo_root, 'W-001',
             f"job '{job_id}' missing timeout-minutes")

    ## W-003 SECRETS-INHERIT
    if job.get('secrets') == 'inherit':
        rel = os.path.relpath(path, repo_root)
        if rel not in SECRETS_INHERIT_ALLOWLIST:
            emit(findings, path, repo_root, 'W-003',
                 f"job '{job_id}' uses 'secrets: inherit'; replace with explicit map "
                 f'(or add to SECRETS_INHERIT_ALLOWLIST if intentional)')

    ## W-005 PERMISSIONS-CHECKOUT
    perms = job.get('permissions')
    ## Skip if perms is not a non-empty mapping. 'permissions: {}'
    ## (empty) is a deliberate "zero permissions" hardening signal;
    ## strings like 'read-all' / 'write-all' also bypass.
    if not (isinstance(perms, dict) and perms):
        return
    ## Same-repo checkout means: actions/checkout@... with NO
    ## 'with.repository:' override. Cross-repo public-anonymous
    ## clone does not need 'contents:' permission on THIS repo.
    uses_same_repo_checkout = False
    for s in (job.get('steps') or []):
        if not isinstance(s, dict):
            continue
        s_uses = s.get('uses', '')
        if not isinstance(s_uses, str):
            continue
        if not s_uses.startswith('actions/checkout@'):
            continue
        w = s.get('with') or {}
        if not w.get('repository'):
            uses_same_repo_checkout = True
            break
    if uses_same_repo_checkout and 'contents' not in perms:
        emit(findings, path, repo_root, 'W-005',
             f"job '{job_id}' has job-level permissions but no 'contents:' entry "
             f'AND uses actions/checkout on the current repo. Job-level permissions '
             f'REPLACE top-level (not merge), so checkout has no contents access.')


def collect_target_files(repo_root):
    """Workflows + composite-action definitions."""
    targets = []
    workflows_dir = os.path.join(repo_root, '.github', 'workflows')
    if os.path.isdir(workflows_dir):
        for entry in sorted(os.listdir(workflows_dir)):
            if entry.endswith('.yml') or entry.endswith('.yaml'):
                targets.append(os.path.join(workflows_dir, entry))
    actions_dir = os.path.join(repo_root, '.github', 'actions')
    if os.path.isdir(actions_dir):
        for action_name in sorted(os.listdir(actions_dir)):
            for filename in ('action.yml', 'action.yaml'):
                p = os.path.join(actions_dir, action_name, filename)
                if os.path.isfile(p):
                    targets.append(p)
    return targets


def check_dependabot(repo_root, targets, findings):
    """W-007: if the repo has any direct third-party 'uses:' (non-
    first-party, non-local), it must have .github/dependabot.yml.
    Pure '@master'-to-dmf-reusable wrappers (zero direct refs)
    are exempt - dmf's single Dependabot covers them.
    """
    dependabot_path = os.path.join(repo_root, '.github', 'dependabot.yml')
    if os.path.isfile(dependabot_path):
        return
    if os.path.isfile(os.path.join(repo_root, '.github', 'dependabot.yaml')):
        return

    has_direct = False
    for t in targets:
        with open(t) as f:
            for _, uses, _ in find_uses_lines(f.read()):
                if uses.startswith('./') or uses.startswith('docker://'):
                    continue
                m = re.match(r'^([^/@]+)/[^@]+@(.+)$', uses)
                if not m:
                    continue
                if m.group(1) not in FIRST_PARTY_OWNERS:
                    has_direct = True
                    break
        if has_direct:
            break

    if has_direct:
        findings.append(
            f'.github/dependabot.yml:W-007:repo has direct third-party action SHA pins '
            f"but no .github/dependabot.yml; SHA bumps won't be tracked"
        )


def load_owner_gate_exempt(repo_root):
    """Per-repo W-008 carve-outs from .github/owner-gate-exempt.yml.

    Mapping of '<workflow path>:<job id>' -> reason. The reason is
    mandatory: a carve-out nobody had to justify is how a gate quietly
    stops covering things.
    """
    path = os.path.join(repo_root, '.github', 'owner-gate-exempt.yml')
    if not os.path.isfile(path):
        return {}
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError:
        return {}
    if not isinstance(data, dict):
        return {}
    entries = data.get('owner-gate-exempt') or {}
    return entries if isinstance(entries, dict) else {}


def check_owner_gate(repo_root, targets, findings):
    """W-008: every job that runs work must be gated on the CI-enabled
    variable, so a workflow of ours cannot run in an org that never
    opted in (upstream quota, fork noise, our AI reviewers posting into
    someone else's repo).

    The check is on the LITERAL, deliberately. The gate is one string
    repeated across ~50 files; a typo or a renamed variable would
    silently disable it everywhere while every run still reported
    green. Machine-checking the exact string is what makes repeating
    it safe.

    Not flagged:
      * jobs with no 'steps:' -- pure 'uses:' wrappers, governed by the
        reusable they call, which carries its own gate;
      * 'if: false' kill-switches, which allocate no runner either way;
      * consumer-*.yml, propagated byte-identical from
        developer-meta-files and likewise wrapper-only;
      * anything named in .github/owner-gate-exempt.yml WITH a reason.
    """
    exempt = load_owner_gate_exempt(repo_root)

    for path in targets:
        rel = os.path.relpath(path, repo_root)
        if os.path.basename(path).startswith('consumer-'):
            continue
        try:
            with open(path) as f:
                parsed = yaml.safe_load(f)
        except (yaml.YAMLError, OSError):
            continue
        if not isinstance(parsed, dict) or is_composite_action(parsed):
            continue
        jobs = parsed.get('jobs') or {}
        if not isinstance(jobs, dict):
            continue
        for job_id, job in jobs.items():
            if not isinstance(job, dict) or 'steps' not in job:
                continue
            cond = job.get('if')
            ## 'if: false' parses to the boolean, not a string.
            if cond is False:
                continue
            ## The literal must gate EVERY top-level disjunct, not merely appear
            ## somewhere: 'literal || true' contains it but still runs the job
            ## unconditionally.
            if all(OWNER_GATE_LITERAL in part
                   for part in top_level_or_parts(effective_condition(cond))):
                continue
            key = f'{rel}:{job_id}'
            if key in exempt:
                if str(exempt[key]).strip():
                    continue
                findings.append(
                    f'{rel}:W-008:job {job_id!r} is exempt in '
                    f'.github/owner-gate-exempt.yml but gives no reason; '
                    f'state why this job may run outside the allow-list'
                )
                continue
            findings.append(
                f'{rel}:W-008:job {job_id!r} runs steps without the CI-enabled gate; '
                f"add \"if: {OWNER_GATE_LITERAL}\" (AND it in front of any existing "
                f'condition), or add {key!r} to .github/owner-gate-exempt.yml with a reason'
            )


def job_checks_out_expression_ref(job):
    """True if JOB has an actions/checkout step whose 'ref:' is a
    '${{ ... }}' expression -- i.e. a ref that may resolve to
    PR-controlled code (github.sha, an input, an env derived from
    either). A literal 'ref: master' is trusted and does NOT count."""
    steps = job.get('steps')
    if not isinstance(steps, list):
        return False
    for step in steps:
        if not isinstance(step, dict):
            continue
        uses = step.get('uses')
        if not isinstance(uses, str) or not uses.startswith('actions/checkout'):
            continue
        with_block = step.get('with')
        if not isinstance(with_block, dict):
            continue
        ref = with_block.get('ref')
        if isinstance(ref, str) and '${{' in ref:
            return True
    return False


def fork_pr_disjunct_is_safe(part):
    """A single top-level '||' disjunct of an if: that, on its own, keeps a
    fork PR from reaching the checkout. Two sanctioned forms (the ones the org
    reusables actually use):

      * the guard literal 'head.repo.full_name == github.repository', ANDed
        with the rest of the disjunct; or
      * a restriction to non-pull_request events by POSITIVE equality
        ('github.event_name == <non-pr-event>'), never mentioning pull_request
        and never a 'github.event_name !=' negation.

    The positive-equality rule is deliberate: 'github.event_name != 'schedule''
    is true on a pull_request, so a bare event negation does NOT keep fork PRs
    out -- treating it as safe would fail OPEN. A bare
    'github.event_name != 'pull_request'' is likewise NOT accepted: it is true
    on pull_request_target, so it does not defend the pull_request_target path;
    the sanctioned defense is the head-repo guard literal.
    """
    if FORK_PR_GUARD_LITERAL in part:
        return True
    return ('github.event_name ==' in part
            and 'pull_request' not in part
            and 'github.event_name !=' not in part)


def check_fork_pr_guard(repo_root, targets, findings):
    """W-009: a reusable (workflow_call) job that checks out a
    PR-controllable ref must carry the fork-PR guard.

    A reusable runs in the CALLER's context and cannot see whether the
    caller triggers it on pull_request (fork PRs get no secrets) or
    pull_request_target (fork PRs DO). So a reusable that checks out a
    '${{ ... }}' ref must defend itself. The guard must hold on EVERY
    top-level '||' disjunct (same reasoning as W-008): 'guard || true' still
    runs the job unguarded through the always-true arm.

    This is an ACCIDENT-prevention gate -- it stops a new reusable silently
    omitting the guard, the way reusable-coverity.yml did -- NOT an
    adversarial expression analyzer. It checks the sanctioned LITERAL forms
    (see fork_pr_disjunct_is_safe). Deliberately OUT of scope, like the other
    policy guards in this org: a crafted 'guard || true' tautology beyond the
    top-level split, a negated guard, or a condition hand-written to carry the
    literal without gating. Non-reusable workflows are out of scope too (their
    own 'on:' triggers, visible in-file, bound the risk).

    Note (surfaced, not enforced): the org-standard guard
    '(head.repo.full_name == github.repository || github.event_name !=
    'pull_request')' defends pull_request but NOT pull_request_target (there
    github.event_name is 'pull_request_target', so the second arm is true).
    The org reusables are safe anyway because they check out github.sha / a
    fixed ref, not github.event.pull_request.head.sha -- so no fork head is
    fetched. A reusable that DID check out head.sha would need a stricter guard.
    """
    for path in targets:
        try:
            with open(path) as f:
                parsed = yaml.safe_load(f)
        except (yaml.YAMLError, OSError):
            continue
        if not isinstance(parsed, dict) or is_composite_action(parsed):
            continue
        if not is_workflow_call(parsed):
            continue
        jobs = parsed.get('jobs') or {}
        if not isinstance(jobs, dict):
            continue
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            if not job_checks_out_expression_ref(job):
                continue
            cond = effective_condition(job.get('if') or '').strip()
            parts = top_level_or_parts(cond) if cond else []
            if parts and all(fork_pr_disjunct_is_safe(p) for p in parts):
                continue
            emit(findings, path, repo_root, 'W-009 FORK-PR-GUARD',
                 f"job {job_id!r} checks out a PR-controllable ref (actions/checkout "
                 f"with an expression 'ref:') but its 'if:' does not keep fork PRs out on "
                 f"every top-level disjunct: carry the fork-PR guard "
                 f"({FORK_PR_GUARD_LITERAL}) or gate to non-pull_request events by equality")


def main(repo_root):
    targets = collect_target_files(repo_root)
    if not targets:
        print(f'workflow yaml validator: no workflow / composite-action files; nothing to validate')
        return 0

    findings: list[str] = []
    for p in targets:
        check_workflow(p, repo_root, findings)
    check_dependabot(repo_root, targets, findings)
    check_owner_gate(repo_root, targets, findings)
    check_fork_pr_guard(repo_root, targets, findings)
    n_files = len(targets)

    if not findings:
        print(f'workflow yaml validator: 0 findings across {n_files} files')
        return 0

    print(f'workflow yaml validator: {len(findings)} finding(s):')
    print('----')
    for f in findings:
        print(f)
    print('----')
    print('Rules:')
    for rule, desc in RULE_LEGEND:
        print(f'  {rule:<27} {desc}')
    return 1


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('usage: test_workflow_yaml.py <repo_root>', file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
