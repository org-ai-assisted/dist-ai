# GitHub Actions security - required patterns

Reusable, cross-repo GitHub Actions security guidance, maintained here in
`dist-ai` and referenced by consumer repos.

For org-wide conventions (reusable workflows, the `github.*` constraint in
`jobs.<id>.uses:`, `schedule:`-must-be-at-caller, cross-repo `uses:` pinning),
see
[`developer-meta-files:agents/github-actions.md`](https://github.com/Kicksecure/developer-meta-files/blob/master/agents/github-actions.md).

A consumer repo's own `agents/github-actions-security.md` holds only that
repo's live pin state (the SHAs and digests its workflows currently use),
because a pin must be bumped in the same commit as the workflow line it
documents.

When editing `.github/workflows/*.yml`, every workflow MUST:

1. **`permissions: contents: read` at the workflow top level.**
   Override per-job (e.g. `security-events: write` for codeql) only when
   strictly needed.

2. **`persist-credentials: false` on every `actions/checkout`.**
   The default leaves `GITHUB_TOKEN` in `.git/config` for any
   subsequent step to harvest. None of our workflows push, so always
   drop credentials post-checkout.

3. **Fork-PR guard on jobs that touch secrets or trigger builds:**
   ```
   if: github.event.pull_request.head.repo.full_name == github.repository
       || github.event_name != 'pull_request'
   ```

4. **Never interpolate `${{ github.event.* }}` (or `${{ inputs.* }}`,
   `${{ github.head_ref }}`, etc.) directly into `run:` shell.**
   Route through `env:` instead:
   ```
   env:
     TITLE: ${{ github.event.issue.title }}
   run: |
     echo "$TITLE"   # safe; not subject to expression-engine substitution
   ```
   Direct interpolation into `run:` is the cycode/Trojan-Source script-
   injection attack class.

5. **Pin `uses:` actions and Docker `image:` to commit SHA / digest.**
   Tags are mutable. Dependabot (`.github/dependabot.yml`) will bump SHAs
   automatically; do not change tags by hand to "latest" / "v6".

6. **Hard timeout on every job** (`timeout-minutes:`).

7. **Inline shell only for steps that must run before checkout** (e.g.
   `apt-get install git ca-certificates` before `actions/checkout`).
   Everything else should call a script under `ci/*.sh` so the bash
   is shellcheck/`bash -n` covered by the lint workflow and runnable
   locally.

If ANY of the above is missing in a workflow you edited, restore it
before committing.

## Why no actionlint

[`rhysd/actionlint`](https://github.com/rhysd/actionlint) catches
workflow-specific bugs that `python3 -c 'yaml.safe_load(...)'` and
shellcheck (on the file tree) don't see - script injection from
`${{ github.event.* }}` into `run:` blocks, mistyped action refs,
shellcheck-of-embedded-shell. It would be useful in principle.

We don't run it because:

- It is not packaged in Debian (`packages.debian.org` has no
  `actionlint` binary). Pulling it from upstream means trusting a
  single-maintainer GitHub release for a tool that runs in CI - same
  trust footprint as the workflow steps it's auditing.
- It is not a "GitHub-verified" Marketplace action; `actionlint`
  itself is a CLI, and the third-party `rhysd/actionlint-action`
  wrapper has the same single-maintainer concern.
- The script-injection class it would catch is already enforced by
  rule 4 above (`env:`-route every external string), and the
  embedded-shell-shellcheck class is mitigated by rule 7 (inline
  shell only when unavoidable).

If `actionlint` ever ships in Debian, we add it back via apt.

Note: `ai-review` DOES run actionlint (and zizmor) from the sandbox -- the
`static` analyzer set is auto-selected on every run, and both fire whenever the
diff touches a workflow or `action.yml`. The trust footprint is contained there.
The rule above governs what runs inside CI itself.

## Pin provenance format

Every `uses: <action>@<sha>` line MUST cite a verifiable source for the SHA,
recorded in the consumer repo's own pin list:

> **`<action>@<sha>  # v<tag>`**
>
> - Source: `<URL of the GitHub release page>`
> - Verbatim quote from the source: `"<commit hash shown there>"`
> - Verified: `<YYYY-MM-DD>` by `<who/how>`

### Procedure when adding or bumping a pin

1. Open the action's release page on github.com (`/<owner>/<action>/releases/tag/<version>`).
2. Copy the exact SHA shown there (40 hex chars).
3. Replace the `@<sha>  # v<tag>` line in the workflow.
4. Add (or update) the row in that repo's pin list with the same source URL.
5. Commit the workflow change and the pin-list update **in the same commit** so
   review can verify both at once.

Dependabot does NOT auto-bump container digests in workflow `image:` lines, so
those need manual re-pinning when porting to a new Debian release.
