# Pending AI reviews

Entries here are reviews that could not run. Delete an entry once its
findings are folded in.

## glm on b7d3d48 (R-170 rule + this repo's /tmp cleanup)

- Scope: `ai-review HEAD~1` at 367fc74, and the follow-up b7d3d48.
- Files: `usr/bin/pre-push-static`,
  `usr/share/developer-meta-files-tests/test_pre_push_static_style_rules.sh`,
  plus the `${TMP}` conversions across `usr/bin/dist-ai-tests-all`,
  `usr/share/github-org-tools-tests/`, `usr/share/tb-updater-tests/`.
- Why it matters: R-170 is a single grep enforced repo-wide over WHOLE changed
  files, so a regex false positive blocks unrelated pushes.
- Why it did not run: two causes. The 600s zero-byte timeouts were GLM-4.7's
  default reasoning pass eating the response budget (fixed in dist-ai-config
  a10f7b7 -- 4x faster, more findings). What remains is throughput: even with
  thinking disabled, glm-4.7-flash does not finish THIS diff inside
  ai-review's 480s ceiling. The smaller dist-ai-config scope completes in 10.5s.
- Covered meanwhile by codex, coderabbit, agy and static; codex's two
  false-positive findings were fixed in b7d3d48.
- Re-run: `ai-review --only glm --timeout 900 b7d3d48~1` (auto-detaches;
  the default ceiling is too short for this diff), or scope it tighter.

## dist-ai 145eee3~1..HEAD -- BLOCKED by a dirty tree

- Scope: the R-190 inline-interpreter gate rule and its four tests
  (`usr/bin/pre-push-static`,
  `usr/share/developer-meta-files-tests/test_pre_push_static_style_rules.sh`),
  the dist-ai-config-tests lane registration, and the unregistered-test guard
  (`usr/share/dist-ai-config-tests/run-tests.sh`).
- Why it matters: R-190 fails pushes across every repo using the gate, and the
  guard changes what a green lane means. Both are enforcement code, where a
  false positive blocks unrelated work.
- Why it did not run: `ai-review` reviews COMMITTED work only and refuses a
  dirty tree. A parallel session has uncommitted work here (seen
  `ci/dist-ai-tests-ci-config.sh`, then `usr/bin/dist-ai-tests-all`), which is
  not mine to commit.
- Re-run once `git status --porcelain` is empty:
  `ai-review --timeout 900 145eee3~1`
