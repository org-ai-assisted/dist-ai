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
