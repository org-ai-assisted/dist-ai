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
- Why it did not run: the timeout was glm-review sending the payload with
  GLM-4.7's default reasoning on -- fixed in dist-ai-config a10f7b7, which
  cut a request from 7m16s to ~5s. It now fails fast on
  `HTTP 429 -- Rate limit reached for requests` instead; free-tier request
  limit, window outlasts several minutes.
- Covered meanwhile by codex, coderabbit, agy and static; codex's two
  false-positive findings were fixed in b7d3d48.
- Re-run: `ai-review --only glm b7d3d48~1`
