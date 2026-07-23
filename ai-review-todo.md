# Pending AI reviews

## dm-image-boot-tests suite move (commit 2a7dd43)
- Scope: `ai-review HEAD~1` timed out (481s ceiling, both codex + coderabbit
  killed with zero output) -- the large verbatim moved files (dm-qemu ~37KB +
  arch wrappers) bloat/stall the reviewers. NO-RESULT, not a clean pass.
- Genuinely new logic to review: `usr/bin/dm-image-boot-tests` (the runner) and
  the `dist-ai-tests-all` registration (integration_suites / suite_component /
  wire). The bundled dm-qemu/dm-image-test are byte-identical relocations.
- Already validated: shellcheck clean; SKIP-77 on no-image; correct dm-qemu
  wiring (propagates setup error); runs clean through the aggregate runner.
- Re-run on backoff, ideally scoped to just the runner (a throwaway commit with
  only usr/bin/dm-image-boot-tests), or `--detach` with a longer ceiling.
