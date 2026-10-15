# systemcheck-tests

systemcheck `ai` tracks arraybolt3/trixie wholesale; fragment sourcing is deferred behind
`was_executed` so a bare source defines the orchestrator functions without loading fragments.
These tests target that tree.

org-ai-assisted/systemcheck#21 collects the open trixie-rewrite regressions; each test for one
is `@unittest.expectedFailure` with the issue link. An unexpected pass (xpass reddens the run)
means it is fixed upstream -- drop the decorator then.

By design -- do NOT re-add tests asserting the opposite:
- a non-CI headless/sessionless run WARNS (or reports its real result); it does not force N/A
  (systemcheck#20, closed). `--ci` still skips via `systemcheck_nosession_autoskip=true`.
- a config drop-in MAY clear `systemcheck_kernel_hardening_token_list` (systemcheck#19, closed).
