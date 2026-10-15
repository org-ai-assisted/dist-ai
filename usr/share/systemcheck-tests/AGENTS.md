# systemcheck-tests

systemcheck `ai` tracks arraybolt3/trixie wholesale (plus a local `was_executed` deferral of
fragment sourcing so a bare source is cheap). These tests target that tree.

The trixie-rewrite findings once filed as org-ai-assisted/systemcheck #19/#20/#21 are settled:
#19/#20 closed by-design, #21's valid findings fixed upstream and absorbed. No
`@unittest.expectedFailure` markers remain. Behaviors that are BY DESIGN -- do NOT re-add tests
asserting the opposite:
- a non-CI headless/sessionless run WARNS (or reports its real result); it does not force N/A
  (#20). `--ci` still skips via `systemcheck_nosession_autoskip=true`.
- a config drop-in MAY clear `systemcheck_kernel_hardening_token_list` (#19).
- Secure Boot / firmware is one prose line `Firmware: {BIOS|UEFI}, Secure Boot
  {enabled|disabled|unavailable}` + a verbose-only warning when indeterminate, NOT structured
  `>TOKEN<` tags (#21, maintainer-confirmed). Unknown SB defaults the shared flag to disabled.
- the kernel `BUG` match is case-insensitive by design; the `BUG at` oops form IS matched (#21).
