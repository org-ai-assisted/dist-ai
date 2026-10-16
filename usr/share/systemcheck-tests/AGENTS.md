# systemcheck-tests

systemcheck `ai` tracks arraybolt3/trixie wholesale, including upstream's top-level fragment
sourcing (a library must be functional when sourced -- NO downstream `was_executed` deferral;
that was reverted). A bare `source` of the orchestrator therefore sources all ~40 check
fragments + msgcollector from the HARDCODED `/usr/libexec/{systemcheck,msgcollector}` paths.

Consequence for tests: a test that SOURCES the orchestrator must stage the checkout at
`/usr/libexec` (the installed copy lags). Those tests live in the bwrap suite
(`systemcheck-tests-bwrap/test_systemcheck_orchestrator_isolated.py`, via
`source_orchestrator()` which binds the checkout with bubblewrap). The non-bwrap suite keeps
only STATIC (text-scan) checks of the orchestrator. Do NOT re-add a `was_executed` gate to make
a bare source cheap, and do NOT re-add a "fragments not sourced on source" test -- fragments
ARE defined on source, by design.

The trixie-rewrite findings filed as org-ai-assisted/systemcheck #19/#20/#21 are settled:
#19/#20 closed by-design, #21's valid findings fixed upstream and absorbed. Behaviors BY DESIGN
-- do NOT re-add tests asserting the opposite:
- a non-CI headless/sessionless run WARNS (or reports its real result); it does not force N/A
  (#20). `--ci` still skips via `systemcheck_nosession_autoskip=true`.
- a config drop-in MAY clear `systemcheck_kernel_hardening_token_list` (#19).
- Secure Boot / firmware is one prose line `Firmware: {BIOS|UEFI}, Secure Boot
  {enabled|disabled|unavailable}` + a verbose-only warning when indeterminate, NOT structured
  `>TOKEN<` tags (#21). Unknown SB defaults the shared flag to disabled.
- the kernel `BUG` match is case-insensitive by design; the `BUG at` oops form IS matched (#21).
