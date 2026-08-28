# Test + formal-verification hardening plan

Why: a recent audit found ~10 real bugs in secure-terminal / mediawiki-dom-snapshot;
NONE were caught by the formal suite (`verify_formal_absint.py`), which does abstract
interpretation over PURE string transforms. Each escaped for a structural reason the
pure-function lane cannot see:

1. STATEFUL / event-loop / object-lifetime -- a `term` used after a Qt modal's nested
   loop deleted it (use-after-free). The class survived THREE eyeball audits.
2. COMPLEXITY not correctness -- an O(N^2) pass with correct output.
3. TOCTOU over external state -- a sticky pyte mode bit set by output, checked at a
   later event (bracketed-paste; mouse/wheel in CLI mode).
4. INTEGRATION BOUNDARY -- a raw scan diverging from argparse; `int()` past
   int_max_str_digits.
5. MIRROR ORACLE -- `paste_is_multiline`'s CRLF bug was IN a verified function, but the
   T3 oracle re-derived the same logic, so impl==oracle passed.

An AI coder (codex, via the ai-code skill) produced a full six-lane proposal; the lead
reconciled it. Each lane targets one class. Priority = exploitability + recurrence-prevention.

## Status

- P0 modal-site liveness invariant -- PROTOTYPED HERE: `test_modal_liveness.py`. A pure-AST
  tripwire (no Qt import) that inventories every `QDialog.exec()` / `QMessageBox.*` /
  `QInputDialog|QFileDialog|QColorDialog|QFontDialog.get*` / `<expr>.exec()` in main.py +
  terminal.py and FAILS unless each site either re-resolves a live target after the modal
  (`_tab_is_live` / `tabs.indexOf` / `current`) or is in a reasoned `KNOWN_SAFE` /
  `NON_DIALOG_EXEC` allowlist. Passes on the current (fixed) tree (20 sites), and a fake
  unguarded modal trips it. Allowlist keyed by (function, callee) -- stable across line
  shifts (low churn), yet a new modal TYPE in a function or a lost guard still trips. It is
  a TRIPWIRE, not a proof (an AST matcher can't show a guard protects the RIGHT object) --
  the P0 event-sequence suite below is the semantic complement. NEXT: review-gate it, then
  promote into the required dist-ai suite with NO CI path filter that could skip it.
- The other five lanes are DESIGNED, not yet built (each a substantial module):

## Remaining lanes (proposed)

- P0 adversarial Qt event-sequence suite (offscreen): real MainWindow/SecureTerminal, a
  `QTimer.singleShot(0)` firing while each modal is open + deferred-delete drained, so a
  genuinely dead C++ wrapper is reproduced. Model-based over 2-3 tab identities; assert no
  RuntimeError, at-most-one shutdown, a surviving mutation hits the captured identity (not
  the tab now at the stale index), a closed target gets no rename/color/grant/transcript.
  Fixed regression traces for close_tab / rename_tab / save_transcript /
  _pick_custom_tab_color / _on_clipboard_read_requested. The static tripwire supplies the
  coverage link from each modal site to one of these.
- P0 output-armed-input TOCTOU state machine: state
  (tui, alt_screen, foreground_program, DEC-2004, mouse_modes, review_active); generate
  output/mode/paste/click/wheel/focus transitions (DECSET split at byte boundaries); spy
  only at `_write`. Assert authorization AT THE CONSUMING EVENT (`_dispatch_paste`,
  `_mouse_reporting`, focus), never when output first sets a bit -- the check/use
  interleaving abstract interpretation can't express.
- P1 deterministic complexity contracts: per-hot-path work counters (linear total work +
  per-cell caps) + a fresh-process N/2N/4N geometric timing test, fail on a scaling ratio
  above a generous linear threshold. Catches the O(N^2) class without runner-speed flakiness.
- P1 INDEPENDENT + mutation-tested oracles: replace mirror expressions (starting with
  `paste_is_multiline`) with an externally-reviewed decision table + a token-state oracle
  that must NOT call the impl or copy its predicate; add metamorphic properties (LF->CRLF
  preserves classification -- kills the historical CRLF bug); mutation-test the SPEC tests.
- P1 differential integration-boundary tests: generate token vectors from
  `_launch_parser`'s grammar, compare headless dispatch to argparse's resolved namespace
  (option-value-equals-flag, abbreviations, `--` boundary); numeric strings at 0/1/8/20/
  int_max_str_digits-1/limit/limit+1 through run_command + `_safe_int` + real pyte -- assert
  untrusted text never lets a library ValueError/OverflowError/RecursionError escape.

## CI shape

Keep the pure proofs as one required job, but a green formal job must state WHICH layer it
covers -- a proof over pure transforms does not establish lifecycle, timing, complexity, or
library-integration safety. Add required jobs (modal-source-inventory, qt-event-sequences,
boundary-differential); complexity counters in the normal suite, large timing/property runs
in scheduled fuzz CI. Every fixed audit bug gets a named, non-random regression trace.
