# pyte-tests

Comprehensive public-API, property, and fuzz coverage for the [`pyte`][pyte]
terminal-emulator library (fork at `org-ai-assisted/pyte`), packaged as a
dist-ai suite.

[pyte]: https://github.com/selectel/pyte

## Commands

- `pyte-tests` -- runs pytest over the full suite:
  - `test_full_api.py` -- ~100 behavioural unit tests for every public class,
    method, and function (Stream, ByteStream, Screen, HistoryScreen,
    DiffScreen, DebugScreen, control/escape/CSI/OSC handling, charsets, modes,
    cursor, resize, SGR, device reports, grapheme clustering).
  - `test_full_properties.py` -- Hypothesis property tests (state invariants,
    resize, SGR, cursor clamping, history paging, parser chunk-invariance).
  - `test_full_regressions.py` -- regressions for the parser crash and
    data-loss defects (see the `pyte-audit` repository), each expected to pass
    or to still reproduce per the tree's own declaration (below).
- `pyte-tests-fuzz [iterations] [seed]` -- in-process fuzzer for
  Stream/ByteStream/Screen; fails only on a crash signature NOT already listed
  in `known_crashes.json` (the known/reported defects), printing the seed and
  reproducing sequence for any new finding.

## Which defects a tree is expected to have

The suites run against pyte trees that fix different subsets of the audited
defects, so each tree declares its own state in a `pyte-audit-fixes.txt`
manifest at its root -- one `pyte-audit` finding id per line. A tree with no
manifest (stock upstream, a distribution package) declares nothing.

- Declared fixed: the regression test must pass, and the fuzzer no longer
  allowlists that defect's crash signatures -- a regression is red.
- Not declared: the regression test is `xfail(strict=True)` and the signatures
  stay allowlisted -- fixing the defect without declaring it is an XPASS, also
  red.

The expectation is never derived from the observed behaviour: a test that
decided by running the crash could never disagree with the code under test.

## Targeting a checkout

Both commands honour `PYTE_REPO=/path/to/pyte/checkout`, whose root is prepended
to `PYTHONPATH` so `import pyte` binds to that tree. Under dist-ai CI this is
wired automatically from the component checkout. `pyte-tests` targets the modern
pyte API (0.8.3+) and SKIPs (exit 77) an older build such as Debian
`python3-pyte` 0.8.0.

## Requirements

`python3`, `python3-pytest`, `python3-wcwidth`; `python3-hypothesis` for the
property tests (skipped if absent). No root, no network.
