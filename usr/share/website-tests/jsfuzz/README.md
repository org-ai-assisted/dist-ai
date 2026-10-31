# jsfuzz -- first-party JS property/fuzz lane

A standalone/CI lane that drives the sites' first-party JavaScript with [fast-check] property
tests under jsdom, confined in the review sandbox. Complementary to the `jscov` unit-coverage
lane: jscov owns exhaustive 100% line/branch coverage of every module; jsfuzz exercises the
adversarial-input surfaces with invariants and holds a deterministic coverage floor so a fuzz
test cannot rot into a vacuous pass.

## Run

    webcheck-jsfuzz-sandbox [<site>=]<site-root> [[<site>=]<site-root> ...]

The driver stages `jsfuzz/` + `jsfuzz-selftest/` + each site's `*.js` (as `roots/<site>/<rel>`),
reuses jscov's `harness.js` jsdom loader (staged fresh, never duplicated), syncs into the sandbox,
and runs `run.sh`. Needs `provision jstest` (node >= 22 + jsdom + c8 + fast-check) in the sandbox.
Local-first: where that toolchain resolves (a provisioned CI runner) the gate runs directly; else
it delegates to the sandbox; else it exits 77 (env-unmet SKIP), never a masked pass.

## Two sub-gates (`run.sh`)

1. **COVERAGE (deterministic).** The `*.fuzz.js` run under c8 with a FIXED fast-check seed +
   bounded `numRuns`, requiring 100% statements/branches/functions/lines over exactly `fuzzed.txt`
   (`c8 --all`, so an included-but-unexercised module is a red, not silently absent). Reproducible,
   so it never flakes in the auto-merge repo. Each `fuzz()`/property carries an explicit `examples`
   corpus that fast-check always runs first -- the per-branch inputs that reach 100% regardless of
   the random sampling.
2. **INVARIANTS (rotating seed).** The same `*.fuzz.js` re-run with a FRESH random seed + more
   runs and NO coverage threshold, exploring for a counterexample. A red here is a genuine finding
   (an uncaught throw, a prototype-pollution read, a sanitizer escape), never flake.

`run.sh` selects the mode via `JSFUZZ_MODE`; `fuzz-harness.js` configures fast-check per mode.

## Non-vacuity self-check (`jsfuzz-selftest/`)

Before the real gates, `run.sh` runs a fail-closed self-check that REQUIRES each sub-gate to fail
as designed: the coverage sub-gate MUST fail on an unexercised include (`b.js` at 0% under
`--all`), and the invariants sub-gate MUST fail on a deliberately-false property's counterexample.
If either self-check passes, `run.sh` refuses the run -- so neither sub-gate can silently regress
to vacuous (no swallowed throws, no zero-run pass).

## Mechanism (how a browser IIFE is fuzzed)

`harness.js` `loadScript(jsPath, bodyHtml, opts)` builds a fresh jsdom window with the real
filename (so c8 attributes coverage to the source), installing stubs for
`prompt`/`window.open`/`navigator.clipboard` and a synchronous `setTimeout`. `fuzz-harness.js`
adds the fast-check config plus adversarial generators: `adversarialString`/`adversarialCodepoint`
(deception-class codepoints -- zero-width, bidi, combining, fullwidth, private-use, astral math --
mixed with ASCII) and `pollutionKey` (`__proto__`/`constructor`/`prototype`/`hasOwnProperty`/
`toString`/`valueOf`, seeded so a plain-`{}` membership map's inherited-key reads are always
exercised). See `analyzer.fuzz.js` (require-based classifier) and `share.fuzz.js` /
`ui.fuzz.js` (DOM widgets, with invariants and a per-copy parametrized suite) for the pattern.

## Fuzzed set (EXPLICIT + GROWING -- not a silent subset)

`fuzzed.txt` lists exactly the files the coverage sub-gate drives to 100%. A file not listed is
NOT silently green -- it is simply not yet in the fuzz corpus. To add one: write `<name>.fuzz.js`
(curated `examples` for 100%, plus >= 1 meaningful invariant), add its `roots/<site>/<rel>` path
to `fuzzed.txt`, re-run. c8 attributes coverage per FILE PATH, so a byte-identical copy's path is
listed and its suite exercises that path too (see `share.fuzz.js`).

[fast-check]: https://github.com/dubzzz/fast-check
