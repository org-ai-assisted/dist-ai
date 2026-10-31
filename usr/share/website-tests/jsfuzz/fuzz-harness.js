'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* jsfuzz shared harness: fast-check configuration (two sub-gate modes) + adversarial input
   generators, reusing the jscov jsdom loader (harness.js, staged alongside). Each first-party
   module in fuzzed.txt is both driven to 100% c8 (coverage mode) and probed for invariant
   counterexamples (invariants mode). run.sh selects the mode via JSFUZZ_MODE. */

const fc = require('fast-check');
const { test } = require('node:test');
const { loadScript, sitePath } = require('./harness.js');

/* MODE:
   - 'coverage' (default): DETERMINISTIC -- a FIXED seed + bounded numRuns, so c8 --check-coverage
     is reproducible every run (never flaky in the auto-merge repo).
   - 'invariants': a FRESH random seed + more runs, NO coverage threshold -- explores the input
     space for a counterexample. A red here is a genuine finding, not flake. */
const MODE = process.env.JSFUZZ_MODE === 'invariants' ? 'invariants' : 'coverage';
const COVERAGE_SEED = 0x5eed1337;
const COVERAGE_RUNS = Number(process.env.JSFUZZ_COVERAGE_RUNS || 200);
const INVARIANT_RUNS = Number(process.env.JSFUZZ_RUNS || 600);

/* Register a fast-check property as a node:test case, configured per mode. `examples` (optional)
   is a list of explicit [input] tuples fast-check ALWAYS runs first, in BOTH modes -- the curated
   per-branch corpus that makes the coverage sub-gate reach 100% DETERMINISTICALLY (independent of
   the random seed's sampling), while the random runs add fuzz robustness. */
function fuzz(name, arb, predicate, examples) {
  test(name, function () {
    const opts = MODE === 'invariants'
      ? { numRuns: INVARIANT_RUNS }
      : { seed: COVERAGE_SEED, numRuns: COVERAGE_RUNS };
    if (examples && examples.length) { opts.examples = examples; }
    fc.assert(fc.property(arb, predicate), opts);
  });
}

/* Prototype-pollution key generator (js-object-map-prototype-pollution): the string keys that bite
   a plain-{} membership map. Seeded explicitly so the corpus ALWAYS exercises them (a parity
   fixture that happens to contain no prototype-name token stays green while the sides disagree). */
const pollutionKey = fc.constantFrom(
  '__proto__', 'constructor', 'prototype', 'hasOwnProperty', 'toString', 'valueOf',
);

/* A single adversarial codepoint: deception classes (zero-width, bidi, combining, fullwidth,
   private-use, astral math) plus plain ASCII and anything. */
const adversarialCodepoint = fc.oneof(
  fc.integer({ min: 0x00, max: 0x7f }),        // ASCII + C0 control
  fc.integer({ min: 0x200b, max: 0x200f }),    // zero-width + LRM/RLM
  fc.integer({ min: 0x202a, max: 0x202e }),    // bidi embeddings/overrides
  fc.integer({ min: 0x2066, max: 0x2069 }),    // bidi isolates
  fc.integer({ min: 0x0300, max: 0x036f }),    // combining diacriticals
  fc.integer({ min: 0xff01, max: 0xff5e }),    // fullwidth ASCII
  fc.integer({ min: 0xe000, max: 0xf8ff }),    // private use
  fc.integer({ min: 0x1d400, max: 0x1d7ff }),  // math alphanumeric (astral)
  fc.integer({ min: 0x00, max: 0x10ffff }),    // anything in range
);

function cpToChar(cp) {
  try { return String.fromCodePoint(cp); } catch (e) { return ''; }
}

/* An adversarial string built from those codepoints (version-robust: fc.array + join, no reliance
   on a specific fc string-unit API). Mixes in plain ASCII fragments too. */
const adversarialChar = fc.oneof(
  adversarialCodepoint.map(cpToChar),
  fc.constantFrom('a', 'A', '0', ' ', ':', '/', '.', '-', '@'),
);
const adversarialString = fc.array(adversarialChar, { maxLength: 48 }).map(function (a) { return a.join(''); });

module.exports = {
  fc,
  test,
  fuzz,
  loadScript,
  sitePath,
  MODE,
  pollutionKey,
  adversarialCodepoint,
  cpToChar,
  adversarialString,
};
