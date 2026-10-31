'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* Coverage self-check: fuzz a.js over BOTH branches (so a.js reaches 100%) while b.js -- also in
   fuzzed.txt -- is never touched. Under c8 --all, b.js at 0% makes the coverage sub-gate FAIL;
   that failure is the proof the gate is non-vacuous. The property itself PASSES (so the failure
   is the b.js shortfall, not a counterexample). Self-contained (no fuzz-harness.js here -- the
   selftest dir stages only the jscov loader). */
const path = require('node:path');
const { test } = require('node:test');
const fc = require('fast-check');

const pick = require(path.join(__dirname, 'a.js'));

test('jsfuzz self-check cov: fuzz a.js both branches, leave b.js unexercised', function () {
  fc.assert(
    fc.property(fc.boolean(), function (flag) {
      const r = pick(flag);
      return r === 1 || r === 2;
    }),
    { seed: 1, numRuns: 20 },
  );
});
