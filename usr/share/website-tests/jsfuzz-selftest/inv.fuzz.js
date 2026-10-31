'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* Invariants self-check: a DELIBERATELY-FALSE property (n !== n is always false) that fast-check
   MUST refute with a counterexample. run.sh's invariants sub-gate asserts this fails with a
   fast-check counterexample; a PASS would mean the fuzz is not actually asserting (a vacuous
   invariants gate). Self-contained. */
const { test } = require('node:test');
const fc = require('fast-check');

test('jsfuzz self-check inv: a false property must yield a counterexample', function () {
  fc.assert(fc.property(fc.integer(), function (n) { return n !== n; }));
});
