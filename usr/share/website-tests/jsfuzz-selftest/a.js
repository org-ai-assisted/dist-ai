'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* jsfuzz self-check subject A: cov.fuzz.js fuzzes BOTH branches, so it reaches 100%. Its sibling
   b.js is listed in fuzzed.txt but NEVER exercised -- under c8 --all that drops coverage below
   100% and FAILS, which is what the coverage self-check asserts (proving the real coverage
   sub-gate is not vacuous). */
function pick(flag) {
  if (flag) { return 1; }
  return 2;
}
module.exports = pick;
