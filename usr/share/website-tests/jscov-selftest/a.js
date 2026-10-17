'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* jscov self-check subject A: self-executes both branches on require, so a test that requires it
   reaches 100%. Its sibling b.js is listed in covered.txt but NEVER required -- under c8 --all
   that unexercised include drops coverage below 100% and FAILS, which is what the self-check
   asserts. If it does NOT fail, the coverage gate is vacuous (--all missing/ineffective). */
function pick(flag) {
  if (flag) { return 1; }
  return 2;
}
pick(1);
pick(0);
module.exports = pick;
