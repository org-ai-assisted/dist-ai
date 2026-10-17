'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* jscov self-check subject B: listed in covered.txt but DELIBERATELY never required by any test.
   Under c8 --all it reports 0% -> the gate must FAIL. That failure is the self-check's success. */
function pick(flag) {
  if (flag) { return 1; }
  return 2;
}
module.exports = pick;
