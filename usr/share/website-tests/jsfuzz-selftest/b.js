'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* jsfuzz self-check subject B: listed in fuzzed.txt but DELIBERATELY never exercised by any
   fuzz. Under c8 --all it reports 0% -> the coverage sub-gate must FAIL. That failure is the
   self-check's success. */
function pick(flag) {
  if (flag) { return 1; }
  return 2;
}
module.exports = pick;
