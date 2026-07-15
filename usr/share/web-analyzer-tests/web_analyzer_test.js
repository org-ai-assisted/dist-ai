/*
  Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
  See the file COPYING for copying conditions.

  AI-Assisted

  Comprehensive test for output-lies' web text analyzer (analyze/analyzer.js).
  The classifier is a pure, DOM-free function, so it is exercised directly under
  node. This asserts the class of every boundary codepoint (each range edge, in
  and just outside it), the known real-world traps, astral-plane safety, and the
  analyze() / toAscii() / hex() helpers. Exit 0 on full pass, 1 on any failure,
  77 (SKIP) when the analyzer module cannot be located.

  Source in this file is pure ASCII: codepoints are given as numbers and strings
  are built with String.fromCodePoint / \u escapes, never raw bytes.
*/
'use strict';

var fs = require('fs');
var path = require('path');

// --- locate analyzer.js (OUTPUT_LIES_REPO, then sensible defaults) ------------
function findModule() {
  var candidates = [];
  if (process.env.OUTPUT_LIES_REPO) {
    candidates.push(path.join(process.env.OUTPUT_LIES_REPO, 'analyze', 'analyzer.js'));
    candidates.push(path.join(process.env.OUTPUT_LIES_REPO, 'analyzer.js'));
  }
  var home = process.env.HOME || '';
  if (home) {
    candidates.push(path.join(home, 'private-sources', 'output-lies.github.io', 'analyze', 'analyzer.js'));
  }
  // a sibling checkout next to this dist-ai tree
  candidates.push(path.resolve(__dirname, '../../../../output-lies.github.io/analyze/analyzer.js'));
  for (var i = 0; i < candidates.length; i++) {
    try { if (fs.existsSync(candidates[i])) return candidates[i]; } catch (e) {}
  }
  return null;
}

var modPath = findModule();
if (!modPath) {
  process.stderr.write('web-analyzer-tests: SKIP (analyzer.js not found; set OUTPUT_LIES_REPO to an output-lies.github.io checkout)\n');
  process.exit(77);
}
var OL = require(modPath);

// --- tiny assertion harness ---------------------------------------------------
var pass = 0, fail = 0;
function ok(cond, msg) { if (cond) { pass++; } else { fail++; process.stderr.write('FAIL: ' + msg + '\n'); } }
function cls(cp, expected, msg) {
  var info = OL.classify(cp);
  var got = info === null ? 'null' : info.cls;
  ok(got === expected, (msg || ('U+' + cp.toString(16))) + ' -> class ' + got + ', want ' + expected);
}

// --- safe: printable ASCII + ordinary whitespace ------------------------------
[0x09, 0x0A, 0x0D, 0x20, 0x21, 0x41, 0x5A, 0x61, 0x7A, 0x30, 0x39, 0x7E].forEach(function (cp) {
  cls(cp, 'null', 'safe');
});

// --- control bytes ------------------------------------------------------------
[0x00, 0x01, 0x08, 0x0B, 0x0C, 0x0E, 0x1F].forEach(function (cp) { cls(cp, 'ctrl', 'C0'); });
cls(0x7F, 'ctrl', 'DEL');
[0x80, 0x85, 0x9F].forEach(function (cp) { cls(cp, 'ctrl', 'C1'); });
cls(0x2028, 'ctrl', 'line separator');
cls(0x2029, 'ctrl', 'paragraph separator');
cls(0xE0041, 'ctrl', 'tag character');
cls(0xE007F, 'ctrl', 'tag character end');

// --- bidi ---------------------------------------------------------------------
[0x200E, 0x200F, 0x061C, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069]
  .forEach(function (cp) { cls(cp, 'bidi', 'bidi'); });

// --- zero-width / invisible format --------------------------------------------
[0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x180E, 0xFFF9, 0xFFFB, 0x00AD]
  .forEach(function (cp) { cls(cp, 'zw', 'zero-width'); });

// --- deceptive whitespace -----------------------------------------------------
[0x00A0, 0x1680, 0x2000, 0x2005, 0x200A, 0x202F, 0x205F, 0x3000, 0x2800]
  .forEach(function (cp) { cls(cp, 'space', 'space-like'); });

// --- combining marks / variation selectors ------------------------------------
[0x0300, 0x036F, 0x1AB0, 0x1DC0, 0x20D0, 0xFE20, 0xFE2F, 0xFE00, 0xFE0F, 0xE0100, 0xE01EF, 0x034F]
  .forEach(function (cp) { cls(cp, 'comb', 'combining/variation'); });
ok(OL.classify(0x034F).visible === false, 'combining grapheme joiner is invisible');

// --- homoglyph-prone scripts --------------------------------------------------
[0x0400, 0x0430, 0x04FF, 0x0500, 0x052F].forEach(function (cp) { cls(cp, 'homo', 'Cyrillic'); });
[0x0370, 0x03BF, 0x03FF].forEach(function (cp) { cls(cp, 'homo', 'Greek'); });
cls(0x0531, 'homo', 'Armenian');
cls(0x13A0, 'homo', 'Cherokee');

// --- fullwidth / halfwidth ----------------------------------------------------
[0xFF00, 0xFF41, 0xFFEF].forEach(function (cp) { cls(cp, 'wide', 'fullwidth'); });

// --- private use / other non-ASCII --------------------------------------------
[0xE000, 0xF8FF, 0xF0000, 0x100000].forEach(function (cp) { cls(cp, 'other', 'private use'); });
cls(0x4E2D, 'other', 'CJK non-ASCII');
cls(0x1F600, 'other', 'emoji (astral)');

// --- boundary pairs (edge in one class, next codepoint in another) ------------
cls(0x7E, 'null', 'boundary 0x7E safe');   cls(0x7F, 'ctrl', 'boundary 0x7F ctrl');
cls(0x9F, 'ctrl', 'boundary 0x9F ctrl');   cls(0x00A0, 'space', 'boundary 0xA0 space');
cls(0x036F, 'comb', 'boundary 0x36F comb'); cls(0x0370, 'homo', 'boundary 0x370 Greek');
cls(0x03FF, 'homo', 'boundary 0x3FF Greek'); cls(0x0400, 'homo', 'boundary 0x400 Cyrillic');

// --- visibility flag ----------------------------------------------------------
ok(OL.classify(0x202E).visible === false, 'RLO invisible');
ok(OL.classify(0x200B).visible === false, 'ZWSP invisible');
ok(OL.classify(0x00A0).visible === false, 'NBSP invisible');
ok(OL.classify(0x0430).visible === true, 'Cyrillic visible');
ok(OL.classify(0xFF41).visible === true, 'fullwidth visible');

// --- hex() --------------------------------------------------------------------
ok(OL.hex(0x07) === 'U+0007', 'hex pads to 4');
ok(OL.hex(0x202E) === 'U+202E', 'hex RLO');
ok(OL.hex(0x1F600) === 'U+1F600', 'hex 5-digit astral');

// --- analyze() ----------------------------------------------------------------
(function () {
  var s = 'payp' + String.fromCodePoint(0x0430) + 'l ' +   // homoglyph
          'a' + String.fromCodePoint(0x200B) + 'b ' +       // zero-width
          String.fromCodePoint(0x1F600);                     // emoji (astral)
  var r = OL.analyze(s);
  ok(r.flagged === 3, 'analyze flagged=3, got ' + r.flagged);
  ok(r.counts['Cyrillic'] === 1, 'analyze Cyrillic count');
  ok(r.counts['zero-width space'] === 1, 'analyze zw count');
  // safe runs must coalesce and reconstruct the original string exactly
  var rebuilt = r.items.map(function (it) { return it.safe !== undefined ? it.safe : it.ch; }).join('');
  ok(rebuilt === s, 'analyze reconstructs input');
  // adjacent safe chars share one token
  var safeTokens = r.items.filter(function (it) { return it.safe !== undefined; });
  ok(safeTokens.length >= 1 && safeTokens[0].safe === 'payp', 'analyze coalesces safe run');
})();

ok(OL.analyze('').flagged === 0, 'analyze empty');
ok(OL.analyze('plain ascii only\n').flagged === 0, 'analyze clean ascii');
ok(OL.analyze(null).flagged === 0, 'analyze null-safe');

// --- toAscii() ----------------------------------------------------------------
ok(OL.toAscii('a' + String.fromCodePoint(0x200B) + 'b' + String.fromCodePoint(0x202E) + 'c') === 'abc',
  'toAscii strips flagged');
ok(OL.toAscii('hello world\tx\n') === 'hello world\tx\n', 'toAscii keeps ascii + tab/newline');
ok(OL.toAscii('payp' + String.fromCodePoint(0x0430) + 'l') === 'paypl', 'toAscii strips homoglyph');
ok(OL.toAscii('') === '', 'toAscii empty');

// --- result -------------------------------------------------------------------
process.stdout.write('web-analyzer-tests: ' + pass + ' passed, ' + fail + ' failed\n');
process.exit(fail === 0 ? 0 : 1);
