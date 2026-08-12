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
// assert the ASCII character a homoglyph/fullwidth codepoint imitates
function tgt(cp, want) {
  var info = OL.classify(cp);
  var got = info ? info.target : undefined;
  ok(got === want, 'U+' + cp.toString(16) + ' target ' + got + ', want ' + want);
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

// --- homoglyphs: named by the ASCII char they imitate (confusable pairs) ------
// Cyrillic look-alikes -> Latin
[[0x0430,'a'],[0x0435,'e'],[0x043E,'o'],[0x0440,'p'],[0x0441,'c'],[0x0445,'x'],
 [0x0456,'i'],[0x0410,'A'],[0x0415,'E'],[0x041E,'O'],[0x0420,'P'],[0x0421,'C']]
  .forEach(function (t) { cls(t[0], 'homo', 'Cyrillic->' + t[1]); tgt(t[0], t[1]); });
// Greek look-alikes -> Latin
[[0x03BF,'o'],[0x03B1,'a'],[0x03BD,'v'],[0x0391,'A'],[0x0392,'B'],[0x039F,'O'],[0x03A1,'P']]
  .forEach(function (t) { cls(t[0], 'homo', 'Greek->' + t[1]); tgt(t[0], t[1]); });
// Armenian look-alikes -> Latin
[[0x0585,'o'],[0x057D,'u'],[0x0578,'n'],[0x0570,'h']]
  .forEach(function (t) { cls(t[0], 'homo', 'Armenian->' + t[1]); tgt(t[0], t[1]); });
// mathematical alphanumeric symbols -> ASCII (exact block arithmetic)
[[0x1D400,'A'],[0x1D41A,'a'],[0x1D434,'A'],[0x1D467,'z'],[0x1D49C,'A'],[0x1D4EA,'a'],
 [0x1D504,'A'],[0x1D538,'A'],[0x1D670,'A'],[0x1D68A,'a'],[0x1D7CE,'0'],[0x1D7FF,'9']]
  .forEach(function (t) { cls(t[0], 'homo', 'math->' + t[1]); tgt(t[0], t[1]); });
// styled Letterlike Symbols that fill the maths-block holes
[[0x210E,'h'],[0x2102,'C'],[0x210D,'H'],[0x2115,'N'],[0x2119,'P'],[0x211D,'R'],[0x2124,'Z']]
  .forEach(function (t) { cls(t[0], 'homo', 'letterlike->' + t[1]); tgt(t[0], t[1]); });
// a NON-confusable letter in a look-alike script is surfaced by script, NOT homo
cls(0x0416, 'other', 'Cyrillic Zhe (no ASCII look-alike)');   // Zhe
ok(OL.classify(0x0416).name === 'Cyrillic letter', 'non-confusable Cyrillic named by script');
cls(0x0398, 'other', 'Greek Theta (no ASCII look-alike)');    // Theta
ok(OL.classify(0x0398).name === 'Greek letter', 'non-confusable Greek named by script');
cls(0x13A0, 'other', 'Cherokee (script-labelled, not a false homoglyph)');
ok(OL.classify(0x13A0).name === 'Cherokee letter', 'Cherokee named by script');
// reserved (unassigned) holes in the maths blocks must NOT map to a look-alike
[0x1D455, 0x1D49D, 0x1D4BA, 0x1D506, 0x1D53A, 0x1D551].forEach(function (cp) {
  cls(cp, 'other', 'math reserved hole not a false homoglyph');
  ok(OL.classify(cp).target === undefined, 'U+' + cp.toString(16) + ' has no false target');
});
// the relocated script small g / o glyphs (Letterlike) ARE resolved
cls(0x210A, 'homo', 'script small g'); tgt(0x210A, 'g');
cls(0x2134, 'homo', 'script small o'); tgt(0x2134, 'o');
// removed inaccurate Armenian mapping: 0x0566 is surfaced by script, not 'q'
cls(0x0566, 'other', 'Armenian 0x0566 is not a q look-alike');

// --- fullwidth / halfwidth: kept in the `wide` class, ASCII target attached ----
[0xFF00, 0xFFEF].forEach(function (cp) { cls(cp, 'wide', 'fullwidth'); });
cls(0xFF41, 'wide', 'fullwidth a'); tgt(0xFF41, 'a');
cls(0xFF21, 'wide', 'fullwidth A'); tgt(0xFF21, 'A');
cls(0xFF10, 'wide', 'fullwidth 0'); tgt(0xFF10, '0');

// --- private use / other non-ASCII --------------------------------------------
[0xE000, 0xF8FF, 0xF0000, 0x100000].forEach(function (cp) { cls(cp, 'other', 'private use'); });
cls(0x4E2D, 'other', 'CJK non-ASCII');
cls(0x1F600, 'other', 'emoji (astral)');

// --- boundary pairs (edge in one class, next codepoint in another) ------------
cls(0x7E, 'null', 'boundary 0x7E safe');   cls(0x7F, 'ctrl', 'boundary 0x7F ctrl');
cls(0x9F, 'ctrl', 'boundary 0x9F ctrl');   cls(0x00A0, 'space', 'boundary 0xA0 space');
cls(0x036F, 'comb', 'boundary 0x36F comb'); cls(0x0370, 'other', 'boundary 0x370 Greek (non-confusable)');
cls(0x03BF, 'homo', 'Greek omicron confusable'); cls(0x0430, 'homo', 'Cyrillic a confusable');
cls(0x0400, 'other', 'boundary 0x400 Cyrillic (non-confusable)');

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
  var s = 'ex' + String.fromCodePoint(0x0430) + 'mple.org ' + // homoglyph
          'a' + String.fromCodePoint(0x200B) + 'b ' +       // zero-width
          String.fromCodePoint(0x1F600);                     // emoji (astral)
  var r = OL.analyze(s);
  ok(r.flagged === 3, 'analyze flagged=3, got ' + r.flagged);
  ok(r.counts["looks like 'a'"] === 1, 'analyze homoglyph count');
  ok(r.counts['zero-width space'] === 1, 'analyze zw count');
  // safe runs must coalesce and reconstruct the original string exactly
  var rebuilt = r.items.map(function (it) { return it.safe !== undefined ? it.safe : it.ch; }).join('');
  ok(rebuilt === s, 'analyze reconstructs input');
  // adjacent safe chars share one token
  var safeTokens = r.items.filter(function (it) { return it.safe !== undefined; });
  ok(safeTokens.length >= 1 && safeTokens[0].safe === 'ex', 'analyze coalesces safe run');
})();

ok(OL.analyze('').flagged === 0, 'analyze empty');
ok(OL.analyze('plain ascii only\n').flagged === 0, 'analyze clean ascii');
ok(OL.analyze(null).flagged === 0, 'analyze null-safe');

// --- toAscii() ----------------------------------------------------------------
ok(OL.toAscii('a' + String.fromCodePoint(0x200B) + 'b' + String.fromCodePoint(0x202E) + 'c') === 'abc',
  'toAscii strips flagged');
ok(OL.toAscii('hello world\tx\n') === 'hello world\tx\n', 'toAscii keeps ascii + tab/newline');
ok(OL.toAscii('ex' + String.fromCodePoint(0x0430) + 'mple.org') === 'exmple.org', 'toAscii strips homoglyph');
ok(OL.toAscii('') === '', 'toAscii empty');

// --- result -------------------------------------------------------------------
process.stdout.write('web-analyzer-tests: ' + pass + ' passed, ' + fail + ' failed\n');
process.exit(fail === 0 ? 0 : 1);
