'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* 100% coverage of output-lies' analyze/analyzer.js -- the DOM-free Unicode-deception classifier.
   Covered via require() (the UMD module.exports path + direct function calls) AND one harness
   load (the browser root.OL path). classify() is a long return ladder: one codepoint per branch. */
const { test } = require('node:test');
const assert = require('node:assert');
const { loadScript, sitePath } = require('./harness.js');

const PATH = sitePath('output-lies.github.io', 'analyze/analyzer.js');
const OL = require(PATH);   // UMD: module.exports = factory()

/* [codepoint, expected cls] -- one entry per classify() branch; null = safe (returns null). */
const CASES = [
  [0x09, null], [0x0A, null], [0x0D, null],       // safe whitespace (all three || operands)
  [0x01, 'ctrl'],                                  // C0
  [0x41, null],                                    // printable ASCII
  [0x7F, 'ctrl'], [0x85, 'ctrl'],                  // DEL, C1
  [0x200E, 'bidi'], [0x200F, 'bidi'], [0x061C, 'bidi'], [0x202A, 'bidi'], [0x2066, 'bidi'],
  [0x200B, 'zw'], [0x200C, 'zw'], [0x200D, 'zw'], [0x2060, 'zw'], [0x2061, 'zw'],
  [0xFEFF, 'zw'], [0x180E, 'zw'], [0xFFF9, 'zw'], [0x00AD, 'zw'],
  [0x2028, 'ctrl'], [0x2029, 'ctrl'],              // line/paragraph separators
  [0x00A0, 'space'], [0x1680, 'space'], [0x2000, 'space'], [0x202F, 'space'],
  [0x205F, 'space'], [0x3000, 'space'], [0x2800, 'space'],
  [0xE0001, 'ctrl'],                               // tag character
  [0xFE00, 'comb'], [0xE0100, 'comb'],             // variation selectors (both || operands)
  [0x034F, 'comb'],                                // combining grapheme joiner
  [0x0300, 'comb'], [0x1AB0, 'comb'], [0x1DC0, 'comb'], [0x20D0, 'comb'], [0xFE20, 'comb'],
  [0xE000, 'other'], [0xF0000, 'other'], [0x100000, 'other'],   // private use (3 ranges)
  [0xFF21, 'wide'],                                // fullwidth 'A'
  [0x1D400, 'homo'], [0x1D41A, 'homo'], [0x1D7CE, 'homo'],      // math bold A / a / digit 0
  [0x0430, 'homo'],                                // Cyrillic a (CONFUSABLES)
  [0x1D455, 'other'],                              // MATH_RESERVED hole -> non-ASCII
  [0x03B2, 'other'], [0x1F00, 'other'],            // Greek (both ranges)
  [0x0444, 'other'], [0x1C80, 'other'], [0x2DE0, 'other'],      // Cyrillic (3 ranges)
  [0x0531, 'other'],                               // Armenian
  [0x13A0, 'other'], [0xAB70, 'other'],            // Cherokee (both ranges)
  [0x05D0, 'other'],                               // Hebrew
  [0x0600, 'other'], [0x0750, 'other'],            // Arabic (both ranges)
  [0x3041, 'other'],                               // kana
  [0x4E00, 'other'], [0x3400, 'other'],            // CJK (both ranges)
  [0xAC00, 'other'], [0x1100, 'other'],            // Hangul (both ranges)
  [0xFF61, 'wide'],                                // halfwidth form (fullwidth/halfwidth fallthrough)
  [0xA015, 'other'],                               // non-ASCII final fallthrough (Yi)
];

/* Build a string from codepoints -- keeps this SOURCE pure ASCII (no literal non-ASCII bytes). */
function s() { return String.fromCodePoint.apply(null, arguments); }

test('classify: one codepoint per branch', function () {
  for (const [cp, want] of CASES) {
    const info = OL.classify(cp);
    if (want === null) { assert.strictEqual(info, null, 'U+' + cp.toString(16)); }
    else { assert.strictEqual(info.cls, want, 'U+' + cp.toString(16)); }
  }
});

test('classify: homoglyph targets and fullwidth target', function () {
  assert.strictEqual(OL.classify(0x0430).target, 'a');
  assert.strictEqual(OL.classify(0x1D400).target, 'A');
  assert.strictEqual(OL.classify(0xFF21).target, 'A');
  assert.strictEqual(OL.confusableTarget(0x1D7CE), '0');
  assert.strictEqual(OL.confusableTarget(0x0041), null);   // plain ASCII: no confusable
});

test('analyze: safe runs, leading/trailing flagged, counts', function () {
  const r = OL.analyze(s(0x61, 0x200B, 0x62, 0x200C));   // safe 'a', flag, safe 'b', flag (ends flagged)
  assert.strictEqual(r.flagged, 2);
  assert.deepStrictEqual(r.items[0], { safe: 'a' });
  const r2 = OL.analyze(s(0x200B, 0x78));                 // leading flagged (run empty), trailing safe run
  assert.strictEqual(r2.flagged, 1);
  assert.strictEqual(r2.items[r2.items.length - 1].safe, 'x');
  assert.strictEqual(OL.analyze(null).flagged, 0);        // null -> ''
  assert.deepStrictEqual(OL.analyze('abc').items, [{ safe: 'abc' }]);
});

test('toAscii strips flagged, keeps ascii; null -> empty', function () {
  assert.strictEqual(OL.toAscii(s(0x61, 0x200B, 0x62)), 'ab');
  assert.strictEqual(OL.toAscii(null), '');
});

test('hex pads to >=4 and leaves longer alone', function () {
  assert.strictEqual(OL.hex(0x9), 'U+0009');
  assert.strictEqual(OL.hex(0x1D400), 'U+1D400');
});

test('browser root.OL branch: loading sets window.OL', function () {
  const { win } = loadScript(PATH, '', {});
  assert.ok(win.OL && typeof win.OL.classify === 'function');
});
