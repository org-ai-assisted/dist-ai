'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* Property/fuzz tests for output-lies' analyze/analyzer.js -- the shared, DOM-free deception
   classifier (UMD; require()d directly). Two sub-gates (see fuzz-harness.js): a deterministic
   coverage pass (a curated per-branch codepoint corpus in `examples`, run every time, drives
   100% c8) and a rotating-seed invariants pass (adversarial input, asserts the module never
   throws and its outputs stay well-formed). */

const { fc, test, fuzz, loadScript, sitePath } = require('./fuzz-harness.js');

const APATH = sitePath('output-lies.github.io', 'analyze/analyzer.js');
const OL = require(APATH);

/* Cover the UMD BROWSER branch (`else root.OL = factory()` + the `self` ternary arm), which
   require() in node never reaches: load analyzer into a jsdom window (module.exports absent, self
   defined) so it installs window.OL, and exercise it there. */
test('analyzer: UMD browser load sets window.OL and classifies', function () {
  const loaded = loadScript(APATH, '', {});
  if (typeof loaded.win.OL.classify !== 'function') { throw new Error('window.OL.classify missing'); }
  if (loaded.win.OL.classify(0x41) !== null) { throw new Error('ASCII should be safe'); }
  if (loaded.win.OL.classify(0x0430) === null) { throw new Error('Cyrillic confusable should flag'); }
});

const CLASSES = ['ctrl', 'bidi', 'zw', 'space', 'comb', 'other', 'wide', 'homo'];

/* One representative codepoint for EVERY classify / mathAlnum / confusableTarget / scriptName
   branch, so c8 --all reaches 100% deterministically regardless of the random seed. */
const CP_CORPUS = [
  0x09, 0x0a, 0x0d, 0x20, 0x41, 0x7e,            // safe (tab/nl/cr, space, letter, ~)
  0x00, 0x1f, 0x7f, 0x80, 0x9f,                  // C0 / DEL / C1 controls
  0x200e, 0x200f, 0x061c, 0x202a, 0x202e, 0x2066, 0x2069,  // bidi
  0x200b, 0x200c, 0x200d, 0x2060, 0x2061, 0x2064, 0xfeff, 0x180e, 0xfff9, 0xfffb, 0x00ad,  // zero-width
  0x2028, 0x2029,                                // line / paragraph separators
  0x00a0, 0x1680, 0x2000, 0x200a, 0x202f, 0x205f, 0x3000, 0x2800,  // deceptive spaces
  0xe0000, 0xe007f,                              // tag characters
  0xfe00, 0xfe0f, 0xe0100, 0xe01ef, 0x034f,      // variation selectors + CGJ
  0x0300, 0x036f, 0x1ab0, 0x1aff, 0x1dc0, 0x1dff, 0x20d0, 0x20ff, 0xfe20, 0xfe2f,  // combining
  0xe000, 0xf8ff, 0xf0000, 0xffffd, 0x100000, 0x10fffd,  // private use
  0xff01, 0xff21, 0xff5e,                        // fullwidth ASCII forms
  0x0430, 0x0410, 0x0391, 0x03bf, 0x0585, 0x210e, 0x01c0,  // CONFUSABLES (various sub-tables)
  0x1d400, 0x1d41a, 0x1d434, 0x1d468, 0x1d670,   // math letters (d<26, d>=26, several blocks)
  0x1d7ce, 0x1d7e2, 0x1d7f6,                     // math digits (several blocks)
  0x1d455, 0x1d49d,                              // MATH_RESERVED (mathAlnum -> null)
  0x1d7cd, 0x1d800,                              // mathAlnum loop fall-through -> null
  0x0370, 0x03ff, 0x1f00, 0x1fff,                // Greek script ranges
  0x0401, 0x052f, 0x1c80, 0x1c8f, 0x2de0, 0x2dff, // Cyrillic script ranges (non-confusable)
  0x0530, 0x058f,                                // Armenian script
  0x13a0, 0x13ff, 0xab70, 0xabbf,                // Cherokee
  0x0590, 0x05ff,                                // Hebrew
  0x0600, 0x06ff, 0x0750, 0x077f,                // Arabic
  0x3040, 0x30ff,                                // Japanese kana
  0x4e00, 0x9fff, 0x3400, 0x4dbf,                // CJK
  0xac00, 0xd7af, 0x1100, 0x11ff,                // Hangul
  0xff00, 0xffef,                                // other fullwidth/halfwidth forms
  0x2600, 0x1f600, 0x10ffff,                     // non-ASCII else (symbol, emoji, max)
];

/* classify(cp): null for safe text, else a well-formed descriptor. */
fuzz('classify: every codepoint yields null or a well-formed descriptor',
  fc.integer({ min: 0, max: 0x10ffff }),
  function (cp) {
    const r = OL.classify(cp);
    if (r === null) { return true; }
    if (CLASSES.indexOf(r.cls) === -1) { return false; }
    if (typeof r.name !== 'string' || r.name.length === 0) { return false; }
    if (typeof r.visible !== 'boolean') { return false; }
    if ('target' in r && (typeof r.target !== 'string' || r.target.length !== 1)) { return false; }
    return true;
  },
  CP_CORPUS.map(function (cp) { return [cp]; }));

/* confusableTarget(cp): a single ASCII char or null. */
fuzz('confusableTarget: single ASCII char or null',
  fc.integer({ min: 0, max: 0x10ffff }),
  function (cp) {
    const t = OL.confusableTarget(cp);
    return t === null || (typeof t === 'string' && t.length === 1 && t.charCodeAt(0) <= 0x7e);
  },
  CP_CORPUS.map(function (cp) { return [cp]; }));

/* hex(cp): always U+ followed by >= 4 uppercase hex digits. */
fuzz('hex: U+XXXX format, >= 4 uppercase hex digits',
  fc.integer({ min: 0, max: 0x10ffff }),
  function (cp) { return /^U\+[0-9A-F]{4,}$/.test(OL.hex(cp)); },
  [[0x09], [0x7e], [0xff], [0x1000], [0x1d400], [0x10ffff]]);

/* Build a string from the corpus codepoints for analyze/toAscii coverage + round-trip. */
function fromCps(cps) {
  return cps.map(function (cp) { try { return String.fromCodePoint(cp); } catch (e) { return ''; } }).join('');
}
const CORPUS_STRINGS = [
  [''],
  [fromCps(CP_CORPUS)],                              // every class in one string
  ['plain ascii only, no flags'],                    // all-safe (run accumulation + final flush)
  [fromCps([0x41, 0x0430, 0x42])],                   // safe-flag-safe (run flush mid-string)
  [fromCps([0x0430, 0x0430])],                       // repeated flag (counts increment)
];

/* analyze(str): items partition the input losslessly; flagged == sum(counts) == # flagged items. */
fuzz('analyze: lossless partition, flagged count consistent',
  fc.string({ maxLength: 64 }),
  function (str) {
    const r = OL.analyze(str);
    let rebuilt = '';
    let flaggedItems = 0;
    for (const it of r.items) {
      if ('safe' in it) { rebuilt += it.safe; }
      else { rebuilt += it.ch; flaggedItems += 1; }
    }
    if (rebuilt !== String(str)) { return false; }
    if (flaggedItems !== r.flagged) { return false; }
    let sum = 0;
    for (const k of Object.keys(r.counts)) { sum += r.counts[k]; }
    return sum === r.flagged;
  },
  CORPUS_STRINGS);

/* toAscii(str): output contains only classify===null codepoints; idempotent; never throws. */
fuzz('toAscii: strips every flagged codepoint, idempotent',
  fc.string({ maxLength: 64 }),
  function (str) {
    const out = OL.toAscii(str);
    for (const ch of Array.from(out)) { if (OL.classify(ch.codePointAt(0)) !== null) { return false; } }
    return OL.toAscii(out) === out;
  },
  CORPUS_STRINGS);

/* Contract of the `str == null ? '' : String(str)` guard: null/undefined are treated as the empty
   string (flagged 0, nothing reconstructed), and any other input is String()-coerced then analyzed.
   The documented inputs are string|null|undefined (callers pass input.value / sessionStorage), so
   the arb covers those plus the primitive coercions (number/boolean) and a plain object -- all
   reliably String-coercible. A pathological object whose `toString`/`valueOf` are overridden to
   non-callables (e.g. {toString: []}) makes String() itself throw; that is outside the guard's
   contract and unreachable from any caller, so it is deliberately not generated here. */
fuzz('analyze/toAscii: documented non-string inputs coerce without throwing',
  fc.oneof(fc.constant(null), fc.constant(undefined), fc.integer(), fc.double(), fc.boolean(),
    fc.constant({}), fc.constant([1, 2])),
  function (x) {
    const r = OL.analyze(x);
    if (!Array.isArray(r.items) || typeof r.flagged !== 'number') { return false; }
    if (typeof OL.toAscii(x) !== 'string') { return false; }
    if (x == null) {               // the `str == null ? ''` arm: treated as empty -> nothing flagged
      return r.flagged === 0;
    }
    return true;
  },
  [[null], [undefined], [0], [{}], [true]]);
