'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* Property/fuzz tests for output-lies' analyze/sandbox.js -- the build-a-trap forge + safe-paste
   sandbox. It reads the shared analyzer as window.OL; the REAL analyzer is injected via require()
   (withOL), exactly as the exemplar ui.fuzz.js does. Curated DOM configs (the jscov branch set)
   drive every branch to deterministic 100% c8; the fuzz invariants assert the attacker-facing
   properties: for ANY input the forge/safe renders are injection-safe (built with
   createElement/textContent -- every rendered node is a <span>, never markup from the input), the
   rendered chip count matches OL.analyze().flagged, the verdict's hidden-codepoint count matches
   the rendered chips, and the safe-paste output equals OL.toAscii() and carries only
   classifier-safe codepoints. */

const { fc, test, sitePath, adversarialString } = require('./fuzz-harness.js');
const { loadScript } = require('./harness.js');

const JS = sitePath('output-lies.github.io', 'analyze/sandbox.js');
const ANALYZER = sitePath('output-lies.github.io', 'analyze/analyzer.js');
const OL = require(ANALYZER);
const withOL = function (w) { w.OL = OL; };
const tick = function () { return new Promise(function (r) { setImmediate(r); }); };

/* Full page skeleton sandbox.js assumes (it has no missing-element guards). #in is optional
   (used by the bt-send / sb-send handlers). Mirrors the jscov sandbox.test.js DOM. */
function dom(opts) {
  opts = opts || {};
  return ''
    + '<input id="bt-in" value="' + (opts.btIn === undefined ? 'hello' : opts.btIn) + '">'
    + '<div id="bt-out"></div><div id="bt-verdict"></div><div id="bt-msg"></div>'
    + '<button id="bt-go">go</button>'
    + '<input type="radio" name="bt-mode" value="homoglyph">'
    + '<input type="radio" name="bt-mode" value="zerowidth">'
    + '<input type="radio" name="bt-mode" value="bidi">'
    + '<button id="bt-copy">copy</button><button id="bt-send">send</button>'
    + '<input id="sb-in" value="' + (opts.sbIn === undefined ? 'abc' : opts.sbIn) + '">'
    + '<div id="sb-raw"></div><div id="sb-safe"></div><div id="sb-tallies"></div>'
    + '<div id="sb-hint"></div><div id="sb-live"></div><div id="sb-msg"></div>'
    + '<button id="sb-copy-in">ci</button><button id="sb-copy-safe">cs</button>'
    + '<button id="sb-send">ss</button>'
    + (opts.withIn === false ? '' : '<input id="in">');
}

/* Every element a renderInto() / forge render may produce is a <span> (safe run, .mark chip, and
   the inner .g glyph span); the ' ' + hex detail is a text node. So any non-SPAN element under a
   render target would be markup injected from the input -- the property this asserts never holds. */
function allSpans(el) {
  const nodes = el.querySelectorAll('*');
  for (let i = 0; i < nodes.length; i++) { if (nodes[i].tagName !== 'SPAN') { return false; } }
  return true;
}

/* --- coverage: every branch, deterministic (reuses the proven jscov DOM configs) --- */

test('sandbox: OL undefined -> early return', function () {
  loadScript(JS, dom(), {});   // no OL injected -> `if (typeof OL === 'undefined') return`
});

test('sandbox: unknown classifier class -> CLSMAP fallback to m-other', function () {
  /* Stub OL whose analyze yields a cls NOT in CLSMAP -> the `|| 'm-other'` arm (dead with the real
     classifier, which only emits the 8 mapped classes). visible:true also exercises the glyph arm.
     renderInto runs at load. */
  loadScript(JS, dom(), {
    setup: function (w) {
      w.OL = {
        analyze: function () {
          return { items: [{ ch: '?', cp: 0x3F, info: { cls: 'bogus', name: 'x', visible: true } }],
            flagged: 1, counts: { x: 1 } };
        },
        hex: function () { return 'U+003F'; },
        toAscii: function (s) { return s; },
      };
    },
  });
});

test('sandbox: full drive -- forge modes, render, bt-copy proceed, bt-send, sb panel', async function () {
  const { win } = loadScript(JS, dom(), { setup: withOL });
  const d = win.document;

  // At load btRun ran with no radio checked -> 'homoglyph' default on 'hello' (flagged -> dirty).
  if (d.getElementById('bt-verdict').textContent.indexOf('Forged') < 0) { throw new Error('forged verdict'); }

  // zerowidth mode via radio change (picked truthy; 2nd ternary arm)
  const zw = d.querySelector('input[value=zerowidth]');
  zw.checked = true; zw.dispatchEvent(new win.Event('change'));
  // bidi mode (3rd ternary arm)
  const bd = d.querySelector('input[value=bidi]');
  bd.checked = true; bd.dispatchEvent(new win.Event('change'));
  // back to homoglyph
  const hg = d.querySelector('input[value=homoglyph]');
  hg.checked = true; hg.dispatchEvent(new win.Event('change'));

  // bt-copy: forged present + clipboard present -> writeText.then -> flash (syncTimers clears it)
  d.getElementById('bt-copy').click();
  await tick();
  if (d.getElementById('bt-msg').textContent !== '') { throw new Error('flash not cleared'); }

  // bt-send: #in present + forged present -> set value, dispatch input, hash
  d.getElementById('bt-send').click();
  if (!(d.getElementById('in').value.length > 0)) { throw new Error('bt-send did not set #in'); }

  // sb panel: 2 unsafe -> plural 's'
  const sbIn = d.getElementById('sb-in');
  sbIn.value = 'a' + String.fromCodePoint(0x0430, 0x200B) + 'b';
  sbIn.dispatchEvent(new win.Event('input'));
  if (d.getElementById('sb-tallies').textContent.indexOf('refused') < 0) { throw new Error('plural tally'); }
  // exactly 1 unsafe -> singular (stripped === 1)
  sbIn.value = 'a' + String.fromCodePoint(0x0430);
  sbIn.dispatchEvent(new win.Event('input'));
  if (d.getElementById('sb-tallies').textContent.indexOf('1 unsafe codepoint ') < 0) { throw new Error('singular tally'); }

  // sb-copy-in + sb-copy-safe with value -> sbCopy resolve
  d.getElementById('sb-copy-in').click();
  d.getElementById('sb-copy-safe').click();
  await tick();
  // sb-send with #in + value
  d.getElementById('sb-send').click();
});

test('sandbox: forge no-change branch + single-flag pluralization', function () {
  // bt-in empty -> forgeHomoglyph('') = '' -> flagged 0 -> "No change" branch.
  const { win } = loadScript(JS, dom({ btIn: '' }), { setup: withOL });
  if (win.document.getElementById('bt-verdict').textContent.indexOf('No change') < 0) { throw new Error('no-change'); }
  // single homoglyph -> flagged === 1 (singular "codepoint")
  const { win: w2 } = loadScript(JS, dom({ btIn: 'a' }), { setup: withOL });
  if (w2.document.getElementById('bt-verdict').textContent.indexOf('1 hidden codepoint.') < 0) { throw new Error('singular codepoint'); }
});

test('sandbox: zerowidth + bidi forge edge inputs (no-match regex, no-\\S bidi)', function () {
  // zerowidth on a <3-alnum input: regex no match -> unchanged; bidi on empty: loop finds no \\S.
  const { win } = loadScript(JS, dom({ btIn: 'ab' }), { setup: withOL });
  const d = win.document;
  const zw = d.querySelector('input[value=zerowidth]');
  zw.checked = true; zw.dispatchEvent(new win.Event('change'));   // 'ab' -> no 3-alnum match
  const bd = d.querySelector('input[value=bidi]');
  d.getElementById('bt-in').value = '';                           // forgeBidi('') -> parts [''], no \S
  bd.checked = true; bd.dispatchEvent(new win.Event('change'));
});

test('sandbox: bt-copy no-op when forged empty (1st || operand)', function () {
  const { win } = loadScript(JS, dom({ btIn: '' }), { setup: withOL });
  win.document.getElementById('bt-copy').click();   // forged '' -> return
});

test('sandbox: clipboard absent -- bt-copy 2nd operand, sbCopy unavailable', function () {
  const { win } = loadScript(JS, dom(), {
    clipboard: false,
    syncTimers: false,
    setup: function (w) { withOL(w); w.setTimeout = function () { return 7; }; },   // keep flash visible
  });
  const d = win.document;
  d.getElementById('bt-copy').click();              // !navigator.clipboard -> return
  d.getElementById('sb-copy-in').click();           // sbCopy -> else -> 'clipboard unavailable'
  if (d.getElementById('sb-msg').textContent.indexOf('unavailable') < 0) { throw new Error('unavailable msg'); }
});

test('sandbox: clipboard without writeText -- bt-copy 3rd operand', function () {
  const { win } = loadScript(JS, dom(), {
    setup: function (w) { withOL(w); w.navigator.clipboard = {}; },
  });
  win.document.getElementById('bt-copy').click();   // !navigator.clipboard.writeText -> return
});

test('sandbox: sbCopy reject -> clipboard blocked', async function () {
  const { win } = loadScript(JS, dom(), {
    syncTimers: false,
    setup: function (w) {
      withOL(w);
      w.setTimeout = function () { return 7; };      // keep flash visible
      w.navigator.clipboard.writeText = function () { return Promise.reject(new Error('x')); };
    },
  });
  win.document.getElementById('sb-copy-in').click();
  await tick();
  if (win.document.getElementById('sb-msg').textContent.indexOf('blocked') < 0) { throw new Error('blocked msg'); }
});

test('sandbox: no #in -- bt-send / sb-send if-x false; empty sb-in resets live', function () {
  const { win } = loadScript(JS, dom({ withIn: false, sbIn: '' }), { setup: withOL });
  const d = win.document;
  d.getElementById('bt-send').click();              // x null -> if(x && forged) false
  d.getElementById('sb-send').click();              // x null
  // sb-in empty at load -> sbRun !str branch (sbLive hidden, sbHint shown)
  if (d.getElementById('sb-live').hidden !== true) { throw new Error('empty sb-in should hide live'); }
  // empty sb-copy-in/safe: if(sbIn.value) false
  d.getElementById('sb-copy-in').click();
  d.getElementById('sb-copy-safe').click();
});

/* --- invariants (real analyzer; DOM rebuilt per run) --- */

/* Safe-paste panel: for ANY input, renderInto(sb-raw) injects no markup (every element is a
   <span>), the visible chip count equals OL.analyze().flagged, the kept text equals OL.toAscii(),
   and that kept text carries only classifier-safe codepoints. Expectations are derived from the
   value the module actually reads back (sbIn.value) -- an <input>, unlike the exemplar's textarea,
   strips CR/LF from its value, so the field's content can differ from the raw string. sb-in starts
   empty so the load-time render leaves a clean baseline. */
test('sandbox: safe-paste render is injection-safe and matches the analyzer', function () {
  fc.assert(fc.property(adversarialString, function (str) {
    const r = loadScript(JS, dom({ sbIn: '', btIn: '' }), { setup: withOL });
    const d = r.win.document;
    const sbIn = d.getElementById('sb-in');
    sbIn.value = str;
    sbIn.dispatchEvent(new r.win.Event('input'));
    const seen = sbIn.value;   // post input-sanitization value the module operated on
    const raw = d.getElementById('sb-raw');
    if (!allSpans(raw)) { return false; }
    if (raw.querySelectorAll('.mark').length !== OL.analyze(seen).flagged) { return false; }
    const safe = d.getElementById('sb-safe').textContent;
    if (safe !== OL.toAscii(seen)) { return false; }
    for (const ch of Array.from(safe)) { if (OL.classify(ch.codePointAt(0)) !== null) { return false; } }
    return true;
  }), { seed: 1, numRuns: 50 });
});

/* Build-a-trap forge: for ANY input, forging (homoglyph mode) then rendering into bt-out injects no
   markup (every element a <span>), and the verdict's reported hidden-codepoint count is exactly the
   number of rendered chips -- the forge never under/over-reports what it produced. */
test('sandbox: forge render is injection-safe and the verdict count matches the chips', function () {
  fc.assert(fc.property(adversarialString, function (str) {
    const r = loadScript(JS, dom({ btIn: '', sbIn: '' }), { setup: withOL });
    const d = r.win.document;
    d.getElementById('bt-in').value = str;
    d.querySelector('input[value=homoglyph]').checked = true;
    d.getElementById('bt-go').click();
    const out = d.getElementById('bt-out');
    if (!allSpans(out)) { return false; }
    const chips = out.querySelectorAll('.mark').length;
    const verdict = d.getElementById('bt-verdict').textContent;
    const m = verdict.match(/carries (\d+) hidden codepoint/);
    const reported = m ? Number(m[1]) : 0;   // "No change" (flagged 0) has no number
    return reported === chips;
  }), { seed: 1, numRuns: 50 });
});
