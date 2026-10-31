'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* Property/fuzz tests for output-lies' analyze/ui.js -- the x-ray tool page wiring (render,
   sample buttons, copy-ASCII, sessionStorage preload). It reads the shared analyzer as window.OL;
   the real analyzer is injected. Curated DOM configs drive every branch to deterministic 100% c8;
   fuzz invariants assert the attacker-facing properties: a prototype-name data-k
   (js-object-map-prototype-pollution) never throws and leaves input.value a string, the rendered
   chip count always matches OL.analyze().flagged, and copy-ASCII only ever writes codepoints the
   classifier deems safe. */

const { fc, test, sitePath } = require('./fuzz-harness.js');
const { loadScript } = require('./harness.js');

const JS = sitePath('output-lies.github.io', 'analyze/ui.js');
if (!require('node:fs').existsSync(JS)) { return; }   // skip when this site is absent (partial checkout)
const ANALYZER = sitePath('output-lies.github.io', 'analyze/analyzer.js');
const OL = require(ANALYZER);
const withOL = function (w) { w.OL = OL; };
const tick = function () { return new Promise(function (r) { setImmediate(r); }); };

const DOM =
  '<textarea id="in"></textarea><div id="out"></div><div id="verdict"></div><div id="tallies"></div>'
  + '<div id="samples"><button data-k="homoglyph">h</button><button data-k="bogus">b</button>'
  + '<span id="notbtn">x</span></div>'
  + '<button id="copyascii">copy</button><div id="copymsg"></div>';
const DOM_NOCOPY =
  '<textarea id="in"></textarea><div id="out"></div><div id="verdict"></div><div id="tallies"></div>'
  + '<div id="samples"></div>';

/* --- coverage: every branch, deterministic (reuses the proven jscov DOM configs) --- */

test('ui: render empty/clean/dirty, samples hit+miss+non-button, copy resolve', async function () {
  const r = loadScript(JS, DOM, { setup: withOL });   // render() at load: '' -> if(!str) arm
  const d = r.win.document;
  const input = d.getElementById('in');

  input.value = 'git commit -m ok';                               // clean ASCII -> flagged===0 arm
  input.dispatchEvent(new r.win.Event('input'));
  if (d.getElementById('verdict').textContent.indexOf('Clean') < 0) { throw new Error('clean verdict'); }

  input.value = 'a' + String.fromCodePoint(0x0430, 0x200B) + 'b'; // homoglyph (visible chip) + zw (invisible)
  input.dispatchEvent(new r.win.Event('input'));
  if (d.getElementById('verdict').textContent.indexOf('suspicious') < 0) { throw new Error('dirty verdict'); }
  if (d.getElementById('tallies').textContent.indexOf('Breakdown') < 0) { throw new Error('breakdown'); }

  d.querySelector('[data-k=homoglyph]').click();                  // SAMPLES hit
  if (input.value.indexOf('ex') < 0) { throw new Error('sample not loaded'); }
  d.querySelector('[data-k=bogus]').click();                      // SAMPLES miss -> ''
  if (input.value !== '') { throw new Error('unknown sample should clear'); }
  d.getElementById('notbtn').click();                             // closest('button') null -> if(!btn) return

  input.value = 'x' + String.fromCodePoint(0x0430);
  input.dispatchEvent(new r.win.Event('input'));
  d.getElementById('copyascii').click();                          // clipboard resolve -> ok()
  await tick();
  if (r.copied[0] !== 'x') { throw new Error('copy wrote wrong value: ' + JSON.stringify(r.copied)); }
});

test('ui: copy clipboard reject -> strips in place', async function () {
  const r = loadScript(JS, DOM, {
    setup: function (w) { withOL(w); w.navigator.clipboard.writeText = function () { return Promise.reject(new Error('x')); }; },
  });
  const input = r.win.document.getElementById('in');
  input.value = 'y' + String.fromCodePoint(0x0435);
  input.dispatchEvent(new r.win.Event('input'));
  r.win.document.getElementById('copyascii').click();
  await tick();
  if (input.value !== 'y') { throw new Error('reject should strip in place'); }
});

test('ui: copy without clipboard -> strips in place (else)', function () {
  const r = loadScript(JS, DOM, { clipboard: false, setup: withOL });
  const input = r.win.document.getElementById('in');
  input.value = 'z' + String.fromCodePoint(0x0441);
  input.dispatchEvent(new r.win.Event('input'));
  r.win.document.getElementById('copyascii').click();
  if (input.value !== 'z') { throw new Error('no clipboard should strip in place'); }
});

test('ui: no #copyascii -> if(copyBtn) false arm', function () {
  loadScript(JS, DOM_NOCOPY, { setup: withOL });
});

test('ui: sessionStorage preload (pre !== null)', function () {
  const r = loadScript(JS, DOM, { setup: function (w) { withOL(w); w.sessionStorage.setItem('ol-xray-input', 'preloaded'); } });
  if (r.win.document.getElementById('in').value !== 'preloaded') { throw new Error('preload not applied'); }
});

test('ui: sessionStorage getItem throws -> catch swallows', function () {
  const r = loadScript(JS, DOM, {
    setup: function (w) {
      withOL(w);
      Object.defineProperty(w, 'sessionStorage', { configurable: true, value: { getItem: function () { throw new Error('unavailable'); } } });
    },
  });
  if (!r.win.document.getElementById('in')) { throw new Error('should load despite throw'); }
});

test('ui: classifier cls not in CLSMAP -> chip m-other fallback', function () {
  /* Stub OL yielding an item with a cls absent from CLSMAP -> chip()'s `|| 'm-other'` (dead with
     the real classifier). render() runs the items loop at load before the if(!str) return. */
  loadScript(JS, DOM, {
    setup: function (w) {
      w.OL = {
        analyze: function () { return { items: [{ ch: '?', cp: 0x3F, info: { cls: 'bogus', name: 'x', visible: false } }], flagged: 1, counts: { x: 1 } }; },
        hex: function () { return 'U+003F'; },
        toAscii: function (s) { return s; },
      };
    },
  });
});

/* --- invariants --- */

/* A prototype-name data-k (SAMPLES[k] is inherited-truthy) must not throw and must leave
   input.value a string -- the `|| ''` + assignment coerce any lookup to text; render() then runs
   on it. The key is applied with setAttribute (no HTML-attribute parsing) and the samples handler
   reads it at click time. Seeds the pollution keys explicitly (a corpus without a prototype-name
   token would stay green while the map silently disagreed). NOTE: tests attribute VALUES, not a
   POLLUTED Object.prototype value (ui.js reads SAMPLES[k] without a hasOwnProperty guard) -- a
   source-side concern tracked outside this lane. */
test('ui: any sample data-k keeps input.value a string, never throws', function () {
  fc.assert(fc.property(
    fc.oneof(
      fc.constantFrom('homoglyph', 'zerowidth', 'bidi', 'ascii', 'space', 'combining', 'clean', 'clear'),
      fc.constantFrom('__proto__', 'constructor', 'prototype', 'hasOwnProperty', 'toString', 'valueOf'),
      fc.string({ maxLength: 16 }),
    ),
    function (k) {
      const r = loadScript(JS, '<textarea id="in"></textarea><div id="out"></div><div id="verdict"></div>'
        + '<div id="tallies"></div><div id="samples"><button>s</button></div>', { setup: withOL });
      const btn = r.win.document.querySelector('button');
      btn.setAttribute('data-k', k);                  // DOM API: no HTML-attribute parsing of the fuzzed value
      btn.click();
      return typeof r.win.document.getElementById('in').value === 'string';
    },
  ), { seed: 1, numRuns: 40 });
});

/* For ANY input string, render() never throws, injects no markup (chips are built with
   createElement/textContent -- out must contain no element whose tag came from the input), and the
   flagged-chip count equals OL.analyze(str).flagged. */
test('ui: render is injection-safe and chip count matches analyzer', function () {
  const { adversarialString } = require('./fuzz-harness.js');
  fc.assert(fc.property(adversarialString, function (str) {
    const r = loadScript(JS, DOM, { setup: withOL });
    const d = r.win.document;
    const input = d.getElementById('in');
    input.value = str;
    input.dispatchEvent(new r.win.Event('input'));
    const out = d.getElementById('out');
    /* EVERY rendered element is a <span> (render builds .safe / .mark / .g spans via
       createElement + textContent); an innerHTML regression injecting any other tag from the input
       fails here -- counting .mark alone would miss injected non-.mark markup. */
    for (const el of Array.from(out.querySelectorAll('*'))) { if (el.tagName !== 'SPAN') { return false; } }
    return out.querySelectorAll('.mark').length === OL.analyze(str).flagged;
  }), { seed: 1, numRuns: 60 });
});

/* The copy-ASCII guarantee: for ANY input, the text written to the clipboard contains only
   codepoints the classifier deems safe (classify === null) -- never a hidden/confusable codepoint. */
test('ui: copy-ASCII writes only classifier-safe codepoints', async function () {
  const { adversarialString } = require('./fuzz-harness.js');
  await fc.assert(fc.asyncProperty(adversarialString, async function (str) {
    const r = loadScript(JS, DOM, { setup: withOL });
    const input = r.win.document.getElementById('in');
    input.value = str;
    input.dispatchEvent(new r.win.Event('input'));
    r.win.document.getElementById('copyascii').click();
    await tick();
    const written = r.copied.length ? r.copied[r.copied.length - 1] : '';
    for (const ch of Array.from(written)) { if (OL.classify(ch.codePointAt(0)) !== null) { return false; } }
    return true;
  }), { seed: 1, numRuns: 40 });
});
