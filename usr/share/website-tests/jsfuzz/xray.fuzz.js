'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* Property/fuzz tests for output-lies' terminal/xray.js -- the live board x-ray. It reads the
   shared analyzer as window.OL; the REAL analyzer is injected via require() (withOL), exactly as
   the exemplar ui.fuzz.js does. Curated DOM configs (the jscov branch set) drive every branch to
   deterministic 100% c8. The invariants assert the module's stated security guarantee: it renders
   via DOM text nodes only (never innerHTML), so even when the analyzer returns attacker-controlled
   strings the board contains no injected markup (every rendered element is a <span>); and, with the
   real analyzer, the summary total equals the number of hex chips actually rendered. */

const { fc, test, sitePath, adversarialString } = require('./fuzz-harness.js');
const { loadScript } = require('./harness.js');

const JS = sitePath('output-lies.github.io', 'terminal/xray.js');
if (!require('node:fs').existsSync(JS)) { return; }   // skip when this site is absent (partial checkout)
const ANALYZER = sitePath('output-lies.github.io', 'analyze/analyzer.js');
const withOL = function (w) { w.OL = require(ANALYZER); };

/* xray.js only ever document.createElement('span') (the .dim labels, the .cp chips, the summary);
   every other node it adds is a text node. So any non-SPAN element under #board-xray would be
   markup injected from analyzer output -- the property the injection-safety invariant forbids. */
function allSpans(el) {
  const nodes = el.querySelectorAll('*');
  for (let i = 0; i < nodes.length; i++) { if (nodes[i].tagName !== 'SPAN') { return false; } }
  return true;
}

/* --- coverage: every branch, deterministic (reuses the proven jscov DOM configs) --- */

test('xray: OL undefined -> early return', function () {
  loadScript(JS, '<div id="board-xray"></div>', {});   // no OL injected
});

test('xray: #board-xray missing -> early return', function () {
  loadScript(JS, '<div></div>', { setup: withOL });
});

test('xray: full render walks every row (ASCII, flagged, honest) and totals', function () {
  const { win } = loadScript(JS, '<div id="board-xray"></div>', { setup: withOL });
  const box = win.document.getElementById('board-xray');
  if (box.textContent.indexOf('hidden or disguised codepoints revealed') < 0) { throw new Error('summary missing'); }
  if (box.textContent.indexOf('NOT an attack') < 0) { throw new Error('honest row missing'); }
});

/* --- invariants --- */

/* Injection safety for arbitrary analyzer output: a stub OL whose analyze() returns
   attacker-controlled strings (a safe run + a flagged item with adversarial ch/name/cls) and whose
   hex() returns an adversarial string. However hostile that text, xray places it only via
   textContent / createTextNode / the .title property, so the board can contain no element other
   than the <span>s xray itself creates -- no <img>/<script>/<iframe>/etc. injected from the input. */
test('xray: renders injection-safe for arbitrary analyzer output', function () {
  fc.assert(fc.property(adversarialString, adversarialString, function (advText, advHex) {
    const stub = function (w) {
      w.OL = {
        analyze: function () {
          return {
            items: [
              { safe: advText },
              { ch: advText, cp: 0x3F, info: { cls: advText, name: advText } },
            ],
            flagged: 1,
            counts: {},
          };
        },
        hex: function () { return advHex; },
      };
    };
    const { win } = loadScript(JS, '<div id="board-xray"></div>', { setup: stub });
    const box = win.document.getElementById('board-xray');
    if (box.querySelectorAll('img, script, iframe, a, svg, style, link, object, embed').length !== 0) { return false; }
    return allSpans(box);
  }), { seed: 1, numRuns: 50 });
});

/* With the REAL analyzer, the summary total is not decorative: it equals the number of hex chips
   (`[U+XXXX]`) actually rendered on the board, and the board has at least one (it ships known
   attacks). Also re-confirms every element is a <span> under the real classifier. */
test('xray: summary total equals the hex chips rendered (real analyzer)', function () {
  const { win } = loadScript(JS, '<div id="board-xray"></div>', { setup: withOL });
  const box = win.document.getElementById('board-xray');
  const cps = Array.prototype.slice.call(box.querySelectorAll('.cp'));
  let hexChips = 0;
  let total = null;
  cps.forEach(function (c) {
    const t = c.textContent;
    if (/^\[U\+[0-9A-F]{4,}\]$/.test(t)) { hexChips += 1; return; }
    const m = t.match(/^-> (\d+) hidden or disguised codepoints revealed$/);
    if (m) { total = Number(m[1]); }
  });
  if (total === null) { throw new Error('summary line not found'); }
  if (total !== hexChips) { throw new Error('summary total ' + total + ' != hex chips ' + hexChips); }
  if (!(hexChips >= 1)) { throw new Error('board rendered no hex chips'); }
  if (!allSpans(box)) { throw new Error('non-span element injected'); }
});
