'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* Property/fuzz tests for secure-terminal's chat-view/mockup.js -- the non-functional chat-view
   demo wiring (theme/state/block-style toggles, session-row select, sidebar collapse, the unicode
   setting-chip display-mode cycle). Nothing here touches a shell, so the invariants are about the
   widget's own state machine: aria-pressed is always the exact boolean-string 'true'/'false' with
   exactly one pressed per group, exactly one session row is ever .active, and the unicode chip's
   data-umode only ever lands on one of its four declared modes. Curated DOM configs drive every
   branch to deterministic 100% c8. */

const { fc, test, sitePath } = require('./fuzz-harness.js');
const { loadScript } = require('./harness.js');

const JS = sitePath('secure-terminal.github.io', 'chat-view/mockup.js');
if (!require('node:fs').existsSync(JS)) { return; }   // skip when this site is absent (partial checkout)

const FULL =
  '<div id="app"><div id="chat"></div>'
  + '<button data-theme-btn="dark">d</button><button data-theme-btn="light">l</button>'
  + '<button data-state-btn="run">r</button><button data-state-btn="idle">i</button>'
  + '<button data-bs-btn="bubble">b</button><button data-bs-btn="plain">p</button>'
  + '<div id="sessions"><div class="srow">a</div><div class="srow">b</div><div class="srow">c</div></div>'
  + '<button id="collapsebtn" title="Collapse sidebar">c</button>'
  + '<span class="chip set">unicode <b>Show</b></span>'
  + '<span class="chip set">other</span>'
  + '<span id="umcap"></span>'
  + '</div>';

const UMODES = ['box', 'show', 'reveal', 'detail'];

/* --- coverage: every branch, deterministic (mirrors the jscov DOM configs) --- */

test('mockup: full wiring -- toggles, session select, collapse, unicode chip cycle', function () {
  const r = loadScript(JS, FULL, {});
  const d = r.win.document;

  d.querySelector('[data-theme-btn=dark]').click();
  if (d.documentElement.getAttribute('data-theme') !== 'dark') { throw new Error('theme not applied'); }
  if (d.querySelector('[data-theme-btn=dark]').getAttribute('aria-pressed') !== 'true') { throw new Error('clicked btn not pressed'); }
  if (d.querySelector('[data-theme-btn=light]').getAttribute('aria-pressed') !== 'false') { throw new Error('sibling btn still pressed'); }

  d.querySelector('[data-state-btn=run]').click();
  if (d.getElementById('app').getAttribute('data-state') !== 'run') { throw new Error('state not applied'); }
  d.querySelector('[data-bs-btn=bubble]').click();
  if (d.getElementById('chat').getAttribute('data-blockstyle') !== 'bubble') { throw new Error('blockstyle not applied'); }

  const rows = d.querySelectorAll('#sessions .srow');
  rows[0].click();
  rows[1].click();
  if (!rows[1].classList.contains('active') || rows[0].classList.contains('active')) { throw new Error('session-row select wrong'); }

  const cb = d.getElementById('collapsebtn');
  cb.click();
  if (cb.title !== 'Expand sidebar') { throw new Error('collapse toggle title wrong'); }
  cb.click();
  if (cb.title !== 'Collapse sidebar') { throw new Error('expand toggle title wrong'); }

  const chip = d.querySelector('.chip.set');   // the 'unicode' one (regex-matched, has <b> + #umcap)
  chip.click();                                 // data-umode absent -> ||'show'; next = 'reveal'
  if (d.getElementById('chat').getAttribute('data-umode') !== 'reveal') { throw new Error('umode not advanced'); }
  if (chip.querySelector('b').textContent !== 'Reveal') { throw new Error('chip label not updated'); }
  if (d.getElementById('umcap').textContent !== 'Reveal') { throw new Error('umcap not updated'); }
  chip.click();                                 // data-umode present now -> truthy side of ||'show'
});

test('mockup: unicode chip without <b> and without #umcap -- if-absent branches', function () {
  const r = loadScript(JS,
    '<div id="app"><div id="chat"></div><span class="chip set">unicode</span></div>', {});
  r.win.document.querySelector('.chip.set').click();   // b null + cap null -> both if-absent arms
});

test('mockup: no collapsebtn and no #chat -- if(cb) false + final scroll catch', function () {
  loadScript(JS, '<div id="app"></div>', {});          // chat null -> chat.scrollTop throws -> catch
});

/* --- invariants --- */

/* For ANY sequence of theme-button clicks, every [data-theme-btn] carries aria-pressed that is
   EXACTLY 'true' or 'false' (never missing/other), and exactly ONE button -- the last clicked --
   is pressed. This is the press() state machine's guarantee (single-select radio behaviour). */
test('mockup: theme group is always a valid single-select (aria-pressed true/false, one pressed)', function () {
  const themes = ['dark', 'light', 'sepia', 'auto'];
  fc.assert(fc.property(
    fc.array(fc.integer({ min: 0, max: 3 }), { minLength: 1, maxLength: 20 }),
    function (clicks) {
      let body = '<div id="app"><div id="chat"></div>';
      themes.forEach(function (t) { body += '<button data-theme-btn="' + t + '">' + t + '</button>'; });
      body += '</div>';
      const r = loadScript(JS, body, {});
      const d = r.win.document;
      const btns = Array.prototype.slice.call(d.querySelectorAll('[data-theme-btn]'));
      let last = 0;
      clicks.forEach(function (i) { btns[i].click(); last = i; });
      let pressed = 0;
      for (const b of btns) {
        const v = b.getAttribute('aria-pressed');
        if (v !== 'true' && v !== 'false') { return false; }     // only the two boolean strings
        if (v === 'true') { pressed += 1; }
      }
      if (pressed !== 1) { return false; }                       // exactly one selected
      return btns[last].getAttribute('aria-pressed') === 'true';  // and it is the last clicked
    },
  ), { seed: 1, numRuns: 50 });
});

/* For ANY sequence of session-row clicks, exactly one row is ever .active (the last clicked) --
   the handler clears all then adds one. */
test('mockup: session rows keep exactly one .active (the last clicked)', function () {
  fc.assert(fc.property(
    fc.array(fc.integer({ min: 0, max: 4 }), { minLength: 1, maxLength: 20 }),
    function (clicks) {
      let rows = '';
      for (let i = 0; i < 5; i += 1) { rows += '<div class="srow">r' + i + '</div>'; }
      const r = loadScript(JS, '<div id="app"><div id="chat"></div><div id="sessions">' + rows + '</div></div>', {});
      const d = r.win.document;
      const els = Array.prototype.slice.call(d.querySelectorAll('#sessions .srow'));
      let last = 0;
      clicks.forEach(function (i) { els[i].click(); last = i; });
      let active = 0;
      els.forEach(function (e) { if (e.classList.contains('active')) { active += 1; } });
      return active === 1 && els[last].classList.contains('active');
    },
  ), { seed: 1, numRuns: 50 });
});

/* For ANY number of unicode-chip clicks, chat's data-umode is always one of the four declared
   modes -- nx is drawn from umodes by modular index, so it can never land off the cycle, and the
   chip <b> label always matches the active mode. Non-vacuous: an off-by-one or non-modular index
   would produce undefined. */
test('mockup: unicode chip data-umode always stays within the declared mode set', function () {
  fc.assert(fc.property(
    fc.integer({ min: 1, max: 30 }),
    function (n) {
      const r = loadScript(JS,
        '<div id="app"><div id="chat"></div><span class="chip set">unicode <b>Show</b></span></div>', {});
      const d = r.win.document;
      const chip = d.querySelector('.chip.set');
      const labels = { box: 'Box', show: 'Show', reveal: 'Reveal', detail: 'Detail' };
      for (let i = 0; i < n; i += 1) {
        chip.click();
        const mode = d.getElementById('chat').getAttribute('data-umode');
        if (UMODES.indexOf(mode) === -1) { return false; }           // always a declared mode
        if (chip.querySelector('b').textContent !== labels[mode]) { return false; }  // label matches
      }
      return true;
    },
  ), { seed: 1, numRuns: 40 });
});
