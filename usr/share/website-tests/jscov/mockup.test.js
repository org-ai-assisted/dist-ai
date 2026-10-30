'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* 100% coverage of secure-terminal's chat-view/mockup.js -- the non-functional demo wiring
   (theme/state/block-style toggles, session-row select, collapse, unicode chip cycle). */
const { test } = require('node:test');
const assert = require('node:assert');
const { loadScript, sitePath } = require('./harness.js');

const JS = sitePath('secure-terminal.github.io', 'chat-view/mockup.js');
if (!require('node:fs').existsSync(JS)) { return; }   // skip when this site is absent (partial checkout)

const FULL =
  '<div id="app"><div id="chat"></div>'
  + '<button data-theme-btn="dark">d</button><button data-theme-btn="light">l</button>'
  + '<button data-state-btn="run">r</button>'
  + '<button data-bs-btn="bubble">b</button>'
  + '<div id="sessions"><div class="srow">a</div><div class="srow">b</div></div>'
  + '<button id="collapsebtn" title="Collapse sidebar">c</button>'
  + '<span class="chip set">unicode <b>Show</b></span>'
  + '<span class="chip set">other</span>'
  + '<span id="umcap"></span>'
  + '</div>';

test('full wiring: toggles, session select, collapse, unicode chip', function () {
  const { win } = loadScript(JS, FULL, {});
  const d = win.document;

  d.querySelector('[data-theme-btn=dark]').click();
  assert.strictEqual(d.documentElement.getAttribute('data-theme'), 'dark');
  assert.strictEqual(d.querySelector('[data-theme-btn=dark]').getAttribute('aria-pressed'), 'true');
  assert.strictEqual(d.querySelector('[data-theme-btn=light]').getAttribute('aria-pressed'), 'false');

  d.querySelector('[data-state-btn=run]').click();
  assert.strictEqual(d.getElementById('app').getAttribute('data-state'), 'run');
  d.querySelector('[data-bs-btn=bubble]').click();
  assert.strictEqual(d.getElementById('chat').getAttribute('data-blockstyle'), 'bubble');

  const rows = d.querySelectorAll('#sessions .srow');
  rows[0].click();
  rows[1].click();
  assert.ok(rows[1].classList.contains('active'));
  assert.ok(!rows[0].classList.contains('active'));

  const cb = d.getElementById('collapsebtn');
  cb.click();
  assert.strictEqual(cb.title, 'Expand sidebar');
  cb.click();
  assert.strictEqual(cb.title, 'Collapse sidebar');

  const chip = d.querySelector('.chip.set');  // the 'unicode' one
  chip.click();   // data-umode absent -> ||'show'; b present; umcap present
  assert.strictEqual(d.getElementById('chat').getAttribute('data-umode'), 'reveal');
  assert.strictEqual(chip.querySelector('b').textContent, 'Reveal');
  assert.strictEqual(d.getElementById('umcap').textContent, 'Reveal');
  chip.click();   // data-umode present now (||'show' truthy side)
});

test('unicode chip without <b> and without #umcap: if-absent branches', function () {
  const { win } = loadScript(JS,
    '<div id="app"><div id="chat"></div><span class="chip set">unicode</span></div>', {});
  win.document.querySelector('.chip.set').click();
});

test('no collapsebtn and no #chat: if-cb false + final scroll catch', function () {
  loadScript(JS, '<div id="app"></div>', {});
});
