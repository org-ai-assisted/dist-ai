'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* 100% coverage of secure-terminal's share.js -- a variant of the family share.js that adds
   Mastodon-instance host-regex validation with an alert() on an invalid host. */
const { test } = require('node:test');
const assert = require('node:assert');
const { loadScript, sitePath } = require('./harness.js');

const JS = sitePath('secure-terminal.github.io', 'share.js');
const tick = function () { return new Promise(function (r) { setImmediate(r); }); };

const FSHARE =
  '<div class="fshare">'
  + '<span class="sh-msg"></span>'
  + '<a class="sh" data-net="x">x</a>'
  + '<a class="sh" data-net="email">email</a>'
  + '<a class="sh" data-net="nope">unknown</a>'
  + '<button data-net="mastodon">m</button>'
  + '<button data-net="copy">c</button>'
  + '<button data-net="md">md</button>'
  + '</div>';

test('share links: known net set, email no _blank, unknown untouched', function () {
  const { win } = loadScript(JS, FSHARE, {});
  const x = win.document.querySelector('a[data-net=x]');
  assert.ok(x.href.indexOf('twitter.com/intent/tweet') >= 0);
  assert.strictEqual(x.target, '_blank');
  assert.strictEqual(win.document.querySelector('a[data-net=email]').target, '');
  assert.strictEqual(win.document.querySelector('a[data-net=nope]').getAttribute('href'), null);
});

test('mastodon valid host opens normalized URL', function () {
  const { win, opened } = loadScript(JS, FSHARE, { prompt: 'https://mastodon.social//' });
  win.document.querySelector('[data-net=mastodon]').click();
  assert.strictEqual(opened.length, 1);
  assert.ok(opened[0][0].indexOf('https://mastodon.social/share?text=') === 0, opened[0][0]);
});

test('mastodon invalid host alerts, opens nothing', function () {
  const alerted = [];
  const { win, opened } = loadScript(JS, FSHARE, {
    prompt: 'not a host!!',
    setup: function (w) { w.alert = function (m) { alerted.push(m); }; },
  });
  win.document.querySelector('[data-net=mastodon]').click();
  assert.strictEqual(opened.length, 0);
  assert.strictEqual(alerted.length, 1);
});

test('mastodon empty prompt: no alert, no open', function () {
  const alerted = [];
  const { win, opened } = loadScript(JS, FSHARE, {
    prompt: '',
    setup: function (w) { w.alert = function (m) { alerted.push(m); }; },
  });
  win.document.querySelector('[data-net=mastodon]').click();
  assert.strictEqual(opened.length, 0);
  assert.strictEqual(alerted.length, 0);
});

test('copy + md write clipboard and flash', async function () {
  const { win, copied } = loadScript(JS, FSHARE, {});
  win.document.querySelector('[data-net=copy]').click();
  win.document.querySelector('[data-net=md]').click();
  await tick();
  assert.deepStrictEqual(copied,
    ['https://site.example/page', '[T](https://site.example/page)']);
});

test('copy with clipboard but no sh-msg: flash if-msg false branch', async function () {
  const { win, copied } = loadScript(JS, FSHARE.replace('<span class="sh-msg"></span>', ''), {});
  win.document.querySelector('[data-net=copy]').click();
  await tick();
  assert.deepStrictEqual(copied, ['https://site.example/page']);
});

test('copy/md with no clipboard: handler no-op', function () {
  const { win, copied } = loadScript(JS, FSHARE, { clipboard: false });
  win.document.querySelector('[data-net=copy]').click();
  win.document.querySelector('[data-net=md]').click();
  assert.deepStrictEqual(copied, []);
});

test('no mastodon/copy/md elements: if-absent branches', function () {
  loadScript(JS, '<div class="fshare"></div>', {});
});

test('navtoggle present: scroll closes when checked, resize when not', function () {
  const { win } = loadScript(JS, '<input type="checkbox" id="navtoggle">' + FSHARE, {});
  const nt = win.document.getElementById('navtoggle');
  nt.checked = true;
  win.dispatchEvent(new win.Event('scroll'));
  assert.strictEqual(nt.checked, false);
  win.dispatchEvent(new win.Event('resize'));
});

test('navtoggle absent: nav IIFE returns early', function () {
  loadScript(JS, FSHARE, {});
});
