'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* 100% coverage of the family share.js (3 byte-identical copies). Each physical copy is loaded
   and exercised so c8 covers every file the gate includes. */
const { test } = require('node:test');
const assert = require('node:assert');
const { loadScript, sitePath } = require('./harness.js');

const COPIES = [
  sitePath('output-lies.github.io', 'share.js'),
  sitePath('org-ai-assisted.github.io', 'share.js'),
  sitePath('output-lies.github.io', 'git-diffs-lie/share.js'),
];

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

for (const JS of COPIES) {
  test('share links: known net set, email no _blank, unknown untouched [' + JS + ']', function () {
    const { win } = loadScript(JS, FSHARE, {});
    const x = win.document.querySelector('a[data-net=x]');
    assert.ok(x.href.indexOf('twitter.com/intent/tweet') >= 0);
    assert.strictEqual(x.target, '_blank');
    assert.strictEqual(win.document.querySelector('a[data-net=email]').target, '');
    assert.strictEqual(win.document.querySelector('a[data-net=nope]').getAttribute('href'), null);
  });

  test('mastodon prompt-with-value opens normalized URL [' + JS + ']', function () {
    const { win, opened } = loadScript(JS, FSHARE, { prompt: 'https://mastodon.social//' });
    win.document.querySelector('[data-net=mastodon]').click();
    assert.strictEqual(opened.length, 1);
    assert.ok(opened[0][0].indexOf('https://mastodon.social/share?text=') === 0, opened[0][0]);
  });

  test('mastodon empty prompt opens nothing [' + JS + ']', function () {
    const { win, opened } = loadScript(JS, FSHARE, { prompt: '' });
    win.document.querySelector('[data-net=mastodon]').click();
    assert.strictEqual(opened.length, 0);
  });

  test('copy + md write clipboard and flash (msg present) [' + JS + ']', async function () {
    const { win, copied } = loadScript(JS, FSHARE, {});
    win.document.querySelector('[data-net=copy]').click();
    win.document.querySelector('[data-net=md]').click();
    await new Promise(function (r) { setImmediate(r); });
    assert.deepStrictEqual(copied,
      ['https://site.example/page', '[T](https://site.example/page)']);
  });

  test('copy/md with no clipboard and no msg: no-op, no throw [' + JS + ']', function () {
    const { win, copied } = loadScript(JS, FSHARE.replace('<span class="sh-msg"></span>', ''),
      { clipboard: false });
    win.document.querySelector('[data-net=copy]').click();
    win.document.querySelector('[data-net=md]').click();
    assert.deepStrictEqual(copied, []);
  });

  test('no mastodon/copy/md elements: if-absent branches [' + JS + ']', function () {
    loadScript(JS, '<div class="fshare"></div>', {});
  });

  test('navtoggle present: scroll closes when checked, resize when not [' + JS + ']', function () {
    const { win } = loadScript(JS, '<input type="checkbox" id="navtoggle">' + FSHARE, {});
    const nt = win.document.getElementById('navtoggle');
    nt.checked = true;
    win.dispatchEvent(new win.Event('scroll'));
    assert.strictEqual(nt.checked, false);
    win.dispatchEvent(new win.Event('resize'));
  });

  test('navtoggle absent: nav IIFE returns early [' + JS + ']', function () {
    loadScript(JS, FSHARE, {});
  });
}
