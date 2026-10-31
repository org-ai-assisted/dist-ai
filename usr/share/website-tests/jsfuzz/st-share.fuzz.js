'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* Property/fuzz tests for secure-terminal's share.js -- the local-only social-share widget, the
   MASTODON-instance VARIANT (differs from the output-lies family copy: it validates the prompted
   instance against a host-name regex and alert()s an invalid one instead of silently opening).
   Attacker/author-influenced surfaces: the share-link map L[data-net] wired into anchor hrefs, and
   the mastodon prompt() string turned into a window.open() navigation. Invariants assert that NO
   data-net value (own key, prototype name, adversarial string) ever yields a dangerous URL scheme
   in an anchor href, and that the mastodon handler NEVER produces a non-https / foreign-scheme
   open -- the /^[a-z0-9.-]+$/i host gate is what blocks a 'javascript:'/'data:' instance. Curated
   DOM configs drive every branch of both IIFEs to deterministic 100% c8. */

const { fc, test, sitePath, adversarialString } = require('./fuzz-harness.js');
const { loadScript } = require('./harness.js');

const JS = sitePath('secure-terminal.github.io', 'share.js');
if (!require('node:fs').existsSync(JS)) { return; }   // skip when this site is absent (partial checkout)

const DANGER = /^\s*(javascript|data|vbscript):/i;
const HOSTCHARS = /^[a-z0-9.-]+$/i;

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

const tick = function () { return new Promise(function (r) { setImmediate(r); }); };

/* --- coverage: every branch of both IIFEs, deterministic (mirrors the jscov DOM configs) --- */

test('st-share: known net set, email gets no _blank, unknown net untouched', function () {
  const r = loadScript(JS, FSHARE, {});
  const x = r.win.document.querySelector('a[data-net=x]');
  if (x.href.indexOf('twitter.com/intent/tweet') < 0) { throw new Error('known net href not wired'); }
  if (x.target !== '_blank') { throw new Error('known net should open _blank'); }
  if (r.win.document.querySelector('a[data-net=email]').target === '_blank') { throw new Error('email must not open _blank'); }
  if (r.win.document.querySelector('a[data-net=nope]').getAttribute('href') !== null) { throw new Error('unknown net must not get an href'); }
});

test('st-share: mastodon valid host opens the normalized https URL', function () {
  const r = loadScript(JS, FSHARE, { prompt: 'https://mastodon.social//' });
  r.win.document.querySelector('[data-net=mastodon]').click();
  if (r.opened.length !== 1) { throw new Error('valid host did not open a window'); }
  if (r.opened[0][0].indexOf('https://mastodon.social/share?text=') !== 0) { throw new Error('open URL not normalized: ' + r.opened[0][0]); }
});

test('st-share: mastodon invalid host alerts and opens nothing', function () {
  const alerted = [];
  const r = loadScript(JS, FSHARE, {
    prompt: 'not a host!!',
    setup: function (w) { w.alert = function (m) { alerted.push(m); }; },
  });
  r.win.document.querySelector('[data-net=mastodon]').click();
  if (r.opened.length !== 0) { throw new Error('invalid host must not open'); }
  if (alerted.length !== 1) { throw new Error('invalid host must alert once'); }
});

test('st-share: mastodon empty prompt -> no alert, no open', function () {
  const alerted = [];
  const r = loadScript(JS, FSHARE, {
    prompt: '',
    setup: function (w) { w.alert = function (m) { alerted.push(m); }; },
  });
  r.win.document.querySelector('[data-net=mastodon]').click();
  if (r.opened.length !== 0 || alerted.length !== 0) { throw new Error('empty prompt must do nothing'); }
});

test('st-share: copy + md write clipboard and flash with sh-msg present', async function () {
  const r = loadScript(JS, FSHARE, {});
  r.win.document.querySelector('[data-net=copy]').click();
  r.win.document.querySelector('[data-net=md]').click();
  await tick();
  if (r.copied.length !== 2) { throw new Error('copy+md should write twice'); }
  if (r.copied[0] !== 'https://site.example/page') { throw new Error('copy wrote wrong URL'); }
  if (r.copied[1] !== '[T](https://site.example/page)') { throw new Error('md wrote wrong markdown'); }
});

test('st-share: copy with clipboard but no sh-msg -> flash if(msg) false arm', async function () {
  const r = loadScript(JS, FSHARE.replace('<span class="sh-msg"></span>', ''), {});
  r.win.document.querySelector('[data-net=copy]').click();
  await tick();
  if (r.copied.length !== 1 || r.copied[0] !== 'https://site.example/page') { throw new Error('copy without msg still writes the URL'); }
});

test('st-share: copy/md with no clipboard -> handler no-op', function () {
  const r = loadScript(JS, FSHARE, { clipboard: false });
  r.win.document.querySelector('[data-net=copy]').click();
  r.win.document.querySelector('[data-net=md]').click();
  if (r.copied.length !== 0) { throw new Error('no clipboard -> nothing copied'); }
});

test('st-share: absent mastodon/copy/md controls -> if-absent branches', function () {
  loadScript(JS, '<div class="fshare"></div>', {});
});

test('st-share: navtoggle present -> scroll closes when checked, resize when not', function () {
  const r = loadScript(JS, '<input type="checkbox" id="navtoggle">' + FSHARE, {});
  const nt = r.win.document.getElementById('navtoggle');
  nt.checked = true;
  r.win.dispatchEvent(new r.win.Event('scroll'));
  if (nt.checked !== false) { throw new Error('scroll should close the open nav'); }
  r.win.dispatchEvent(new r.win.Event('resize'));
});

test('st-share: navtoggle absent -> nav IIFE returns early', function () {
  loadScript(JS, FSHARE, {});
});

/* --- invariants --- */

/* For ANY data-net string -- own key, prototype name (js-object-map-prototype-pollution: L is a
   plain object literal, so L['constructor'] is the inherited Function, truthy, and its href
   coerces to a harmless "function ..." string), or adversarial -- the resolved .sh href is never a
   dangerous URL scheme, and _blank is only ever set for a non-email truthy lookup. Non-vacuous: an
   inherited-truthy lookup that coerced to a 'javascript:'/'data:' string would fail here. NOTE: this
   tests attribute VALUES, not a POLLUTED Object.prototype value -- share.js reads L[n] without a
   hasOwnProperty guard, a source-side concern tracked outside this lane. */
test('st-share: no data-net ever yields a dangerous href scheme', function () {
  fc.assert(fc.property(
    fc.oneof(
      fc.constantFrom('x', 'facebook', 'telegram', 'reddit', 'whatsapp', 'linkedin', 'hn', 'email'),
      fc.constantFrom('__proto__', 'constructor', 'prototype', 'hasOwnProperty', 'toString', 'valueOf'),
      adversarialString,
      fc.string({ maxLength: 20 }),
    ),
    function (net) {
      /* The IIFE wires hrefs at load from the data-net present then; opts.setup runs BEFORE the
         script, and setAttribute carries any adversarial value verbatim with no HTML parsing. */
      const r = loadScript(JS,
        '<div class="fshare"><a class="sh" data-net="x">x</a></div>',
        { url: 'https://s.example/x', title: 'T',
          setup: function (w) { w.document.querySelector('.sh').setAttribute('data-net', net); } });
      const a = r.win.document.querySelector('.sh');
      if (a.hasAttribute('href') && DANGER.test(a.getAttribute('href'))) { return false; }
      if (a.getAttribute('target') === '_blank' && net === 'email') { return false; }
      return true;
    },
  ), { seed: 1, numRuns: 50 });
});

/* ACTUAL prototype-pollution regression guard (F7): Object.prototype polluted to a javascript: URL
   + a data-net matching the key -- the own-property-guarded share.js must NOT resolve the INHERITED
   value into an href. FAILS on an un-hardened `if (L[n])`; passes with the hasOwnProperty guard. */
test('st-share: a polluted Object.prototype never lands in an href', function () {
  const r = loadScript(JS, '<div class="fshare"><a class="sh" data-net="pwn">p</a></div>', {
    url: 'https://s.example/x', title: 'T',
    setup: function (w) { w.Object.prototype.pwn = 'javascript:alert(1)'; },
  });
  const a = r.win.document.querySelector('.sh');
  if (a.hasAttribute('href')) { throw new Error('polluted data-net resolved to an href: ' + a.getAttribute('href')); }
});

/* The mastodon instance sanitizer: for ANY prompt() string, when a window opens it is ALWAYS
   https-schemed, its opener is 'noopener', and the host segment (between 'https://' and '/share')
   contains only host characters [a-z0-9.-] -- the /^[a-z0-9.-]+$/i gate is what prevents a
   'javascript:'/'data:' or path-traversal instance from ever becoming a navigation. Non-vacuous:
   feeding 'javascript:alert(1)' / 'data:text/html,x' MUST yield zero opens (they fail the gate). */
test('st-share: mastodon open URL is always https with a clean host, never a foreign scheme', function () {
  fc.assert(fc.property(
    fc.oneof(
      fc.constantFrom('mastodon.social', 'example.org/', 'https://a.b//', 'http://c.d',
        'javascript:alert(1)', 'data:text/html,x', 'vbscript:x', '  spaced  ', 'a/../../b',
        'HTTPS://Mastodon.Social/', 'foo bar', '', '.'),
      adversarialString,
      fc.string({ maxLength: 24 }),
    ),
    function (inst) {
      const r = loadScript(JS,
        '<div class="fshare"><button data-net="mastodon">m</button></div>',
        { url: 'https://s.example/x', title: 'T',
          setup: function (w) {
            w.prompt = function () { return inst; };
            w.alert = function () {};
          } });
      r.win.document.querySelector('[data-net=mastodon]').click();
      for (const o of r.opened) {
        if (o[0].indexOf('https://') !== 0) { return false; }       // scheme is hard-coded https
        if (o[2] !== 'noopener') { return false; }                  // opener hardening preserved
        const host = o[0].slice('https://'.length).split('/share?')[0];
        if (!HOSTCHARS.test(host)) { return false; }                // only validated host chars reach the URL
        if (DANGER.test(o[0])) { return false; }                    // belt-and-braces: never a dangerous scheme
      }
      return true;
    },
  ), { seed: 1, numRuns: 60 });
});
