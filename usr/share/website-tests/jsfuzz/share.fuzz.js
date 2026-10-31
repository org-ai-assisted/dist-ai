'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* Property/fuzz tests for the local-only social-share widget share.js (byte-identical across
   output-lies.github.io, org-ai-assisted.github.io and git-diffs-lie/; the secure-terminal copy
   is a separate variant with its own test). Two concerns:
     - the share-link map L[data-net] and the mastodon-instance prompt sanitizer are the
       attacker/author-influenced surfaces; invariants assert no dangerous URL scheme ever lands in
       an anchor href or an opened window, and a prototype-name data-net (js-object-map-prototype-
       pollution) never produces a javascript:/data: href (the lookup coerces to a harmless string);
     - curated DOM configs drive every branch of both IIFEs to deterministic 100% c8. */

const { fc, test, sitePath } = require('./fuzz-harness.js');
const { loadScript } = require('./harness.js');

/* The three byte-identical copies in the covered set. c8 attributes coverage per FILE PATH, so the
   same suite must exercise each path to drive all three to 100% (the secure-terminal copy is a
   different variant -- share-st.fuzz.js). */
const SHARES = [
  ['output-lies', sitePath('output-lies.github.io', 'share.js')],
  ['org-ai', sitePath('org-ai-assisted.github.io', 'share.js')],
  ['git-diffs-lie', sitePath('output-lies.github.io', 'git-diffs-lie/share.js')],
].filter(function (s) { return require('node:fs').existsSync(s[1]); });   // drop sites absent in a partial checkout

/* A .fshare container with one anchor per data-net value, plus the optional mastodon/copy/md/msg
   controls and the mobile-nav toggle. `nets` drives the anchor set; flags toggle each control. */
function shareBody(nets, opt) {
  opt = opt || {};
  let h = '<nav class="fshare">';
  nets.forEach(function (n) { h += '<a class="sh" data-net="' + n + '">' + n + '</a>'; });
  if (opt.mastodon) { h += '<a data-net="mastodon">m</a>'; }
  if (opt.copy) { h += '<a data-net="copy">c</a>'; }
  if (opt.md) { h += '<a data-net="md">md</a>'; }
  if (opt.msg) { h += '<span class="sh-msg"></span>'; }
  h += '</nav>';
  if (opt.navtoggle) { h += '<input type="checkbox" id="navtoggle"' + (opt.checked ? ' checked' : '') + '>'; }
  return h;
}

const DANGER = /^\s*(javascript|data|vbscript):/i;

/* The full suite, parametrized over each byte-identical copy's path so c8 reports 100% on each. */
function shareSuite(label, SHARE) {
/* --- coverage: every branch of both IIFEs, deterministic --- */

/* Full config: real net needing _blank (x), the email net (no _blank), an unknown net (L[n]
   falsy -> skipped), and a prototype-name net (inherited truthy -> the coercion path); all the
   optional controls present; nav toggle checked. Exercises the forEach truthy/email/falsy arms,
   the mastodon prompt (truthy instance), copy+md with clipboard, flash with msg present, and
   closeNav with checked=true. */
test(label + ' share: full widget wires links, mastodon, copy, md, nav-close', async function () {
  const r = loadScript(SHARE, shareBody(['x', 'email', 'nope', 'constructor'],
    { mastodon: true, copy: true, md: true, msg: true, navtoggle: true, checked: true }),
    { url: 'https://site.example/p', title: 'Pg', prompt: 'mastodon.social' });
  const win = r.win;
  const a = {};
  win.document.querySelectorAll('.sh').forEach(function (el) { a[el.getAttribute('data-net')] = el; });
  if (a.x.getAttribute('href').indexOf('twitter.com') === -1) { throw new Error('x href not set'); }
  if (a.x.getAttribute('target') !== '_blank') { throw new Error('x should open _blank'); }
  if (a.email.getAttribute('href').indexOf('mailto:') !== 0) { throw new Error('email href not mailto'); }
  if (a.email.getAttribute('target') === '_blank') { throw new Error('email must not open _blank'); }
  if (a.nope.hasAttribute('href')) { throw new Error('unknown net must not get an href'); }
  /* prototype-name net: L[n] is inherited-truthy, href coerces to a string -- MUST NOT be a
     dangerous scheme (the safety boundary; benign garbage href is acceptable). */
  if (a.constructor.hasAttribute('href') && DANGER.test(a.constructor.getAttribute('href'))) {
    throw new Error('prototype-name net produced a dangerous scheme');
  }
  win.document.querySelector('[data-net=mastodon]').dispatchEvent(new win.Event('click'));
  if (r.opened.length !== 1 || r.opened[0][0].indexOf('https://mastodon.social/share') !== 0) {
    throw new Error('mastodon open URL wrong: ' + JSON.stringify(r.opened));
  }
  const msg = win.document.querySelector('.sh-msg');
  win.document.querySelector('[data-net=copy]').dispatchEvent(new win.Event('click'));
  if (r.copied[0] !== 'https://site.example/p') { throw new Error('copy did not copy the URL'); }
  win.document.querySelector('[data-net=md]').dispatchEvent(new win.Event('click'));
  if (r.copied[1] !== '[Pg](https://site.example/p)') { throw new Error('md copy wrong'); }
  /* flash runs in the writeText .then microtask; flush it, then the inline setTimeout clears. */
  await Promise.resolve(); await Promise.resolve();
  if (msg.textContent !== '') { throw new Error('flash did not set-then-clear'); }
  win.dispatchEvent(new win.Event('scroll'));
  if (win.document.getElementById('navtoggle').checked) { throw new Error('scroll should close nav'); }
});

/* Empty-prompt mastodon (i falsy -> no open), clipboard ABSENT (copy/md skip writeText), msg
   ABSENT (flash if(msg) false arm -- reached because clipboard-present would be needed to call
   flash; here we instead cover the clipboard-absent arms and the no-msg element), nav toggle
   present but UNCHECKED (closeNav no-op on resize). */
test(label + ' share: empty prompt, no clipboard, no msg, resize no-op', function () {
  const r = loadScript(SHARE, shareBody(['reddit'],
    { mastodon: true, copy: true, md: true, navtoggle: true, checked: false }),
    { clipboard: false, prompt: '' });
  const win = r.win;
  win.document.querySelector('[data-net=mastodon]').dispatchEvent(new win.Event('click'));
  if (r.opened.length !== 0) { throw new Error('empty instance must not open a window'); }
  win.document.querySelector('[data-net=copy]').dispatchEvent(new win.Event('click'));
  win.document.querySelector('[data-net=md]').dispatchEvent(new win.Event('click'));
  if (r.copied.length !== 0) { throw new Error('no clipboard -> nothing copied'); }
  win.dispatchEvent(new win.Event('resize'));
  /* unchecked stays unchecked; nothing to assert beyond no throw. */
});

/* flash with msg present but clipboard present too, and msg element present -> covers the
   if(msg) TRUE arm of flash independently of config 1's ordering. Also covers copy with
   clipboard present and msg present. */
test(label + ' share: flash sets the message element (clear timer deferred)', async function () {
  /* syncTimers:false keeps the real setTimeout, so flash sets the text and the 2s clear does NOT
     fire during the test -- the SET arm is observable after the writeText .then microtask. */
  const r = loadScript(SHARE, shareBody([], { copy: true, msg: true }), { syncTimers: false });
  const win = r.win;
  const msg = win.document.querySelector('.sh-msg');
  win.document.querySelector('[data-net=copy]').dispatchEvent(new win.Event('click'));
  await Promise.resolve(); await Promise.resolve();
  if (msg.textContent !== 'link copied') { throw new Error('flash did not set the message'); }
});

/* Minimal DOM: no mastodon/copy/md controls (the if(m)/if(c)/if(md) FALSE arms) and no
   #navtoggle (the if(!nt) return arm). */
test(label + ' share: absent controls and absent nav toggle are no-ops', function () {
  const r = loadScript(SHARE, shareBody(['hn']), {});
  if (r.opened.length !== 0 || r.copied.length !== 0) { throw new Error('nothing should fire'); }
});

/* --- invariants --- */

/* For ANY data-net attribute VALUE (own keys, built-in prototype names, adversarial strings), the
   resolved .sh href never carries a dangerous scheme, and _blank is set only for a non-email truthy
   lookup. The value is applied with setAttribute in setup (before the IIFE reads it), NOT
   interpolated into HTML, so a value with quotes/brackets cannot break out and inject a second
   attribute -- the predicate always tests the generated value. A built-in prototype NAME (e.g.
   'constructor') is inherited-truthy and coerces to a harmless non-URL string here. NOTE: this does
   NOT assert prototype-pollution safety -- a POLLUTED Object.prototype value is a separate, source-
   side concern tracked outside this lane (share.js reads L[n] without a hasOwnProperty guard). */
test(label + ' share: no data-net attribute value yields a dangerous href scheme', function () {
  fc.assert(fc.property(
    fc.oneof(
      fc.constantFrom('x', 'facebook', 'telegram', 'reddit', 'whatsapp', 'linkedin', 'hn', 'email'),
      fc.constantFrom('__proto__', 'constructor', 'prototype', 'hasOwnProperty', 'toString', 'valueOf'),
      fc.string({ maxLength: 20 }),
    ),
    function (net) {
      const r = loadScript(SHARE, '<nav class="fshare"></nav>', {
        url: 'https://s.example/x', title: 'T',
        setup: function (w) {
          const a = w.document.createElement('a');
          a.className = 'sh';
          a.setAttribute('data-net', net);   // DOM API: the value cannot break out of the attribute
          w.document.querySelector('.fshare').appendChild(a);
        },
      });
      const el = r.win.document.querySelector('.sh');
      if (el.getAttribute('data-net') !== net) { return false; }   // the IIFE saw exactly our value
      if (el.hasAttribute('href') && DANGER.test(el.getAttribute('href'))) { return false; }
      if (el.getAttribute('target') === '_blank' && net === 'email') { return false; }
      return true;
    },
  ), { seed: 1, numRuns: 40 });
});

/* ACTUAL prototype-pollution regression guard (F7): with Object.prototype polluted to a javascript:
   URL and a data-net matching the polluted key, the own-property-guarded share.js must NOT resolve
   the INHERITED value into an href. FAILS on an un-hardened `if (L[n])` (which read the inherited
   polluted string and set href='javascript:alert(1)'); passes with the hasOwnProperty guard. */
test(label + ' share: a polluted Object.prototype never lands in an href', function () {
  const r = loadScript(SHARE, '<nav class="fshare"><a class="sh" data-net="pwn">p</a></nav>', {
    url: 'https://s.example/x', title: 'T',
    setup: function (w) { w.Object.prototype.pwn = 'javascript:alert(1)'; },
  });
  const el = r.win.document.querySelector('.sh');
  if (el.hasAttribute('href')) {
    throw new Error('polluted data-net resolved to an href: ' + el.getAttribute('href'));
  }
});

/* The mastodon instance sanitizer: for ANY prompt() string, the opened URL (when one opens) is
   always https-schemed and never a javascript:/data: payload -- the http(s):// strip + trailing
   -slash trim must not let another scheme through. */
test(label + ' share: mastodon open URL is always https, never a foreign scheme', function () {
  fc.assert(fc.property(
    fc.oneof(
      fc.constantFrom('mastodon.social', 'example.org/', 'https://a.b//', 'http://c.d',
        'javascript:alert(1)', 'data:text/html,x', '  spaced  ', 'a/../../b'),
      fc.string({ maxLength: 24 }),
    ),
    function (inst) {
      let cur = inst;
      const r = loadScript(SHARE, shareBody([], { mastodon: true }),
        { setup: function (w) { w.prompt = function () { return cur; }; } });
      r.win.document.querySelector('[data-net=mastodon]').dispatchEvent(new r.win.Event('click'));
      /* The scheme is hardcoded 'https://', so no prompt value can inject a javascript:/data:
         navigation (the real XSS boundary); a broken host is harmless. Assert scheme + opener. */
      for (const o of r.opened) {
        if (o[0].indexOf('https://') !== 0) { return false; }
        if (o[2] !== 'noopener') { return false; }
      }
      return true;
    },
  ), { seed: 1, numRuns: 40 });
});
}

SHARES.forEach(function (s) { shareSuite(s[0], s[1]); });
