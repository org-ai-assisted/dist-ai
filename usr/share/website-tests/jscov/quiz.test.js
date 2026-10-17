'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* 100% coverage of output-lies' quiz/quiz.js -- the client-side "spot the lie" quiz. */
const { test } = require('node:test');
const assert = require('node:assert');
const { loadScript, sitePath } = require('./harness.js');

const JS = sitePath('output-lies.github.io', 'quiz/quiz.js');
const tick = function () { return new Promise(function (r) { setImmediate(r); }); };

/* One question: answer is 'lie' or 'honest'; two choice buttons; a verdict span. */
function q(answer) {
  return '<div class="q" data-answer="' + answer + '">'
    + '<button class="qbtn" data-choice="lie">L</button>'
    + '<button class="qbtn" data-choice="honest">H</button>'
    + '<span class="verdict"></span></div>';
}
function page(questions) {
  return questions + '<span id="scoreN"></span><span id="scoreMsg"></span><div id="scorebox"></div>'
    + '<span id="progress"></span><span id="qstats"></span><span id="qcmsg"></span>'
    + '<button id="qcopy">copy</button><button id="qretry">retry</button>';
}
/* click the choice matching `want` (correct) or the other (wrong) in question index i. */
function answer(win, i, correct) {
  const qEls = win.document.querySelectorAll('.q');
  const want = qEls[i].getAttribute('data-answer');
  const pick = correct ? want : (want === 'lie' ? 'honest' : 'lie');
  qEls[i].querySelector('.qbtn[data-choice=' + pick + ']').click();
}

test('perfect score + secs=0 branch (Date.now stubbed to 0)', function () {
  const { win } = loadScript(JS, page(q('lie')), {
    setup: function (w) { w.Date.now = function () { return 0; }; },  // startTime stays 0 -> secs ':0'
  });
  answer(win, 0, true);
  assert.strictEqual(win.document.getElementById('scoreN').textContent, '1');
  assert.ok(win.document.getElementById('scoreMsg').textContent.indexOf('Perfect') >= 0);
  assert.ok(win.document.getElementById('qstats').textContent.indexOf('Time: 0s') >= 0);
});

test('strong score: one correct then one wrong (want=lie -> missed-lying)', function () {
  const { win } = loadScript(JS, page(q('lie') + q('lie')), {});
  answer(win, 0, true);    // correct: streak>bestStreak
  answer(win, 1, false);   // wrong, want=lie -> "Missed - it was lying"; startTime already set
  assert.ok(win.document.getElementById('scoreMsg').textContent.indexOf('Strong') >= 0);
  const vs = win.document.querySelectorAll('.verdict');
  assert.ok(vs[1].textContent.indexOf('lying') >= 0);
});

test('half score (4 q, 2 correct, a wrong want=honest -> missed-honest)', function () {
  const { win } = loadScript(JS, page(q('lie') + q('lie') + q('honest') + q('honest')), {});
  answer(win, 0, true);
  answer(win, 1, true);
  answer(win, 2, false);   // want=honest -> "Missed - it was honest"
  answer(win, 3, false);
  assert.ok(win.document.getElementById('scoreMsg').textContent.indexOf('Half') >= 0);
  const vs = win.document.querySelectorAll('.verdict');
  assert.ok(vs[2].textContent.indexOf('honest') >= 0);
});

test('normal score (4 q, 1 correct)', function () {
  const { win } = loadScript(JS, page(q('lie') + q('lie') + q('lie') + q('lie')), {});
  answer(win, 0, true);
  answer(win, 1, false);
  answer(win, 2, false);
  answer(win, 3, false);
  assert.ok(win.document.getElementById('scoreMsg').textContent.indexOf('normal') >= 0);
});

test('clicking an already-answered question is a no-op', function () {
  const { win } = loadScript(JS, page(q('lie')), {});
  const qEl = win.document.querySelector('.q');
  qEl.querySelector('.qbtn[data-choice=honest]').click();   // wrong, answered
  qEl.querySelector('.qbtn[data-choice=lie]').click();      // already answered -> return
  assert.strictEqual(win.document.getElementById('scoreN').textContent, '0');
});

test('qcopy with clipboard copies result; qretry triggers reload', async function () {
  const { win, copied } = loadScript(JS, page(q('lie')), {});
  win.document.getElementById('qcopy').click();
  await tick();
  assert.strictEqual(copied.length, 1);               // qcmsg is cleared by setTimeout; assert the write
  assert.ok(copied[0].indexOf('I scored') >= 0);
  win.document.getElementById('qretry').click();       // location.reload(): jsdom no-op, covers the line
});

test('qcopy without clipboard: no-op', function () {
  const { win } = loadScript(JS, page(q('lie')), { clipboard: false });
  win.document.getElementById('qcopy').click();
  assert.strictEqual(win.document.getElementById('qcmsg').textContent, '');
});
