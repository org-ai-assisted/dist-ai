'use strict';
/* Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions. */
/* AI-Assisted */

/* Property/fuzz tests for output-lies' quiz/quiz.js -- the client-side "spot the lie" quiz (scores
   locally, nothing transmitted). It reads only its own DOM plus navigator.clipboard (provided by the
   jscov loader), so nothing is staged with the `+` prefix. Curated DOM configs (reused from the jscov
   sibling) drive every branch to deterministic 100% c8; the invariants assert the scoring contract:
   for ANY answer sequence the reported score equals the number of correct answers and stays within
   [0, total], the best-streak equals the longest run of consecutive correct answers (and is likewise
   bounded), the shareable copy text always states that true score, and the score message is rendered
   with textContent (no element children). */

const { fc, test, sitePath } = require('./fuzz-harness.js');
const { loadScript } = require('./harness.js');

const JS = sitePath('output-lies.github.io', 'quiz/quiz.js');
if (!require('node:fs').existsSync(JS)) { return; }   // skip when this site is absent (partial checkout)
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

/* --- coverage: every branch, deterministic (reuses the proven jscov DOM configs) --- */

test('quiz: perfect score + secs=0 branch (Date.now stubbed to 0)', function () {
  const r = loadScript(JS, page(q('lie')), {
    setup: function (w) { w.Date.now = function () { return 0; }; },   // startTime stays 0 -> secs ':0'
  });
  const d = r.win.document;
  answer(r.win, 0, true);
  if (d.getElementById('scoreN').textContent !== '1') { throw new Error('perfect score not 1'); }
  if (d.getElementById('scoreMsg').textContent.indexOf('Perfect') < 0) { throw new Error('Perfect message'); }
  if (d.getElementById('qstats').textContent.indexOf('Time: 0s') < 0) { throw new Error('secs=0 branch'); }
});

test('quiz: strong score, one correct then wrong (want=lie -> missed-lying; secs nonzero)', function () {
  const r = loadScript(JS, page(q('lie') + q('lie')), {});
  answer(r.win, 0, true);    // correct: streak(1) > bestStreak(0) true
  answer(r.win, 1, false);   // wrong, want=lie -> "Missed - it was lying"; startTime already set
  const d = r.win.document;
  if (d.getElementById('scoreMsg').textContent.indexOf('Strong') < 0) { throw new Error('Strong message'); }
  if (d.querySelectorAll('.verdict')[1].textContent.indexOf('lying') < 0) { throw new Error('missed-lying verdict'); }
});

test('quiz: half score (4 q, 2 correct, wrong want=honest -> missed-honest)', function () {
  const r = loadScript(JS, page(q('lie') + q('lie') + q('honest') + q('honest')), {});
  answer(r.win, 0, true);
  answer(r.win, 1, true);
  answer(r.win, 2, false);   // want=honest -> "Missed - it was honest"
  answer(r.win, 3, false);
  const d = r.win.document;
  if (d.getElementById('scoreMsg').textContent.indexOf('Half') < 0) { throw new Error('Half message'); }
  if (d.querySelectorAll('.verdict')[2].textContent.indexOf('honest') < 0) { throw new Error('missed-honest verdict'); }
});

test('quiz: normal score (4 q, 1 correct -> else arm)', function () {
  const r = loadScript(JS, page(q('lie') + q('lie') + q('lie') + q('lie')), {});
  answer(r.win, 0, true);
  answer(r.win, 1, false);
  answer(r.win, 2, false);
  answer(r.win, 3, false);
  if (r.win.document.getElementById('scoreMsg').textContent.indexOf('normal') < 0) { throw new Error('normal message'); }
});

test('quiz: streak reset then shorter run keeps bestStreak (streak>bestStreak false arm)', function () {
  const r = loadScript(JS, page(q('lie') + q('lie') + q('lie') + q('lie')), {});
  answer(r.win, 0, true);    // run 1, 1 > 0 true -> best 1
  answer(r.win, 1, true);    // run 2, 2 > 1 true -> best 2
  answer(r.win, 2, false);   // reset run to 0
  answer(r.win, 3, true);    // run 1, 1 > 2 FALSE -> best stays 2
  if (r.win.document.getElementById('qstats').textContent.indexOf('Best streak: 2') < 0) { throw new Error('bestStreak should stay 2'); }
});

test('quiz: clicking an already-answered question is a no-op (answered true arm)', function () {
  const r = loadScript(JS, page(q('lie')), {});
  const qEl = r.win.document.querySelector('.q');
  qEl.querySelector('.qbtn[data-choice=honest]').click();   // wrong, marks answered
  qEl.querySelector('.qbtn[data-choice=lie]').click();      // already answered -> return
  if (r.win.document.getElementById('scoreN').textContent !== '0') { throw new Error('answered-again must not re-score'); }
});

test('quiz: qcopy with clipboard copies result; qretry triggers reload', async function () {
  const r = loadScript(JS, page(q('lie')), {});
  r.win.document.getElementById('qcopy').click();
  await tick();
  if (r.copied.length !== 1) { throw new Error('clipboard should receive one write'); }
  if (r.copied[0].indexOf('I scored') < 0) { throw new Error('copy text missing score'); }
  r.win.document.getElementById('qretry').click();          // location.reload(): jsdom no-op, covers the line
});

test('quiz: qcopy without clipboard is a no-op (if(navigator.clipboard) false arm)', function () {
  const r = loadScript(JS, page(q('lie')), { clipboard: false });
  r.win.document.getElementById('qcopy').click();
  if (r.win.document.getElementById('qcmsg').textContent !== '') { throw new Error('no clipboard -> no message'); }
});

/* --- invariants --- */

/* Scoring contract: for ANY sequence of right/wrong answers over any number of questions, the final
   reported score equals the number of correct answers and is bounded by [0, total]; the best-streak
   equals the longest run of consecutive correct answers and is likewise in [0, total]; and the score
   message is rendered with textContent (zero element children). A miscount, an off-by-one streak, or
   an innerHTML regression each break this. */
test('quiz: reported score + best-streak match the answer sequence and stay bounded', function () {
  fc.assert(fc.property(
    fc.array(fc.boolean(), { minLength: 1, maxLength: 7 }),   // per question: answer correctly?
    function (picks) {
      let qsHtml = '';
      picks.forEach(function () { qsHtml += q('lie'); });
      const r = loadScript(JS, page(qsHtml), {});
      const d = r.win.document;
      let expectCorrect = 0;
      let run = 0;
      let expectBest = 0;
      for (let k = 0; k < picks.length; k++) {
        answer(r.win, k, picks[k]);
        if (picks[k]) { expectCorrect += 1; run += 1; if (run > expectBest) { expectBest = run; } }
        else { run = 0; }
      }
      const total = picks.length;
      const score = Number(d.getElementById('scoreN').textContent);
      if (score !== expectCorrect) { return false; }           // scoring correctness
      if (score < 0 || score > total) { return false; }        // bounds [0, total]
      const m = d.getElementById('qstats').textContent.match(/Best streak: ([0-9]+)/);
      if (!m) { return false; }
      const best = Number(m[1]);
      if (best !== expectBest) { return false; }               // best-streak == longest correct run
      if (best < 0 || best > total) { return false; }          // bounds [0, total]
      if (d.getElementById('scoreMsg').childElementCount !== 0) { return false; }   // textContent, no markup
      return true;
    },
  ), { seed: 1, numRuns: 50 });
});

/* Share-text integrity: after answering every question, the copied result string always states the
   true "I scored <correct>/<total>" -- the template interpolation never drifts from the live score. */
test('quiz: copied result always states the true score out of total', function () {
  return fc.assert(fc.asyncProperty(
    fc.array(fc.boolean(), { minLength: 1, maxLength: 5 }),
    async function (picks) {
      let qsHtml = '';
      picks.forEach(function () { qsHtml += q('lie'); });
      const r = loadScript(JS, page(qsHtml), {});
      let expectCorrect = 0;
      for (let k = 0; k < picks.length; k++) {
        answer(r.win, k, picks[k]);
        if (picks[k]) { expectCorrect += 1; }
      }
      r.win.document.getElementById('qcopy').click();
      await tick();
      if (r.copied.length !== 1) { return false; }
      return r.copied[0].indexOf('I scored ' + expectCorrect + '/' + picks.length) >= 0;
    },
  ), { seed: 1, numRuns: 40 });
});
