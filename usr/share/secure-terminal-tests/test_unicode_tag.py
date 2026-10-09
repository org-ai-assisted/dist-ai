#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Tests for secure_terminal.unicode_tag: the machine-facing Unicode neutralizer.
## Every attack class is tagged inline; every honest string passes byte-identical;
## the transform is byte-faithful (no added/stripped newline). No Qt is imported.
##
## The source stays pure ASCII: every non-ASCII fixture is a \\u/\\U escape -- a
## test for a neutralizer must not itself smuggle raw bidi/homoglyph bytes into a
## file. Attack classes match the git-diffs-lie / tui-showcase corpus (bidi
## override, Cyrillic/Greek homoglyph, zero-width, control) that motivated it.

import io
import json
import os
import sys
import tempfile

try:
    from secure_terminal import unicode_tag
except Exception as exc:  # fail closed: a required dependency must not silently skip
    sys.stderr.write('secure-terminal-tests: FAIL missing dependency: %s\n' % exc)
    sys.exit(1)

_passed = 0
_failed = 0


def ok(cond, msg):
    global _passed, _failed
    if cond:
        _passed += 1
        print('ok   %s' % msg)
    else:
        _failed += 1
        print('FAIL: %s' % msg)


def run():
    tag = unicode_tag.tag_text

    # 1. Each deception class is tagged inline, at its position, order preserved.
    ok(tag('release\u202egpj') == 'release[U+202E RIGHT-TO-LEFT OVERRIDE]gpj',
       'bidi override tagged in place')
    ok(tag('veri\u200bfied') == 'veri[U+200B ZERO WIDTH SPACE]fied',
       'zero-width space tagged')
    ok(tag('a\x1bb') == 'a[U+001B ESCAPE]b', 'ESC (C0, unnamed) tagged via alias')
    ok(tag('cr\rx') == 'cr[U+000D CARRIAGE RETURN]x',
       'carriage return tagged (overwrite trick), never passed as a control')
    ok('[U+0085 C1 CONTROL]' in tag('a\x85b'), 'C1 control named generically')
    ok('[U+0378 UNNAMED]' in tag('a\u0378b'),
       'unassigned code point (invisible) tagged UNNAMED')

    # 2. Homoglyph is tagged ONLY inside a mixed-script token.
    ok(tag('m\u0430ster') == 'm[U+0430 CYRILLIC SMALL LETTER A]ster',
       'Cyrillic-a homoglyph in a Latin word tagged')
    ok(tag('go\u03bfgle') == 'go[U+03BF GREEK SMALL LETTER OMICRON]gle',
       'Greek-omicron homoglyph in a Latin word tagged')

    # 3. Honest text passes BYTE-IDENTICAL -- the low-noise property.
    legit = (
        'caf\u00e9 r\u00e9sum\u00e9',                 # precomposed accents
        'cafe\u0301 re\u0301sume\u0301',              # decomposed (combining marks)
        '\u65e5\u672c\u8a9e.txt',                     # CJK
        'deploy \U0001f680 done \u2705',              # emoji
        '\u0395\u03bb\u03bb\u03b7\u03bd\u03b9\u03ba\u03ac',   # all-Greek
        '\u043f\u0440\u0438\u0432\u0435\u0442',        # all-Cyrillic (privet)
        'rnicrosoft.com',                             # intra-ASCII look-alike (residue)
        'plain ascii only',
    )
    for text in legit:
        ok(tag(text) == text, 'honest text unchanged: %s' % ascii(text[:14]))

    # 4. Byte-faithful: \t/\n pass; the trailing newline is neither added nor
    #    stripped (the codepoint-stream design has no "missing newline" notion).
    ok(tag('a\tb\nc') == 'a\tb\nc', 'tab and newline pass verbatim')
    ok(unicode_tag.tag_bytes(b'abc') == 'abc', 'no trailing newline added')
    ok(unicode_tag.tag_bytes(b'abc\n') == 'abc\n', 'existing trailing newline kept')

    # 5. An undecodable byte survives as a tagged token, not a silent drop.
    ok(unicode_tag.tag_bytes(b'ok\xffz') == 'ok[INVALID-BYTE 0xFF]z',
       'invalid UTF-8 byte tagged, not dropped')

    # 6. A mixed-script word is tagged while an adjacent honest same-script word
    #    is left untouched (both sides of the token scope).
    out = tag('m\u0430ster \u043f\u0440\u0438\u0432\u0435\u0442')
    ok(out == 'm[U+0430 CYRILLIC SMALL LETTER A]ster '
              '\u043f\u0440\u0438\u0432\u0435\u0442',
       'mixed-script word tagged; adjacent honest Cyrillic word untouched')

    # 7. is_dangerous raising must degrade to "no homoglyph refinement", not crash;
    #    the always-tag classes stay safe regardless.
    saved = unicode_tag.is_dangerous

    def _boom(_token):
        raise RuntimeError('confusables data unavailable')

    unicode_tag.is_dangerous = _boom
    try:
        ok(tag('m\u0430ster') == 'm\u0430ster',
           'is_dangerous failure -> homoglyph left as-is, no crash')
        ok(tag('a\u202eb') == 'a[U+202E RIGHT-TO-LEFT OVERRIDE]b',
           'bidi still tagged when the confusable pass is disabled')
    finally:
        unicode_tag.is_dangerous = saved

    # 8. main(): a file argument and the stdin path both emit tagged bytes.
    saved_out = sys.stdout
    try:
        with tempfile.NamedTemporaryFile('wb', suffix='.txt', delete=False) as handle:
            handle.write('x\u202ey'.encode('utf-8'))
            path = handle.name
        try:
            sys.stdout = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
            rc = unicode_tag.main([path])
            sys.stdout.flush()
            captured = sys.stdout.buffer.getvalue().decode('utf-8')
        finally:
            os.unlink(path)
        sys.stdout = saved_out          # restore BEFORE ok() prints, else a FAIL line is swallowed
        ok(rc == 0 and captured == 'x[U+202E RIGHT-TO-LEFT OVERRIDE]y',
           'main() with a file argument tags its bytes')

        saved_stdin = sys.stdin
        try:
            sys.stdin = io.TextIOWrapper(io.BytesIO('a\u200bb'.encode('utf-8')),
                                         encoding='utf-8')
            sys.stdout = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
            rc = unicode_tag.main([])
            sys.stdout.flush()
            captured = sys.stdout.buffer.getvalue().decode('utf-8')
        finally:
            sys.stdin = saved_stdin
        sys.stdout = saved_out          # restore BEFORE ok() prints, else a FAIL line is swallowed
        ok(rc == 0 and captured == 'a[U+200B ZERO WIDTH SPACE]b',
           'main() with no args reads stdin')

        # A bad file path (OSError on the file read) exits non-zero with a clean
        # stderr message, not a traceback.
        saved_err = sys.stderr
        try:
            sys.stderr = io.StringIO()
            rc = unicode_tag.main(['/nonexistent/unicode-tag/path'])
            err = sys.stderr.getvalue()
        finally:
            sys.stderr = saved_err
        sys.stdout = saved_out          # restore BEFORE ok() prints, else a FAIL line is swallowed
        ok(rc == 1 and 'unicode-tag:' in err,
           'main() reports an unreadable file cleanly (rc=1), no traceback')

        # main_stdin(): stdin-only, ignores argv (opens NO file, so a confining
        # AppArmor profile can deny file reads). Same tagging.
        saved_stdin = sys.stdin
        try:
            sys.stdin = io.TextIOWrapper(io.BytesIO('m\u0430ster'.encode('utf-8')),
                                         encoding='utf-8')
            sys.stdout = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
            rc = unicode_tag.main_stdin(['ignored-path'])
            sys.stdout.flush()
            captured = sys.stdout.buffer.getvalue().decode('utf-8')
        finally:
            sys.stdin = saved_stdin
        sys.stdout = saved_out          # restore BEFORE ok() prints, else a FAIL line is swallowed
        ok(rc == 0 and captured == 'm[U+0430 CYRILLIC SMALL LETTER A]ster',
           'main_stdin() tags stdin and ignores its argv')

        # main_stdin on an unreadable stdin (e.g. a directory) exits 1 cleanly.
        class _BadInBuffer:
            @staticmethod
            def read():
                raise IsADirectoryError(21, 'Is a directory')

        class _BadIn:
            buffer = _BadInBuffer()

        saved_stdin = sys.stdin
        saved_err = sys.stderr
        try:
            sys.stdin = _BadIn()
            sys.stderr = io.StringIO()
            rc = unicode_tag.main_stdin()
            err = sys.stderr.getvalue()
        finally:
            sys.stdin = saved_stdin
            sys.stderr = saved_err
        sys.stdout = saved_out          # restore BEFORE ok() prints, else a FAIL line is swallowed
        ok(rc == 1 and 'unicode-tag:' in err,
           'main_stdin reports an unreadable stdin cleanly (rc=1)')

        # A downstream pipe closing early (BrokenPipeError) exits 1, no traceback.
        class _BrokenBuffer:
            @staticmethod
            def write(_data):
                raise BrokenPipeError()

        class _BrokenOut:
            buffer = _BrokenBuffer()

        sys.stdout = _BrokenOut()
        broken_rc = unicode_tag._write_tagged(b'x')
        sys.stdout = saved_out          # restore BEFORE ok() prints
        ok(broken_rc == 1,
           'a closed output pipe exits 1 (BrokenPipeError), no traceback')
    finally:
        sys.stdout = saved_out

    # 9. CANARY: the in-place-tag checks have teeth. Prove it by BREAKING the real
    #    tag_text (not a stub) and confirming its output then MISMATCHES -- so a
    #    neutralizer that stops recognizing an attack class cannot pass section 1
    #    byte-identical (0 failures != 0 coverage). marking_class is the module global
    #    tag_text's active-deception branch rides on (its `in _ALWAYS_TAG` gate);
    #    patching it drives the REAL tag_text -- the SAME function object section 1's
    #    `tag` binds -- down the untagged path. The old canary patched tag_text itself
    #    to `lambda s: s` and then compared its output, reducing to two literals that
    #    passed with the real tag_text fully broken.
    _saved_mc = unicode_tag.marking_class
    unicode_tag.marking_class = lambda cp: 'nonascii'   # never in _ALWAYS_TAG -> tags nothing
    try:
        ok(unicode_tag.tag_text('release\u202egpj')
           != 'release[U+202E RIGHT-TO-LEFT OVERRIDE]gpj',
           'CANARY: tag_text whose classifier stops flagging bidi FAILS the bidi check (teeth)')
        ok(unicode_tag.tag_text('veri\u200bfied')
           != 'veri[U+200B ZERO WIDTH SPACE]fied',
           'CANARY: tag_text whose classifier stops flagging invisibles FAILS the zero-width check (teeth)')
    finally:
        unicode_tag.marking_class = _saved_mc

    # 10. has_deceptive is the allocation-free, early-exit boolean behind tag_text (the
    #     clipboard watcher's trigger). It must agree with `tag_text(s) != s` for every
    #     input at ANY size -- there is no scan cap, so a hazard past 1M is still caught.
    _hd = unicode_tag.has_deceptive
    ZWSP = chr(0x200b); RLO = chr(0x202e); CYR_A = chr(0x430); GREEK_O = chr(0x3bf)
    _past_cap = 'a' * 1_050_000 + ZWSP     # zero-width space past the old 1M cap
    # Honest Cyrillic word (privet) for the mixed/adjacent-token case.
    _cyr_word = ''.join(chr(c) for c in (0x43f, 0x440, 0x438, 0x432, 0x435, 0x442))
    _corpus = [
        '', 'plain ascii', 'a\tb\nc', 'caf' + chr(0xe9),
        chr(0x65e5) + chr(0x672c) + chr(0x8a9e),          # honest CJK
        chr(0x3b1) + chr(0x3b2) + chr(0x3b3),             # honest Greek
        'release' + RLO + 'gpj', 'veri' + ZWSP + 'fied', 'a\x1bb', 'cr\rx',
        'm' + CYR_A + 'ster', 'go' + GREEK_O + 'gle',     # homoglyphs posing as ASCII
        'm' + CYR_A + 'ster ' + _cyr_word,                # homoglyph token + honest word
        'ok' + chr(0xdc80) + 'z',                         # surrogateescape raw undecodable byte
        _past_cap, 'c' * 1_050_000,
    ]
    for _s in _corpus:
        ok(_hd(_s) == (unicode_tag.tag_text(_s) != _s),
           'has_deceptive == (tag_text != s) on a %d-char input' % len(_s))
    ok(_hd(_past_cap),
       'has_deceptive: a zero-width char PAST the old 1M cap is caught (no size cap)')
    ok(not _hd('c' * 1_050_000),
       'has_deceptive: a clean multi-MB string is not deceptive (no false positive)')

    # 11. --json: one process tags every string of a JSON document (the hook's batch
    #     path -- a process per string ran a large Grep past the hook timeout).
    _tj = unicode_tag.tag_json
    ok(_tj('p\u0430ss') == 'p[U+0430 CYRILLIC SMALL LETTER A]ss',
       'tag_json: a top-level string is tagged')
    ok(_tj(7) == 7 and _tj(None) is None and _tj(True) is True,
       'tag_json: a top-level non-string scalar passes unchanged')
    _doc = {'stdout': 'a\u202eb', 'list': ['ok', ['d\u200beep'], 3, None],
            'k\u200b': 'v', 'k[U+200B ZERO WIDTH SPACE]': 'w'}
    _out = _tj(_doc)
    ok(_out['stdout'] == 'a[U+202E RIGHT-TO-LEFT OVERRIDE]b'
       and _out['list'] == ['ok', ['d[U+200B ZERO WIDTH SPACE]eep'], 3, None],
       'tag_json: nested values are tagged in place, order and non-strings kept')
    ok(sorted(_out) == ['k[U+200B ZERO WIDTH SPACE]', 'k[U+200B ZERO WIDTH SPACE]#2',
                        'list', 'stdout']
       and sorted((_out['k[U+200B ZERO WIDTH SPACE]'],
                   _out['k[U+200B ZERO WIDTH SPACE]#2'])) == ['v', 'w'],
       'tag_json: a tagged key colliding with a literal key keeps BOTH values')
    ok(_tj(['a\udcffb']) == ['a\ufffd\ufffd\ufffdb'],
       'tag_json: a lone surrogate is scrubbed (UTF-8 safe), not a crash')
    _deep: list = []
    _cur = _deep
    for _ in range(5000):
        _nxt: list = []
        _cur.append(_nxt)
        _cur = _nxt
    _cur.append('z\u200b')
    _walked = _tj(_deep)
    for _ in range(5000):
        _walked = _walked[0]
    ok(_walked == ['z[U+200B ZERO WIDTH SPACE]'],
       'tag_json: a 5000-deep document is walked (explicit stack, no RecursionError)')

    def _run_json(stdin_bytes, out=None, argv=('--json',)):
        saved = sys.stdin, sys.stdout, sys.stderr
        try:
            sys.stdin = io.TextIOWrapper(io.BytesIO(stdin_bytes), encoding='utf-8')
            sys.stdout = out if out is not None else io.StringIO()
            sys.stderr = io.StringIO()
            rc = unicode_tag.main_stdin(None if argv is None else list(argv))
            got = sys.stdout.getvalue() if out is None else ''
            return rc, got, sys.stderr.getvalue()
        finally:
            sys.stdin, sys.stdout, sys.stderr = saved

    rc, got, _err = _run_json(json.dumps(
        {unicode_tag.JSON_REQUEST_KEY: {'f': ['x', 'm\u0430ster', 1.5]}}).encode('ascii'))
    ok(rc == 0 and json.loads(got) == {unicode_tag.JSON_RESULT_KEY:
                                         {'f': ['x', 'm[U+0430 CYRILLIC SMALL LETTER A]ster', 1.5]}},
       'main_stdin --json replies with the tagged document in the result envelope')
    for _label, _bad in (('malformed JSON', b'{not json'),
                         ('missing request key', b'{"other": 1}'),
                         ('non-object request', b'[1, 2]'),
                         ('invalid UTF-8', b'\xff\xfe'),
                         ('NaN constant', b'{"unicode-tag-json": [NaN]}'),
                         ('Infinity constant', b'{"unicode-tag-json": -Infinity}'),
                         ('overflowing number', b'{"unicode-tag-json": 1e400}')):
        rc, got, err = _run_json(_bad)
        ok(rc == 1 and got == '' and 'unicode-tag: --json: bad request' in err,
           'main_stdin --json rejects a bad request cleanly (rc=1): %s' % _label)

    class _BrokenText:
        @staticmethod
        def write(_data):
            raise BrokenPipeError()

    rc, _got, _err = _run_json(b'{"unicode-tag-json": "x"}', out=_BrokenText())
    ok(rc == 1, 'main_stdin --json: a closed output pipe exits 1, no traceback')

    _saved_argv = sys.argv
    try:
        sys.argv = ['unicode-tag-stdin', '--json']
        rc, got, _err = _run_json(b'{"unicode-tag-json": "a\\u200bb"}', argv=None)
    finally:
        sys.argv = _saved_argv
    ok(rc == 0 and json.loads(got)[unicode_tag.JSON_RESULT_KEY]
       == 'a[U+200B ZERO WIDTH SPACE]b',
       'main_stdin() with no argv reads --json from sys.argv (the installed script path)')

    print('test_unicode_tag: %d pass, %d fail, 0 skip' % (_passed, _failed))
    return 1 if _failed else 0


if __name__ == '__main__':
    sys.exit(run())
