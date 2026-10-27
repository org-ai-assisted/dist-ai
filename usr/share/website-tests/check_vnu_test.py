#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression tests for webcheck.vnu's pure (vnu-free) engine: message ASCII-normalization, the
file: url -> tree-relative path mapping, message -> (path, message) classification (error gated /
info advisory / non-document-error a problem), baseline parse/format roundtrip, and the
accept-baseline comparison -- a NEW error fails, a baselined one passes, a resolved one is
reported, and a MISSING baseline fails CLOSED. Run by the website-tests launcher (a required unit)
or directly: ./check_vnu_test.py"""
import os
import sys

# vnu renders element names + quotes typographically; build those code points with chr() so THIS
# test source stays ASCII (R-001) -- a literal curly quote here would itself fail the style gate.
_LDQUO, _RDQUO, _RSQUO = chr(0x201c), chr(0x201d), chr(0x2019)
_NDASH, _MDASH, _HELLIP = chr(0x2013), chr(0x2014), chr(0x2026)
_NBSP, _CJK = chr(0x00a0), chr(0x4e2d)


def _load():
    # the vnu gate lives in the importable core; import it (its real home). Prepend this tree's
    # dist-packages (checkout case); no-op when installed.
    _dp = os.path.normpath(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..', '..', 'lib', 'python3', 'dist-packages'))
    if os.path.isdir(_dp) and _dp not in sys.path:
        sys.path.insert(0, _dp)
    from dist_ai.webcheck import vnu
    return vnu


vn = _load()


def run() -> int:
    stats = {"pass": 0, "fail": 0}

    def ck(cond: bool, label: str) -> None:
        stats["pass" if cond else "fail"] += 1
        status = "pass" if cond else "FAIL"
        (sys.stdout if cond else sys.stderr).write(
            "check_vnu_test: %s %s\n" % (status, label))

    # normalize_message: fold vnu's typographic quotes/dashes/ellipsis/nbsp to ASCII, drop any
    # residual non-ASCII to '?', and collapse whitespace -- so a committed baseline stays ASCII
    # and the key is stable regardless of vnu's rendering.
    ck(vn.normalize_message('Element %shead%s missing %stitle%s'
                            % (_LDQUO, _RDQUO, _LDQUO, _RDQUO))
       == 'Element "head" missing "title"', "normalize folds curly double quotes")
    ck(vn.normalize_message('don%st' % _RSQUO) == "don't", "normalize folds curly apostrophe")
    ck(vn.normalize_message('a%sb%sc%s' % (_NDASH, _MDASH, _HELLIP)) == 'a-b-c...',
       "normalize folds dashes/ellipsis")
    ck(vn.normalize_message('a%sb' % _NBSP) == 'a b', "normalize folds nbsp to space")
    ck(vn.normalize_message('x%sy' % _CJK) == 'x?y', "normalize residual non-ASCII -> ?")
    ck(vn.normalize_message('a   b\n c\t') == 'a b c', "normalize collapses whitespace + strips")
    # The baseline file must never carry a non-ASCII byte.
    ck(vn.normalize_message('%sa%s %s b' % (_LDQUO, _RDQUO, _MDASH)).isascii(),
       "normalized message is ASCII")

    # _rel_path: a file: url under the root -> the tree-relative path; the file:// authority form
    # and a bare / both normalize; a url OUTSIDE the root degrades to its basename, never an
    # absolute (machine-specific) path leaking into a committed key.
    ck(vn._rel_path('file:/srv/site/wiki/x.html', '/srv/site') == 'wiki/x.html',
       "_rel_path single-slash file url -> relative")
    ck(vn._rel_path('file:///srv/site/a.html', '/srv/site') == 'a.html',
       "_rel_path file:// authority form -> relative")
    ck(vn._rel_path('file:/other/y.html', '/srv/site') == 'y.html',
       "_rel_path url outside root -> basename only")

    # classify: type=="error" -> one (path, normalized-message) key; type=="info" -> advisory
    # count (never gated); type=="non-document-error" -> a problem the caller fails on.
    messages = [
        {"type": "error", "url": "file:/r/a.html", "lastLine": 7,
         "message": 'Duplicate ID %sx%s.' % (_LDQUO, _RDQUO)},
        {"type": "info", "subType": "warning", "url": "file:/r/a.html",
         "message": "Section lacks heading."},
        {"type": "non-document-error", "url": "file:/r/b.html",
         "message": "Cannot read file."},
    ]
    keys, info, problems = vn.classify(messages, "/r")
    ck(keys == {("a.html", 'Duplicate ID "x".')}, "classify keys only type=error: %s" % keys)
    ck(info == 1, "classify counts info as advisory")
    ck(len(problems) == 1 and problems[0].startswith("b.html:"),
       "classify routes non-document-error to problems: %s" % problems)
    # line number is NOT in the key (it churns the baseline on unrelated edits above it).
    again = [{"type": "error", "url": "file:/r/a.html", "lastLine": 999,
              "message": 'Duplicate ID %sx%s.' % (_LDQUO, _RDQUO)}]
    ck(vn.classify(again, "/r")[0] == keys, "classify key ignores line number")
    ck(vn.classify([], "/r") == (set(), 0, []), "classify empty -> clean")

    # ignore: a listed built-tree path is EXCLUDED entirely -- its errors yield no key and its
    # non-document-errors yield no problem, while a non-ignored page is unaffected (deliberately
    # unmaintained pages, e.g. the outdated Dev meta-pages).
    mixed = [
        {"type": "error", "url": "file:/r/wiki/Dev/mediawiki.html",
         "message": 'Stray end tag "a".'},
        {"type": "non-document-error", "url": "file:/r/wiki/Dev/mediawiki.html",
         "message": "Cannot read file."},
        {"type": "error", "url": "file:/r/wiki/Keep.html", "message": 'Stray end tag "a".'},
    ]
    k_ig, _i, p_ig = vn.classify(mixed, "/r", ignore={"wiki/Dev/mediawiki.html"})
    ck(k_ig == {("wiki/Keep.html", 'Stray end tag "a".')},
       "classify ignore drops the ignored page's error key, keeps others: %s" % k_ig)
    ck(p_ig == [], "classify ignore drops the ignored page's problem: %s" % p_ig)
    # CANARY: without the ignore the same page IS checked (error key + problem present), so the
    # filter is load-bearing, not vacuous.
    k_no, _i2, p_no = vn.classify(mixed, "/r")
    ck(("wiki/Dev/mediawiki.html", 'Stray end tag "a".') in k_no and len(p_no) == 1,
       "canary: without ignore the page is checked (error key + problem present)")

    # parse_ignore: one path per line, blank/# skipped.
    ig = vn.parse_ignore("# hdr\n\nwiki/Dev/website.html\nwiki/Dev/mediawiki.html\n")
    ck(ig == {"wiki/Dev/website.html", "wiki/Dev/mediawiki.html"}, "parse_ignore: %s" % ig)

    # parse_baseline: skip blank/# lines; split path off, message is the remainder (may contain
    # spaces); a line with no message is a hard error (never silently 'no accepted violations').
    parsed = vn.parse_baseline('# c\n\nwiki/x.html Element "p" not allowed here\n')
    ck(parsed == {("wiki/x.html", 'Element "p" not allowed here')},
       "parse_baseline path + spaced message: %s" % parsed)
    try:
        vn.parse_baseline("loneword\n")
        ck(False, "parse_baseline rejects a message-less line")
    except ValueError:
        ck(True, "parse_baseline rejects a message-less line")

    # roundtrip: parse(format(x)) == x, deterministic.
    sample = {("a.html", 'Duplicate ID "x".'), ("b/c.html", 'Stray end tag "div".')}
    ck(vn.parse_baseline(vn.format_baseline(sample)) == sample, "format/parse roundtrip")
    ck(vn.format_baseline(set()).startswith("#"), "empty baseline is header-only (no body)")

    # evaluate: a NEW error (not baselined) fails; a baselined one passes; a resolved one is
    # reported not required; a MISSING baseline fails CLOSED even when the fresh set is empty.
    base = {("a.html", "err one"), ("a.html", "err two")}
    rc, new, resolved = vn.evaluate(True, base, {("a.html", "err one"), ("a.html", "err three")})
    ck(rc == 1 and new == [("a.html", "err three")] and resolved == [("a.html", "err two")],
       "evaluate: new fails, resolved reported: new=%s resolved=%s" % (new, resolved))
    rc2, new2, _ = vn.evaluate(True, base, {("a.html", "err one"), ("a.html", "err two")})
    ck(rc2 == 0 and new2 == [], "evaluate: fully-baselined set passes")
    rc3, new3, _ = vn.evaluate(False, set(), set())
    ck(rc3 == 1 and new3 == [], "evaluate: MISSING baseline fails CLOSED even on an empty fresh set")
    rc4, new4, _ = vn.evaluate(False, set(), {("a.html", "err one")})
    ck(rc4 == 1 and new4 == [("a.html", "err one")],
       "evaluate: MISSING baseline reports every fresh error as new")

    # _baseline_path: per-site file keyed by the checkout basename.
    from pathlib import Path
    ck(vn._baseline_path(Path("/bl"), "/x/output-lies.github.io")
       == Path("/bl/vnu-baseline-output-lies.github.io.txt"), "_baseline_path naming")

    # resolve_vnu: absent vnu/JRE -> None (an env-unmet SKIP, not a FAIL); _skip raises
    # SystemExit(77), the shared env-unmet contract.
    _saved = {k: os.environ.pop(k) for k in ("VNU_JAR", "VNU_CMD") if k in os.environ}
    os.environ["VNU_CMD"] = "vnu-definitely-absent-binary-xyzzy"
    try:
        ck(vn.resolve_vnu() is None, "resolve_vnu -> None when vnu is absent")
    finally:
        os.environ.pop("VNU_CMD", None)
        os.environ.update(_saved)
    try:
        vn._skip("canary")
        ck(False, "_skip raises SystemExit(77)")
    except SystemExit as exc:
        ck(exc.code == 77, "_skip raises SystemExit(77)")

    sys.stdout.write(
        "check_vnu_test: %d pass, %d fail, 0 skip\n" % (stats["pass"], stats["fail"]))
    return 1 if stats["fail"] else 0


if __name__ == "__main__":
    sys.exit(run())
