#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression tests for the Speculation Rules + View Transitions gate's pure (browser-free)
logic: the canonical-bytes/hash invariant, the JSON + CSS shape validators, the CDP-event
classifiers, and -- end to end against a built fixture tree -- site.check_speculation_rules /
site.check_view_transition. Every check is CANARY-RED: a page with the feature stripped (no
block, wrong rule, unhashed CSP, VT outside the motion guard) must FAIL. The functional
chromium/CDP proof itself runs in the check_webplatform.py browser lane (sandbox-delegated).
Run by the website-tests launcher (a required unit) or directly: ./check_webplatform_test.py"""
import base64
import hashlib
import os
import sys
import tempfile


def _load():
    _dp = os.path.normpath(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..', '..', 'lib', 'python3', 'dist-packages'))
    if os.path.isdir(_dp) and _dp not in sys.path:
        sys.path.insert(0, _dp)
    from dist_ai.webcheck import webplatform, site
    return webplatform, site


wp, site = _load()


# A minimal built page carrying BOTH features correctly: the CSP meta pins the frozen hash, the
# inline block is byte-identical, the stylesheet opts into VT inside the motion-welcome guard.
_GOOD_CSP = ("default-src 'none'; script-src 'self' '%s'; style-src 'self'; img-src 'self' "
             "data:; base-uri 'none'; form-action 'none'" % wp.SPEC_RULES_HASH)


def _page(csp=_GOOD_CSP, block=wp.SPECULATION_RULES_SCRIPT, css_href='/style.css'):
    link = '<link rel="stylesheet" href="%s">' % css_href if css_href else ''
    return ('<!DOCTYPE html>\n<html lang="en">\n<meta charset="utf-8">\n'
            '<meta http-equiv="Content-Security-Policy" content="%s">\n%s\n'
            '<title>t</title>\n%s\n<header>h</header>\n<footer>f</footer>\n'
            % (csp, link, block))


def _write_site(tmp, html, css=wp.VIEW_TRANSITION_CSS):
    root = os.path.join(tmp, 'site')
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, 'index.html'), 'w', encoding='utf-8') as fh:
        fh.write(html)
    if css is not None:
        with open(os.path.join(root, 'style.css'), 'w', encoding='utf-8') as fh:
            fh.write('body{color:#000}\n' + css + '\n')
    return root, [os.path.join(root, 'index.html')]


def run() -> int:
    stats = {"pass": 0, "fail": 0}

    def ck(cond, label):
        stats["pass" if cond else "fail"] += 1
        status = "pass" if cond else "FAIL"
        (sys.stdout if cond else sys.stderr).write(
            "check_webplatform_test: %s %s\n" % (status, label))

    # --- canonical bytes + hash invariant -------------------------------------------------- #
    want_hash = 'sha256-' + base64.b64encode(
        hashlib.sha256(wp.SPECULATION_RULES_JSON.encode()).digest()).decode()
    ck(wp.SPEC_RULES_HASH == want_hash, "SPEC_RULES_HASH is sha256 of the canonical JSON")
    ck(wp.SPECULATION_RULES_SCRIPT ==
       '<script type="speculationrules">%s</script>' % wp.SPECULATION_RULES_JSON,
       "canonical inline element wraps the canonical JSON")

    # --- speculation_block_bodies ---------------------------------------------------------- #
    ck(wp.speculation_block_bodies(wp.SPECULATION_RULES_SCRIPT) == [wp.SPECULATION_RULES_JSON],
       "finds the inline block body")
    ck(wp.speculation_block_bodies('<p>no block here</p>') == [],
       "no block -> empty (canary)")
    ck(wp.speculation_block_bodies(
        '<script type="speculationrules" src="/rules.json"></script>') == [],
       "external (src=) ruleset is not an inline body")
    ck(len(wp.speculation_block_bodies(
        wp.SPECULATION_RULES_SCRIPT + wp.SPECULATION_RULES_SCRIPT)) == 2,
       "two blocks both found")

    # --- speculation_json_ok --------------------------------------------------------------- #
    ck(wp.speculation_json_ok(wp.SPECULATION_RULES_JSON)[0] is True, "canonical JSON accepted")
    ck(wp.speculation_json_ok('  %s  ' % wp.SPECULATION_RULES_JSON)[0] is True,
       "surrounding whitespace tolerated for shape")
    ck(wp.speculation_json_ok('')[0] is False, "empty body rejected (canary)")
    ck(wp.speculation_json_ok('{not json')[0] is False, "invalid JSON rejected (canary)")
    ck(wp.speculation_json_ok(
        '{"prefetch":[{"where":{"and":[{"href_matches":"/*"},'
        '{"not":{"selector_matches":"[data-no-instant]"}}]},"eagerness":"eager"}]}')[0] is False,
       "wrong eagerness rejected (canary)")
    ck(wp.speculation_json_ok(
        '{"prefetch":[{"where":{"and":[{"href_matches":"/*"}]},'
        '"eagerness":"moderate"}]}')[0] is False,
       "missing [data-no-instant] clause rejected (canary)")
    ck(wp.speculation_json_ok(
        '{"prefetch":[{"where":{"and":[{"href_matches":"https://evil/*"},'
        '{"not":{"selector_matches":"[data-no-instant]"}}]},"eagerness":"moderate"}]}')[0] is False,
       "non-same-origin href_matches rejected (canary)")
    ck(wp.speculation_json_ok(
        '{"prefetch": [{"eagerness": "moderate", "where": {"and": [{"href_matches": "/*"}, '
        '{"not": {"selector_matches": "[data-no-instant]"}}]}}]}')[0] is False,
       "shape-equal but non-byte-identical rejected (hash would not match)")

    # --- view_transition_css_ok ------------------------------------------------------------ #
    ck(wp.view_transition_css_ok(wp.VIEW_TRANSITION_CSS) is True, "canonical VT CSS accepted")
    ck(wp.view_transition_css_ok('body{color:#000}\n' + wp.VIEW_TRANSITION_CSS) is True,
       "VT rule found amid other CSS")
    ck(wp.view_transition_css_ok('@view-transition { navigation: auto; }') is False,
       "top-level VT outside the motion guard rejected (canary)")
    ck(wp.view_transition_css_ok(
        '@media (prefers-reduced-motion: reduce) { @view-transition { navigation: auto; } }')
       is False, "VT inside a reduce block rejected (canary)")
    ck(wp.view_transition_css_ok(
        '/* @media (prefers-reduced-motion: no-preference) { @view-transition '
        '{ navigation: auto; } } */') is False, "commented-out VT rejected (canary)")
    ck(wp.view_transition_css_ok('html{scroll-behavior:smooth}') is False,
       "no VT rule rejected (canary)")

    # --- CDP event classifiers ------------------------------------------------------------- #
    accepted_ev = [{"ruleSet": {"sourceText": wp.SPECULATION_RULES_JSON}}]
    ck(wp.ruleset_accepted(accepted_ev)[0] is True, "ruleSetUpdated no-error -> accepted")
    ck(wp.ruleset_accepted([{"ruleSet": {"sourceText": wp.SPECULATION_RULES_JSON,
                                         "errorType": "InvalidRulesSkipped"}}])[0] is False,
       "ruleSetUpdated with errorType rejected (CSP-block canary)")
    ck(wp.ruleset_accepted([])[0] is False, "no ruleSetUpdated rejected (CSP-block canary)")
    ck(wp.ruleset_accepted([{"ruleSet": {"sourceText": '{"other":1}'}}])[0] is False,
       "a non-canonical ruleset is not our acceptance")
    ck(wp.prefetch_fired([{"status": "Running"}])[0] is True, "prefetch Running -> fired")
    ck(wp.prefetch_fired([{"status": "Success"}])[0] is True, "prefetch Success -> fired")
    ck(wp.prefetch_fired([])[0] is False, "no prefetch events rejected (canary)")
    ck(wp.prefetch_fired([{"status": "NotEligible"}])[0] is False,
       "prefetch non-live status rejected (canary)")

    # --- end-to-end against a built fixture tree (the REAL site.py gate) -------------------- #
    with tempfile.TemporaryDirectory() as tmp:
        root, pages = _write_site(tmp, _page())
        f = []
        site.check_speculation_rules(root, f, pages)
        site.check_view_transition(root, f, pages)
        ck(f == [], "good fixture: speculation + view-transition both clean (got %r)" % f)

        # Canary: strip the inline block.
        root, pages = _write_site(tmp + '/a', _page(block=''))
        f = []
        site.check_speculation_rules(root, f, pages)
        ck(any('no inline' in x for x in f), "missing speculationrules block -> FAIL (canary)")

        # Canary: block present but its hash NOT in the CSP (Chromium would block it).
        bad_csp = ("default-src 'none'; script-src 'self'; style-src 'self'; "
                   "base-uri 'none'; form-action 'none'")
        root, pages = _write_site(tmp + '/b', _page(csp=bad_csp))
        f = []
        site.check_speculation_rules(root, f, pages)
        ck(any('not pinned in CSP' in x for x in f),
           "speculationrules hash absent from CSP -> FAIL (canary)")

        # Canary: VT CSS stripped.
        root, pages = _write_site(tmp + '/c', _page(), css='body{color:#000}')
        f = []
        site.check_view_transition(root, f, pages)
        ck(any('View Transitions missing' in x for x in f),
           "missing @view-transition CSS -> FAIL (canary)")

        # Canary: results-plane page is exempt from the speculation-block requirement.
        res_dir = os.path.join(tmp, 'd', 'site', site.RESULTS_SUBDIR)
        os.makedirs(res_dir, exist_ok=True)
        with open(os.path.join(tmp, 'd', 'site', 'index.html'), 'w', encoding='utf-8') as fh:
            fh.write(_page())
        with open(os.path.join(res_dir, 'index.html'), 'w', encoding='utf-8') as fh:
            fh.write('<!DOCTYPE html>\n<html><meta charset="utf-8"><title>r</title>\n')
        rroot = os.path.join(tmp, 'd', 'site')
        f = []
        site.check_speculation_rules(
            rroot, f, [os.path.join(res_dir, 'index.html')])
        ck(f == [], "results-plane page exempt from the speculation-block requirement")

    sys.stdout.write("check_webplatform_test: %d pass, %d fail, 0 skip\n"
                     % (stats["pass"], stats["fail"]))
    return 1 if stats["fail"] else 0


if __name__ == "__main__":
    sys.exit(run())
