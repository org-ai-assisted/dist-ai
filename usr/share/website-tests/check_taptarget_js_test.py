#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Browser-backed regression for webcheck.taptarget's IN-PAGE extractor (TAPTARGET_JS) -- the half
check_taptarget_test.py cannot reach, because the standalone/inline classification depends on real
chromium innerText semantics. Runs the REAL TAPTARGET_JS (imported, never copied) against crafted
HTML via Playwright set_content, then feeds the extracted records through the REAL evaluate().

Regression target (CodeRabbit r4546562043, PR #841): the classifier subtracted EVERY anchor's
innerText from the block's innerText to size the non-link 'sentence' text. block.innerText (a
rendered block) EXCLUDES a display:none descendant, but x.innerText on a display:none anchor returns
its RAW descendant text content -- so a hidden anchor was subtracted though it was never in the
block, driving nonLink negative and wrongly marking in-sentence links standalone. Two crowded
undersized sentence links then read as FALSE WCAG-2.5.8 violations. The fix counts an anchor toward
link-text only when it is actually rendered in the block (not inside a display:none subtree) -- and,
conversely, a boxless display:contents anchor whose text IS rendered stays counted.

Needs Playwright + chromium, so it SKIPs(77) when absent (the sandbox harness maps that to a
failure, since the gate must actually run there). Trailing site-root args (the sandbox harness
passes them) are accepted and ignored -- this test serves its own set_content fixtures.

Run in the sandbox (website-tests-sandbox wires it to the Playwright venv python); directly:
  /home/user/.venvs/web-render/bin/python ./check_taptarget_js_test.py
"""
import asyncio
import os
import sys


def _load():
    _dp = os.path.normpath(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..', '..', 'lib', 'python3', 'dist-packages'))
    if os.path.isdir(_dp) and _dp not in sys.path:
        sys.path.insert(0, _dp)
    from dist_ai.webcheck import taptarget
    return taptarget


tt = _load()


def _skip(reason):
    sys.stderr.write("check_taptarget_js_test: SKIP (%s)\n" % reason)
    ## style-ok: allow-skip: env-unmet -- Playwright/chromium absent; the sandbox harness maps 77 to a failure so the browser gate cannot silently pass
    raise SystemExit(77)


# A link-only block (no sentence text around the links) is STANDALONE; an in-sentence link is
# INLINE (WCAG-exempt). The hidden anchor in BUG_HTML has RAW innerText far longer than the visible
# sentence -- on the OLD code it drives nonLink negative and flips the two visible sentence links to
# standalone, so the crowded undersized pair reads as a violation. Tiny font so the visible links
# are genuinely undersized (<24px) and the A/B pair is crowded.
BUG_HTML = """<!doctype html><meta charset="utf-8">
<style>body{font:10px/12px sans-serif}</style>
<p>See <a href="/A">A</a>/<a href="/B">B</a>.
<a href="/hidden" style="display:none">hiddenlabeltextlonger</a></p>"""

# Positive control: a link-only list item stays standalone (the fix must not blanket-exempt).
STANDALONE_HTML = """<!doctype html><meta charset="utf-8">
<ul><li><a href="/C">Clink</a></li></ul>"""

# opacity:0 control: an opacity:0 anchor DOES contribute to block.innerText, so its text must still
# be subtracted. A box/shown()-based guard would drop opacity:0, so the opaque sibling's text would
# wrongly count as sentence text and flip /D off standalone. With the opaque text subtracted, the
# block is link-only -> /D is standalone.
OPACITY_HTML = """<!doctype html><meta charset="utf-8">
<p><a href="/D">Dvis</a> <a href="/opaque" style="opacity:0">opaquetext</a></p>"""

# display:contents control (CodeRabbit r4546562043 / grok follow-up): a display:contents anchor has
# NO box (getClientRects empty) but its text IS rendered into the block's innerText. It must stay
# subtracted; a getClientRects/box-based guard drops it, over-counting nonLink and FALSELY exempting
# the real standalone links /E and /F. With the contents label subtracted, the <li> is link-only ->
# /E and /F are standalone (not inline-exempt).
CONTENTS_HTML = """<!doctype html><meta charset="utf-8">
<style>body{font:10px/12px sans-serif}</style>
<ul><li><a href="/L" style="display:contents">VisibleLabel</a><a href="/E">E</a><a href="/F">F</a></li></ul>"""


async def _records(page, html):
    await page.set_content(html, wait_until="load")
    return await page.evaluate(tt.TAPTARGET_JS)


def _by_href(records, href):
    for rec in records:
        if rec.get("href") == href:
            return rec
    return None


async def _run_async(stats):
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        _skip("python3-playwright not installed: %s" % exc)

    def ck(cond, label):
        stats["pass" if cond else "fail"] += 1
        status = "pass" if cond else "FAIL"
        (sys.stdout if cond else sys.stderr).write(
            "check_taptarget_js_test: %s %s\n" % (status, label))

    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch()
        except Exception as exc:              # noqa: BLE001 -- engine not installed/launchable
            _skip("chromium engine unavailable: %s" % exc)
        page = await browser.new_page(viewport={"width": 390, "height": 844})
        try:
            # --- the bug fixture: a display:none anchor must NOT corrupt the count ---------------
            recs = await _records(page, BUG_HTML)
            a_rec = _by_href(recs, "/A")
            b_rec = _by_href(recs, "/B")
            ck(a_rec is not None and b_rec is not None,
               "both visible sentence links /A and /B are extracted as candidates")
            if a_rec and b_rec:
                ck(a_rec.get("candidate") and b_rec.get("candidate"),
                   "/A and /B are content-link candidates")
                # The core regression: a display:none anchor's raw innerText must not flip these
                # in-sentence links to standalone. OLD code -> standalone True (nonLink negative).
                ck(a_rec.get("standalone") is False and b_rec.get("standalone") is False,
                   "in-sentence links stay inline-exempt despite a display:none anchor")
            # End to end through the real engine: no false WCAG-2.5.8 violation. OLD code flags the
            # crowded undersized pair as two standalone violations.
            fails = tt.evaluate(recs)
            ck(fails == [],
               "no false violation for a sentence with a hidden anchor (got %d)" % len(fails))

            # --- positive control: a link-only list item is still standalone --------------------
            recs2 = await _records(page, STANDALONE_HTML)
            c_rec = _by_href(recs2, "/C")
            ck(c_rec is not None and c_rec.get("standalone") is True,
               "a link-only list item is still classified standalone (no over-correction)")

            # --- opacity:0 control: an opacity:0 sibling's text is still subtracted -------------
            recs3 = await _records(page, OPACITY_HTML)
            d_rec = _by_href(recs3, "/D")
            ck(d_rec is not None and d_rec.get("standalone") is True,
               "an opacity:0 anchor still counts toward link-text (block reads link-only)")

            # --- display:contents control: a boxless-but-rendered anchor is still subtracted ----
            recs4 = await _records(page, CONTENTS_HTML)
            e_rec = _by_href(recs4, "/E")
            f_rec = _by_href(recs4, "/F")
            ck(e_rec is not None and f_rec is not None
               and e_rec.get("standalone") is True and f_rec.get("standalone") is True,
               "a display:contents anchor still counts toward link-text (links stay standalone)")
        finally:
            try:
                await asyncio.wait_for(browser.close(), timeout=5)
            except Exception:
                pass


def run():
    stats = {"pass": 0, "fail": 0}
    asyncio.run(_run_async(stats))
    sys.stdout.write("check_taptarget_js_test: %d pass, %d fail, 0 skip\n"
                     % (stats["pass"], stats["fail"]))
    return 1 if stats["fail"] else 0


if __name__ == "__main__":
    sys.exit(run())
