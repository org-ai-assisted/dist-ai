#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Browser-backed regression for webcheck.mobile's broken-image probe (_BROKEN_IMG_JS) -- the half
check_mobile_test.py cannot reach, because the defect is a cross-ENGINE behaviour only a real
WebKit exhibits. Runs the REAL _BROKEN_IMG_JS (imported, never copied) against crafted HTML via
Playwright, on webkit AND chromium.

Regression target: a loading=lazy image carrying a srcset, inside a display:none subtree (an
inactive GUI/CLI tab cell -- exactly the live wiki ISO page), is reported img.complete===true with
naturalWidth===0 and currentSrc=='' by WebKit, while Blink/Gecko report complete===false for the
same image. So `complete && naturalWidth===0` ALONE false-flags every such image as broken on
WebKit -- the live ISO page produced 12+ phantom broken-image findings (all currentSrc==''), none
real (each decodes fine once scrolled into view). The fix gates the condition on a non-empty
currentSrc: an unfetched image has currentSrc=='' on every engine, while a genuine 404/decode break
sets currentSrc to the selected URL, so the guard is a no-op on Blink/Gecko and removes the WebKit
false positive without dropping any real break.

Asserts, on each engine:
  - the hidden+lazy+srcset image with a VALID (200) src -> NOT flagged (the WebKit false positive)
  - an eager image whose src 404s                       -> flagged (the fix must not over-exclude)

--old-js drives the pre-fix condition instead (a durable self-canary: it must FAIL on webkit,
proving the fixture + assertions still have teeth).

Needs Playwright + chromium + webkit, so it SKIPs(77) when absent (the sandbox harness maps that to
a failure, since the gate must actually run there). Trailing site-root args (the sandbox harness
passes them) are accepted and ignored -- this test serves its own fixtures.

Run in the sandbox (website-tests-sandbox wires it to the Playwright venv python); directly:
  /home/user/.venvs/web-render/bin/python ./check_broken_img_js_test.py
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
    from dist_ai.webcheck import mobile
    return mobile


mob = _load()


def _skip(reason):
    sys.stderr.write("check_broken_img_js_test: SKIP (%s)\n" % reason)
    ## style-ok: allow-skip: env-unmet -- Playwright/chromium/webkit absent; the sandbox harness maps 77 to a failure so the browser gate cannot silently pass
    raise SystemExit(77)


# 1x1 opaque PNG (the VALID image body the route serves for okimage).
_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0bIDATx\xdac\xf8\xcf\xc0"
    b"\xf0\x1f\x00\x03\x01\x01\x00\x18\xdd\x8d\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)

# eager image that 404s (a genuine break, must stay flagged) + a lazy+srcset image inside a
# display:none cell (the WebKit complete===true / currentSrc='' false positive, must NOT be
# flagged). Distinct path tokens 'okimage' / 'gone404' so the route's substring match is exact.
_HTML = (
    "<!doctype html><html><head><meta charset=utf-8></head><body>"
    "<img id=eager404 src='https://example.test/gone404.png' "
    "width=50 height=50 alt='real-404'>"
    "<div style='display:none'>"
    "<img loading=lazy width=356 height=227 alt='lazy-valid' "
    "src='https://example.test/okimage.avif' "
    "srcset='https://example.test/thumb/okimage-160.avif 160w, "
    "https://example.test/okimage.avif 356w' sizes='auto, 356px'>"
    "</div></body></html>"
)

# Pre-fix condition, for --old-js (the self-canary).
_OLD_JS = r"""
() => {
  var out = [];
  Array.prototype.forEach.call(document.querySelectorAll('img'), function (img) {
    var src = img.currentSrc || img.getAttribute('src') || '';
    if (/\.svgz?(\?|#|$)/i.test(src)) return;
    if (img.complete && img.naturalWidth === 0) {
      out.push({ src: (src || '(inline)').slice(-80), alt: (img.alt || '').slice(0, 40) });
    }
  });
  return out.slice(0, 12);
}
"""

ENGINES = ("chromium", "webkit")


async def _route(route):
    url = route.request.url
    if url.endswith("page.html"):
        await route.fulfill(status=200, content_type="text/html", body=_HTML)
    elif "okimage" in url:
        await route.fulfill(status=200, content_type="image/png", body=_PNG)
    elif "gone404" in url:
        await route.fulfill(status=404, content_type="text/plain", body=b"nope")
    else:
        await route.continue_()


async def _flagged_alts(p, engine, js):
    browser = await getattr(p, engine).launch()
    try:
        page = await browser.new_page(viewport={"width": 390, "height": 800})
        await page.route("**/*", _route)
        await page.goto("https://example.test/page.html", wait_until="networkidle",
                        timeout=30000)
        await page.wait_for_timeout(500)
        flagged = await page.evaluate(js)
        return sorted({r.get("alt", "") for r in flagged})
    finally:
        await browser.close()


async def _amain(old_js):
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        _skip("playwright not importable")

    js = _OLD_JS if old_js else mob._BROKEN_IMG_JS
    bad = False
    async with async_playwright() as p:
        for eng in ENGINES:
            try:
                flagged = await _flagged_alts(p, eng, js)
            except Exception as exc:  # noqa: BLE001 -- a wedge is a failure, never a silent green
                launch = ("executable doesn't exist" in str(exc)
                          or "Executable doesn't exist" in str(exc))
                if launch:
                    _skip("engine %s not installed: %s" % (eng, exc))
                sys.stderr.write("check_broken_img_js_test: WEDGE %s: %s: %s\n"
                                 % (eng, type(exc).__name__, exc))
                return 2
            lazy_fp = "lazy-valid" in flagged         # must be False (the WebKit regression)
            missed = "real-404" not in flagged        # must be False (over-exclusion)
            ok = (not lazy_fp) and (not missed)
            sys.stderr.write("check_broken_img_js_test: [%s] %s flagged=%s "
                             "lazy_false_pos=%s real_404_missed=%s\n"
                             % (eng, "pass" if ok else "FAIL", flagged, lazy_fp, missed))
            if not ok:
                bad = True
    return 1 if bad else 0


def main(argv):
    old_js = "--old-js" in argv
    rc = asyncio.run(_amain(old_js))
    if old_js:
        # Self-canary: the pre-fix condition MUST be caught (non-zero) -- a 0 here means the
        # fixture or the assertions lost their teeth, which is itself a failure.
        if rc == 0:
            sys.stderr.write("check_broken_img_js_test: --old-js SELF-CANARY DEFEATED -- the "
                             "pre-fix condition was not caught; fixture/assertions are toothless\n")
            return 1
        sys.stderr.write("check_broken_img_js_test: --old-js self-canary OK "
                         "(pre-fix condition correctly caught)\n")
        return 0
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
