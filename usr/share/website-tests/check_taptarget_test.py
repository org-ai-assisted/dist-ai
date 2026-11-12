#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression tests for webcheck.taptarget's pure (browser-free) WCAG 2.5.8 engine: the
under-size test, the spacing exception (circle-vs-circle AND circle-vs-rect), the inline
exception (a standalone link fails; an inline / non-candidate one never does), and the whole
evaluate() verdict. No browser -- the geometry decisions run on hand-built records, exactly the
records the in-page extractor returns. Also canaries the extractor JS so the inline-exempt
selectors and the viewport sweep cannot be silently dropped.

Run by the website-tests launcher (a required unit) or directly: ./check_taptarget_test.py"""
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


def _rec(x, y, w, h, candidate=True, standalone=True, sel="a", href="/p"):
    return {"x": float(x), "y": float(y), "w": float(w), "h": float(h),
            "candidate": candidate, "standalone": standalone, "sel": sel, "href": href}


def run() -> int:
    stats = {"pass": 0, "fail": 0}

    def ck(cond, label):
        stats["pass" if cond else "fail"] += 1
        status = "pass" if cond else "FAIL"
        (sys.stdout if cond else sys.stderr).write("check_taptarget_test: %s %s\n" % (status, label))

    # --- is_undersized: below 24 on EITHER edge is undersized; >=24 both is not ---------------
    ck(tt.is_undersized(_rec(0, 0, 200, 20)), "200x20 is undersized (short height)")
    ck(tt.is_undersized(_rec(0, 0, 20, 200)), "20x200 is undersized (narrow width)")
    ck(not tt.is_undersized(_rec(0, 0, 24, 24)), "24x24 is NOT undersized")
    ck(not tt.is_undersized(_rec(0, 0, 200, 24)), "200x24 is NOT undersized")

    # --- _circle_hits_rect: a 24px circle (radius 12) reaching into a box ----------------------
    # a point 10px from a box edge is inside a radius-12 circle; 20px away is outside.
    box = _rec(100, 100, 40, 40)
    ck(tt._circle_hits_rect(90, 120, 12.0, box), "circle 10px from box edge intersects")
    ck(not tt._circle_hits_rect(80, 120, 12.0, box), "circle 20px from box edge misses")

    # --- well_spaced: isolated small link passes; crowded one does not -------------------------
    lone = _rec(0, 0, 100, 20)
    ck(tt.well_spaced(lone, [lone]), "an isolated undersized link is well-spaced (passes)")
    # two undersized links whose CENTRES are < 24px apart -> circles intersect -> not well-spaced.
    a = _rec(0, 0, 100, 20)      # centre (50,10)
    b = _rec(0, 15, 100, 20)     # centre (50,25) -> 15px below -> < 24 -> crowded
    ck(not tt.well_spaced(a, [a, b]), "two undersized links 15px apart are not well-spaced")
    # push them to >=24px centre distance -> circle-circle clears; boxes must also clear.
    far = _rec(0, 40, 100, 20)   # centre (50,50) -> 40px below a's centre
    ck(tt.well_spaced(a, [a, far]), "two undersized links 40px apart are well-spaced")

    # --- evaluate(): the full verdict ----------------------------------------------------------
    # Standalone + undersized + crowded -> FAIL (both of the mutual pair).
    crowd = [_rec(34, 13004, 106, 20, href="/A"), _rec(61, 13014, 106, 20, href="/B")]
    fails = tt.evaluate(crowd)
    ck(len(fails) == 2, "two crowded standalone undersized links both FAIL (got %d)" % len(fails))

    # The SAME pair padded to 24px tall (the fix: fill the 24px line box) -> no longer undersized
    # -> PASS, even though still close. This is the canary that mirrors the real style.css fix.
    padded = [_rec(34, 13004, 106, 24, href="/A"), _rec(61, 13012, 106, 24, href="/B")]
    ck(tt.evaluate(padded) == [], "the same pair at 24px tall PASSES (the padding fix)")

    # Inline (in-sentence) link: undersized + crowded but standalone=False -> EXEMPT, never fails.
    inline = [_rec(34, 100, 40, 20, standalone=False, href="/x"),
              _rec(61, 108, 40, 20, standalone=False, href="/y")]
    ck(tt.evaluate(inline) == [], "inline (sentence) undersized links are WCAG-exempt (pass)")

    # A non-candidate neighbour (a nav/button target) is never itself a failure, but DOES crowd a
    # standalone candidate (so the exempt markers dev1497 owns still count for spacing).
    cand = _rec(0, 0, 40, 20, candidate=True, standalone=True, href="/c")  # centre (20,10)
    nbr = _rec(28, 0, 24, 24, candidate=False, standalone=False, href="#mark")  # box 8px from centre
    fails2 = tt.evaluate([cand, nbr])
    ck([f["href"] for f in fails2] == ["/c"],
       "a non-candidate neighbour crowds the candidate but is not itself flagged")

    # Crowding is purely geometric (destination-independent): the icon+text and gallery pairs are
    # sized by CSS, so the engine does not special-case same-href links. Two crowded standalone
    # undersized links both FAIL regardless of href.
    crowded = [_rec(0, 0, 40, 20, href="/same"), _rec(0, 8, 40, 20, href="/same")]
    ck(len(tt.evaluate(crowded)) == 2, "two crowded standalone undersized links both FAIL")
    # A size-adequate link (>=24x24) passes even when crowded -- the CSS fix lifts the real cases.
    sized = [_rec(0, 0, 40, 24, href="/a"), _rec(0, 8, 40, 24, href="/b")]
    ck(tt.evaluate(sized) == [], "a crowded but >=24x24 standalone link passes (size route)")

    # Neighbour set is drawn from the content SCOPE, not document-wide (chrome overlays excluded).
    ck("SCOPE.querySelectorAll(INTERACTIVE)" in tt.TAPTARGET_JS,
       "spacing neighbours are scoped to the content region")

    # An isolated standalone undersized link (no neighbour within 24px) PASSES (spacing exception).
    solo = [_rec(0, 0, 100, 20, href="/solo"), _rec(0, 200, 100, 20, href="/other")]
    ck(tt.evaluate(solo) == [], "isolated standalone undersized links pass (well-spaced)")

    # --- extractor JS canaries: the inline exemptions + dual viewport cannot silently vanish ---
    for marker in ("sup", ".reference", ".mw-cite-backlink", ".mw-editsection",
                   ".ext-link-to-archive"):
        ck(marker in tt.TAPTARGET_JS,
           "extractor excludes inline marker %s from candidacy" % marker)
    ck("closest(EXEMPT_MARKER)" in tt.TAPTARGET_JS, "extractor applies the marker exclusion")
    ck("summary" in tt.TAPTARGET_JS, "a native <summary> disclosure is a spacing neighbour")
    # Visibility excludes a target under an opacity:0 ancestor (opacity is not inherited, so a
    # per-element opacity test misses an inactive tab/accordion panel left in flow). shown() runs
    # in-browser, so this canaries the ancestor walk cannot be silently dropped.
    ck("hiddenByAncestorOpacity" in tt.TAPTARGET_JS,
       "extractor excludes targets under an opacity:0 ancestor")
    # Standalone classification reads RENDERED text (innerText), so a display:none/script/style
    # sibling does not count as sentence text and wrongly exempt a stacked link.
    ck("block.innerText" in tt.TAPTARGET_JS,
       "standalone text uses rendered innerText, not raw textContent")
    vnames = [n for n, _, _ in tt.VIEWPORTS]
    ck("mobile" in vnames and "desktop" in vnames,
       "measures BOTH a mobile and a desktop viewport")
    ck(abs(tt.MIN_PX - 24.0) < 1e-9, "the WCAG 2.5.8 minimum is 24 CSS px")

    # The per-(page,viewport) outer wall-clock MUST exceed the 45s inner goto budget with headroom
    # for the post-nav force-lazy + settle + evaluates, else a page whose networkidle lands near 45s
    # is cancelled before its successful measurement and falsely reported "wedged".
    ck(tt.HARD_TIMEOUT > 45, "per-page timeout has headroom over the 45s goto budget")

    # _skip raises SystemExit(77) (the shared env-unmet contract).
    try:
        tt._skip("canary")
        ck(False, "_skip raises SystemExit(77)")
    except SystemExit as exc:
        ck(exc.code == 77, "_skip raises SystemExit(77)")

    sys.stdout.write("check_taptarget_test: %d pass, %d fail, 0 skip\n"
                     % (stats["pass"], stats["fail"]))
    return 1 if stats["fail"] else 0


if __name__ == "__main__":
    sys.exit(run())
