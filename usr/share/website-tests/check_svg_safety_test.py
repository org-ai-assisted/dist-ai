#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Regression tests for webcheck.svg_safety (the SVG active-content gate). Run by the
website-tests launcher (a required unit) or directly: ./check_svg_safety_test.py

CANARY: a construct-free SVG MUST pass, and each dangerous construct MUST be flagged -- a scanner
that passes everything (0 fail) has 0 coverage. Every malicious fixture below is asserted to fail,
and the clean one to pass, so weakening the detector re-fails this test. The fixtures past the
plain MALICIOUS dict each reproduce a verified fail-open BYPASS (encoding / case / .svgz / CSS
escape / <style> child-tail / image-set / presentation-attr url() / animate from / xml:base /
missing-target) so a regression reopening any of them re-fails here."""
import gzip
import os
import sys
import tempfile
from pathlib import Path


def _load():
    # the scan logic lives in the importable core; import it (its real home).
    # Prepend this tree's dist-packages (checkout case); no-op when installed.
    _dp = os.path.normpath(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..', '..', 'lib', 'python3', 'dist-packages'))
    if os.path.isdir(_dp) and _dp not in sys.path:
        sys.path.insert(0, _dp)
    from dist_ai.webcheck import svg_safety
    return svg_safety


svgsafe = _load()

_SVG = 'xmlns="http://www.w3.org/2000/svg"'
_XL = 'xmlns:xlink="http://www.w3.org/1999/xlink"'

# A clean, construct-free SVG (the canary: must stay PASS).
CLEAN = f'<svg {_SVG} {_XL} width="10" height="10"><rect width="10" height="10" fill="#333"/>' \
        '<a xlink:href="https://example.test/ok"><text>hi</text></a>' \
        '<rect fill="url(#grad)"/>' \
        '<image xlink:href="data:image/png;base64,AAAA"/></svg>'

# name -> (svg source, substring expected in the flagged issue)
MALICIOUS = {
    "script": (f'<svg {_SVG}><script>alert(1)</script></svg>', "<script>"),
    "onload": (f'<svg {_SVG} onload="alert(1)"><rect/></svg>', "onload="),
    "onclick-nested": (f'<svg {_SVG}><rect onclick="x()"/></svg>', "onclick="),
    "js-href": (f'<svg {_SVG} {_XL}><a xlink:href="javascript:alert(1)"><text>x</text></a></svg>',
                "unsafe URL"),
    "data-html-href": (f'<svg {_SVG} {_XL}><a xlink:href="data:text/html;base64,'
                       'PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="><text>x</text></a></svg>',
                       "unsafe URL"),
    "data-svg-href": (f'<svg {_SVG} {_XL}><image xlink:href="data:image/svg+xml,%3Csvg%3E"/></svg>',
                      "unsafe URL"),
    "foreignobject": (f'<svg {_SVG}><foreignObject><p>x</p></foreignObject></svg>', "foreignobject"),
    "xhtml-ns": (f'<svg {_SVG}><body xmlns="http://www.w3.org/1999/xhtml">x</body></svg>',
                 "disallowed namespace"),
    "animate-href": (f'<svg {_SVG}><a><animate attributeName="href" to="javascript:alert(1)"/></a>'
                     '</svg>', "animated"),
    "animate-onbegin": (f'<svg {_SVG}><set attributeName="onload" to="alert(1)"/></svg>',
                        "animated script/href"),
    "handler": (f'<svg {_SVG}><handler>alert(1)</handler></svg>', "<handler>"),
    "xml-stylesheet-pi": (f'<?xml-stylesheet href="x.css"?><svg {_SVG}><rect/></svg>',
                          "xml-stylesheet"),
    "entity-bomb": ('<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY a "x">]>'
                    f'<svg {_SVG}><text>&a;</text></svg>', "forbidden XML construct"),
    "external-dtd": ('<?xml version="1.0"?>'
                     '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" '
                     '"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">'
                     f'<svg {_SVG}><rect/></svg>', "external DTD"),
    "style-remote": (f'<svg {_SVG}><style>@import url(https://evil.test/x.css);</style></svg>',
                     "remote url()/@import"),
    # --- verified fail-open bypasses now closed ---
    "css-escape-import": (f'<svg {_SVG}><style>@\\69mport "https://evil.test/x.css";</style></svg>',
                          "remote url()"),
    "css-escape-url": (f'<svg {_SVG}><rect style="fill:url(\\68ttps://evil.test/f.svg)"/></svg>',
                       "remote url"),
    "style-child-tail": (f'<svg {_SVG}><style>x<g/>@import "https://evil.test/x.css";</style></svg>',
                         "remote url()"),
    "image-set": (f'<svg {_SVG}><rect style="background-image:image-set('
                  "'https://evil.test/t.png' 1x)\"/></svg>", "image-set"),
    "fill-remote-url": (f'<svg {_SVG}><rect fill="url(https://evil.test/f.svg#a)"/></svg>',
                        "remote url()"),
    "filter-remote-url": (f'<svg {_SVG}><rect filter="url(https://evil.test/f.svg#a)"/></svg>',
                          "remote url()"),
    "animate-from-remote": (f'<svg {_SVG}><set attributeName="filter" '
                            'from="url(https://evil.test/f.svg)" to="url(#x)"/></svg>',
                            "animated to a remote"),
    "xml-base": (f'<svg {_SVG} xml:base="https://evil.test/"><rect/></svg>', "xml:base"),
    # --- round-2 bypasses (CSS line-continuation / comment / whitespace-split / image-set /
    #     protocol-relative / animated handler+base) now closed ---
    "css-linecont-style": (f'<svg {_SVG}><style>rect{{fill:url("ht\\\ntps://evil.test/f.svg")}}'
                           '</style></svg>', "remote url"),
    "css-comment-url": (f'<svg {_SVG}><rect style="background:url(/*x*/\'//evil.test/x.png\')"/>'
                        '</svg>', "remote url"),
    "attr-charref-tab": (f'<svg {_SVG}><rect fill="url(ht&#9;tps://evil.test/f.svg)"/></svg>',
                         "remote url"),
    "image-set-attr": (f'<svg {_SVG}><rect cursor="image-set(\'https://evil.test/c.png\' 1x)"/>'
                       '</svg>', "image-set"),
    "handler-protorel": (f'<svg {_SVG}><rect handler="//evil.test/x"/></svg>', "handler="),
    "animate-handler": (f'<svg {_SVG}><set attributeName="handler" to="//evil.test/x"/></svg>',
                        "handler"),
    "animate-xmlbase": (f'<svg {_SVG}><set attributeName="xml:base" to="https://evil.test/"/></svg>',
                        "animated"),
    # --- round-3 bypasses (CSS fake-comment hide / backslash-as-slash) now closed ---
    "css-comment-hide": (f'<svg {_SVG}><style>rect{{foo:"/*";fill:url(https://evil.test/f.svg#g);'
                         'bar:"*/"}}</style></svg>', "remote url"),
    "css-backslash-slash": (f'<svg {_SVG}><rect fill="url(/\\evil.test/f.svg#g)"/></svg>',
                            "remote url"),
    # --- trojan-source bidi/format controls (unicode-gate excludes SVG, so this gate owns them) ---
    # A raw RLO (U+202E) in text content reorders what a human reads; written via chr() so THIS
    # test source stays ASCII (the byte lands only in the on-disk fixture).
    "bidi-rlo": (f'<svg {_SVG}><text>{chr(0x202e)}evil</text></svg>', "trojan-source bidi"),
    "bidi-isolate": (f'<svg {_SVG}><text>a{chr(0x2067)}b{chr(0x2069)}</text></svg>',
                     "trojan-source bidi"),
    # Char-reference bypass: &#x202e; / &#8238; carry NO literal control byte (raw scan is
    # blind), but the XML parser + browser expand them to U+202E and reorder the text.
    "bidi-charref-hex": (f'<svg {_SVG}><text>&#x202e;evil</text></svg>', "via character reference"),
    "bidi-charref-dec": (f'<svg {_SVG}><text>a&#8238;b</text></svg>', "via character reference"),
    # CSS comment stripping is not string-aware, so a /* inside a string + */ in a later string
    # must NOT let the stripper delete a real url() between them (the decoded, non-comment-stripped
    # variant must still catch the live url).
    "css-fake-comment-string": (
        f'<svg {_SVG}><style>a{{p:"/*"}}b{{background:url(http://evil.test/hit)}}c{{q:"*/"}}'
        '</style></svg>', "remote url"),
    # a hex-escaped backslash host decodes to a double-backslash host, which WHATWG URL parsing on
    # an http(s) base treats as //host and fetches -- the gate must fold decoded backslashes to
    # slashes before matching. 6-digit \\00005c escapes are unambiguous (a bare \\5c would greedily
    # eat the following hex letter of "evil").
    "css-escaped-backslash-host": (
        f'<svg {_SVG}><rect style="background:url(' + chr(0x5c) + '00005c' + chr(0x5c)
        + '00005cevil.test/hit)"/></svg>', "remote url"),
    "malformed": (f'<svg {_SVG}><rect>', "malformed XML"),
}


def run() -> int:
    stats = {"pass": 0, "fail": 0}

    def ck(cond: bool, label: str) -> None:
        stats["pass" if cond else "fail"] += 1
        status = "pass" if cond else "FAIL"
        (sys.stdout if cond else sys.stderr).write(
            f"check_svg_safety_test: {status} {label}\n")

    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        clean = root / "clean.svg"
        clean.write_text(CLEAN, encoding="utf-8")
        ck(svgsafe.scan_svg(clean) == [], f"clean SVG passes (canary): {svgsafe.scan_svg(clean)}")

        for name, (src, want) in MALICIOUS.items():
            p = root / f"{name}.svg"
            p.write_text(src, encoding="utf-8")
            issues = svgsafe.scan_svg(p)
            hit = any(want in i for i in issues)
            ck(hit, f"{name}: flagged ({want!r}); got {issues}")

        # Encoding bypass: a UTF-16 SVG whose <script> the raw-text scans cannot see -> REFUSED.
        u16 = root / "u16.svg"
        u16.write_bytes(f'<svg {_SVG}><script>alert(1)</script></svg>'.encode("utf-16"))
        ck(any("NUL" in i or "UTF" in i for i in svgsafe.scan_svg(u16)),
           f"utf-16 SVG refused: {svgsafe.scan_svg(u16)}")

        # .svgz (gzip) is decompressed and scanned -> the inner <script> is caught.
        svgz = root / "evil.svgz"
        svgz.write_bytes(gzip.compress(f'<svg {_SVG}><script>alert(1)</script></svg>'.encode()))
        ck(any("<script>" in i for i in svgsafe.scan_svg(svgz)),
           f".svgz decompressed+scanned: {svgsafe.scan_svg(svgz)}")

        # A corrupt .svgz raises zlib.error (not OSError) -- it must be REPORTED, not crash the scan.
        corrupt = root / "corrupt.svgz"
        corrupt.write_bytes(b"\x1f\x8b\x08\x00" + b"\xff" * 12)
        ck(any("gzip" in i for i in svgsafe.scan_svg(corrupt)),
           f"corrupt .svgz reported, not raised: {svgsafe.scan_svg(corrupt)}")

        # A multi-member .svgz (clean member + malicious member) -- a browser decompresses BOTH, so
        # the first-member-only scan must REFUSE it, not pass on the clean first member.
        multi = root / "multi.svgz"
        multi.write_bytes(gzip.compress(f'<svg {_SVG}><rect/></svg>'.encode())
                          + gzip.compress(f'<svg {_SVG}><script>x</script></svg>'.encode()))
        ck(any("gzip" in i for i in svgsafe.scan_svg(multi)),
           f"multi-member .svgz refused: {svgsafe.scan_svg(multi)}")

        # Trojan-source bidi: LEGITIMATE non-ASCII text (accented label) must stay CLEAN -- the
        # bidi gate rejects only the format controls, never the glyphs SVG media legitimately
        # carries (why SVG is excluded from the ASCII-only unicode-gate). chr() keeps this source
        # ASCII; the real bytes land only on disk.
        accented = root / "accented.svg"
        accented.write_text(
            f'<svg {_SVG}><text>caf{chr(0xe9)} r{chr(0xe9)}sum{chr(0xe9)}</text></svg>',
            encoding="utf-8")
        ck(svgsafe.scan_svg(accented) == [],
           f"legit accented SVG text stays clean: {svgsafe.scan_svg(accented)}")
        # ...but a bidi control hidden inside a .svgz (gunzipped, then text-scanned) is caught.
        bidiz = root / "bidi.svgz"
        bidiz.write_bytes(gzip.compress(
            f'<svg {_SVG}><text>{chr(0x202e)}evil</text></svg>'.encode()))
        ck(any("trojan-source bidi" in i for i in svgsafe.scan_svg(bidiz)),
           f"bidi control in .svgz caught: {svgsafe.scan_svg(bidiz)}")

    # Discovery: case-variant .SVG and .svgz in a directory must BOTH be found (not skipped),
    # so main() returns 1 (not "0 SVG(s) clean").
    with tempfile.TemporaryDirectory() as d:
        dd = Path(d)
        (dd / "Evil.SVG").write_text(f'<svg {_SVG} onload="x()"><rect/></svg>', encoding="utf-8")
        ck(svgsafe.main([str(dd)]) == 1, "case-variant .SVG discovered + flagged")
    with tempfile.TemporaryDirectory() as d:
        dd = Path(d)
        (dd / "e.svgz").write_bytes(gzip.compress(f'<svg {_SVG}><script>x</script></svg>'.encode()))
        ck(svgsafe.main([str(dd)]) == 1, ".svgz discovered + flagged")

    # Fail-closed: a non-existent scan target is an ERROR (never "0 SVG(s) clean").
    ck(svgsafe.main(["/nonexistent/path/xyz"]) == 1, "missing target fails closed")
    ck(svgsafe.main(["-weird-name.svg"]) == 1, "a '-'-prefixed missing target is NOT dropped")

    # main(): exit 1 on a tree containing a bad SVG, 0 on a clean-only tree, 2 on no args.
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "bad.svg").write_text(f'<svg {_SVG}><script>x</script></svg>', encoding="utf-8")
        ck(svgsafe.main([str(root)]) == 1, "main() returns 1 when the tree has unsafe SVGs")
    with tempfile.TemporaryDirectory() as d2:
        cleanroot = Path(d2)
        (cleanroot / "a.svg").write_text(CLEAN, encoding="utf-8")
        ck(svgsafe.main([str(cleanroot)]) == 0, "main() returns 0 on an all-clean tree")
    ck(svgsafe.main([]) == 2, "main() usage error with no targets")

    sys.stdout.write(
        f"check_svg_safety_test: {stats['pass']} pass, {stats['fail']} fail, 0 skip\n")
    return 1 if stats["fail"] else 0


if __name__ == "__main__":
    sys.exit(run())
