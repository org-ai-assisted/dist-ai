## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Scan SVG files for active-content constructs that make them unsafe to serve same-origin.

Generic webcheck lane, shared by the family Pages sites (first-party favicons, run
in-process) and the wiki stage sites (untrusted editor SVG, run CONFINED in the sandbox).
The module is pure logic + defusedxml; WHERE it runs (host vs sandbox) is the caller's call.

WHY: on a static host (GitHub Pages) we cannot set a CSP or Content-Disposition response header,
and everything is one origin. An SVG referenced via <img src=...> never runs its script -- that is
already safe -- but a visitor who opens /media/X.svg DIRECTLY gets an SVG *document* whose
<script>/on*/javascript: then runs in OUR origin, and whose external refs fetch (exfil/track). So
this gate REJECTS (fail-closed) any SVG that carries such a construct, modelled on MediaWiki's
upload verifier (detectScriptInSvg: detect + REJECT, never silently sanitize) and hardened against
the encoding / case / escape / comment / whitespace-split / child-tail / presentation-attribute
bypasses an ADVERSARIAL SVG can use (a malicious wiki editor is in scope here).

SCOPE / convergence: the SCRIPT-execution vectors (<script>, on*, javascript:, <foreignObject>,
encoding/.svgz/case) are closed hard. The remaining remote-FETCH vectors (CSS url()/@import/
image-set) are normalized (comments stripped, escapes decoded incl CSS line-continuation, URL
tab/CR/LF removed) before matching; an ever-more-exotic CSS-tokenizer edge case is a residual
bounded by two facts: production nginx serves every svg under a sandbox CSP (default-src 'none')
that blocks ALL of it, and the ONLY surface this gate is the sole control on is the header-less
GitHub Pages stage, where the residual is a remote FETCH (privacy), never script.

Parsed with defusedxml (XXE / entity-bomb / external-DTD safe). Parsing untrusted SVG is attack
surface, so against untrusted input this runs CONFINED in the sandbox, never on the trusted host.

NORMALIZE-FIRST (fail-closed): .svgz is gunzipped (bounded, so a gzip bomb is refused); a file with
NUL bytes (UTF-16/32) or not valid UTF-8 is REJECTED; discovery is case-insensitive and covers
.svgz; a NON-EXISTENT target is an error.

Exit 0 = all clean; 1 = a dangerous/unparseable SVG or a missing target (each listed); 2 = usage.
"""
from __future__ import annotations

import re
import sys
import zlib
from pathlib import Path
from xml.etree.ElementTree import ParseError

from defusedxml.ElementTree import fromstring as _safe_fromstring
from defusedxml.common import DefusedXmlException

_SVG_NS = "http://www.w3.org/2000/svg"
_XML_NS = "http://www.w3.org/XML/1998/namespace"

# Benign element namespaces (editor/metadata), ported from MediaWiki $validNamespaces. An element
# in any OTHER namespace is rejected (fail-closed) -- catches XHTML smuggled via <foreignObject>.
# Its absence is a hard error (a security gate must never run without its allowlist).
_NS_FILE = Path(__file__).with_name("svg-valid-namespaces.txt")
_VALID_NS = frozenset(
    ln.strip().lower() for ln in _NS_FILE.read_text(encoding="utf-8").splitlines()
    if ln.strip() and not ln.lstrip().startswith("#")
)
# Inkscape mangles Adobe-Illustrator namespace defs into "&ns_...;" (MediaWiki T144827) -- harmless.
_BUGGY_INKSCAPE_NS = re.compile(r"^&(#38;)*ns_[a-z_]+;$", re.IGNORECASE)
_BAD_ELEMS = frozenset({"script", "handler", "stylesheet", "iframe", "foreignobject"})
_ANIM_ELEMS = frozenset({"animate", "set", "animatetransform", "animatemotion"})
# Presentation / CSS attributes whose value can be a url(...) that fetches a resource.
_URL_ATTRS = frozenset({"fill", "stroke", "filter", "clip-path", "clip", "mask", "cursor",
                        "marker", "marker-start", "marker-mid", "marker-end", "style",
                        "background", "background-image", "shape-outside", "list-style-image",
                        "mask-border-source"})
# Animating one of these rewrites something dangerous regardless of the value.
_ANIM_BAD_NAMES = frozenset({"handler", "base", "xml:base"})
_DATA_IMAGE_OK = re.compile(r"^data:\s*image/(gif|jpeg|jpg|a?png|webp|avif)[;,]", re.IGNORECASE)
_HTTP = re.compile(r"^https?://", re.IGNORECASE)
# Format-control whitespace a URL parser strips INSIDE a token (so "ht\ttps:" is really "https:").
_URL_STRIP_WS = {0x09: None, 0x0a: None, 0x0d: None, 0x0c: None}
# A remote/exfil/script scheme OR a protocol-relative "//" anywhere in a (whitespace-stripped) value.
_REMOTE_IN_VALUE = re.compile(r"(?:https?|data|script|vbscript):|//", re.IGNORECASE)
# Raw-TEXT checks run on the normalized UTF-8 text (never raw bytes -> no UTF-16 evasion).
# Trojan-source bidi / format controls (RHSB-2021-007 / lintian unicode-trojan) -- the SAME set
# grep-find-unicode-wrapper enforces on all other source + HTML. unicode-gate.sh excludes
# SVG/SVGZ (graphics carry legitimate non-ASCII TEXT, e.g. accented labels), delegating SVG
# active-content safety here; bidi overrides are never needed in legitimate graphics and can
# reorder visible text deceptively, so they are rejected fail-closed, keeping SVG consistent
# with the repo-wide no-trojan-codepoint policy.
_TROJAN_BIDI = frozenset(chr(cp) for cp in (
    0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
    0x2066, 0x2067, 0x2068, 0x2069))
_PI_STYLESHEET = re.compile(r"<\?xml-stylesheet", re.IGNORECASE)
# A DOCTYPE with an EXTERNAL identifier. [^>\[] bounds the match to BEFORE the doctype's own '>'
# (and before any internal '[...]' subset), so "System"/"public" words elsewhere in the document
# are not a false positive, and the scan stays O(n). No DOTALL -- it must not cross markup.
_EXTERNAL_DOCTYPE = re.compile(r"<!DOCTYPE\b[^>\[]*?\b(?:SYSTEM|PUBLIC)\b", re.IGNORECASE)
# CSS comment (stripped before remote matching; `url(/*x*/'//evil')` must not hide the ref).
_CSS_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
# A CSS escape: \<1-6 hex><opt ws>, or \<newline(s)> (line continuation: REMOVED), or \<char>.
_CSS_ESCAPE = re.compile(r"\\(?:([0-9a-fA-F]{1,6})[ \t\r\n\f]?|(\r\n|[\s\S]))")
# A remote reference in a CSS context, AFTER normalization: @import, image-set(), a url() to
# http(s)/protocol-relative/data, or a bare absolute URL. url(#fragment) is intentionally NOT hit.
_CSS_REMOTE = re.compile(
    r"@import|image-set\s*\(|url\s*\(\s*['\"]?\s*(?:https?:|//|data:)|https?://",
    re.IGNORECASE)
# A remote url()/image-set() inside any (non-style) attribute value -- fill/filter/cursor/mask/...
_ATTR_URL_REMOTE = re.compile(
    r"image-set\s*\(|url\s*\(\s*['\"]?\s*(?:https?:|//|data:)", re.IGNORECASE)
_GZIP_LIMIT = 20_000_000   # decompressed .svgz cap; a gzip bomb is refused, not expanded


def _css_unescape_sub(m: re.Match[str]) -> str:
    hexd, ch = m.group(1), m.group(2)
    if hexd is not None:
        try:
            return chr(int(hexd, 16))
        except (ValueError, OverflowError):
            return ""
    # a backslash before a newline is a CSS line-continuation: BOTH are removed (not kept).
    return "" if ch in ("\n", "\r", "\f", "\r\n") else (ch or "")


def _css_decode(s: str) -> str:
    """Escape-decode (incl CSS line-continuation removal) + drop the tab/CR/LF a URL parser
    ignores inside a token. NO comment removal (that is a separate variant below)."""
    return _CSS_ESCAPE.sub(_css_unescape_sub, s).translate(_URL_STRIP_WS)


def _css_variants(s: str) -> tuple[str, ...]:
    """The forms a browser may resolve from ONE css value -- remote matching runs on ALL of them
    (OR), so a comment- or backslash-trick can only ADD a detection, never hide a live url (a real
    CSS tokenizer is deliberately avoided -- the "burn rounds building a parser" trap):
      - decoded: escapes + whitespace folded (the live value; a FAKE /* inside a string survives
        here, so the real url is still matched);
      - comment-stripped: a GENUINE /* ... */ is browser-ignored, so stripping it is safe and
        exposes a url hidden behind a real comment;
      - backslash->slash on the DECODED forms: WHATWG URL parsing treats '\\' as '/' for http(s),
        so url(\\\\evil) is really //evil. A CSS-ESCAPED backslash (\\00005c) only becomes a literal
        '\\' AFTER escape-decoding, so the fold must also run on the decoded (and comment-stripped)
        value, not just the raw one below;
      - backslash->slash on the RAW value: catches a LITERAL '\\' written before escape-decoding
        could consume it.
    Residual (ever-more-exotic CSS tokenizer edges) is bounded: nginx serves every svg under a
    sandbox CSP (default-src 'none') that blocks ALL remote fetches, and the only surface this gate
    is sole control of is the header-less GitHub Pages stage, where the residual is a FETCH, not
    script."""
    d = _css_decode(s)
    dc = _CSS_COMMENT.sub("", d)
    return (d, dc, d.replace("\\", "/"), dc.replace("\\", "/"),
            (s or "").replace("\\", "/").translate(_URL_STRIP_WS))


def _css_has_remote(s: str) -> bool:
    return any(_CSS_REMOTE.search(v) for v in _css_variants(s))


def _attr_has_remote_url(s: str) -> bool:
    return any(_ATTR_URL_REMOTE.search(v) for v in _css_variants(s))


def _value_has_remote(s: str) -> bool:
    raw = s or ""
    return any(_REMOTE_IN_VALUE.search(v) for v in
               (raw.translate(_URL_STRIP_WS), raw.replace("\\", "/").translate(_URL_STRIP_WS)))


def _split(tag: str):
    """(namespace, localname-lowercased) for an ElementTree '{ns}local' or bare name."""
    if isinstance(tag, str) and tag.startswith("{"):
        ns, _, local = tag[1:].partition("}")
        return ns, local.lower()
    return "", (tag.lower() if isinstance(tag, str) else "")


def _href_ok(val: str, is_anchor: bool) -> bool:
    v = (val or "").strip()
    if v == "" or v.startswith("#"):
        return True                        # same-document fragment
    if v.lower().startswith("data:"):
        return bool(_DATA_IMAGE_OK.match(v))   # only a raster data: payload
    if is_anchor and _HTTP.match(v):
        return True                        # a plain external link on <a> is fine
    return False                           # javascript:, relative, other schemes


def _gunzip(data: bytes) -> bytes:
    """Decompress gzip with a hard output cap (a .svgz gzip bomb must not exhaust memory), and
    REFUSE a truncated stream or trailing/2nd concatenated member -- a browser would decompress
    every member, but the scan only sees the first, so a clean-then-malicious .svgz must not pass."""
    d = zlib.decompressobj(zlib.MAX_WBITS | 16)
    out = d.decompress(data, _GZIP_LIMIT + 1)
    if len(out) > _GZIP_LIMIT:
        raise ValueError("gzip payload exceeds limit")
    if not d.eof or d.unused_data:
        raise ValueError("truncated or multi-member gzip")
    return out


def _normalize(raw: bytes, path: Path) -> tuple[bytes | None, str | None]:
    """Decompress .svgz, reject non-UTF-8/NUL/gzip-broken input. (data, None) or (None, reason)."""
    data = raw
    if path.suffix.lower() == ".svgz" or data[:2] == b"\x1f\x8b":
        try:
            data = _gunzip(data)
        except Exception as exc:  # noqa: BLE001 -- any decompress failure/oversize is a reject
            return None, f"unreadable or oversized gzip (.svgz): {type(exc).__name__}"
    if b"\x00" in data:
        # UTF-16/UTF-32 (or binary): the raw-text checks below cannot see its markup, so refuse.
        return None, "contains NUL bytes (non-UTF-8 encoding such as UTF-16/32) -- refused"
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        return None, f"not valid UTF-8 -- refused: {exc}"
    return data, None


def scan_svg(path: Path) -> list[str]:
    """Dangerous-construct issues for one SVG (empty list = clean)."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return [f"unreadable: {exc}"]
    data, reason = _normalize(raw, path)
    if data is None:
        return [reason or "unreadable"]
    text = data.decode("utf-8")

    issues: list[str] = []
    # Trojan-source bidi/format controls. The RAW-text scan catches a LITERAL control anywhere
    # (incl. comments / PI) and survives a later XML parse failure. It does NOT see a numeric
    # character reference (&#x202e;): that is scanned on the PARSED DOM below, since the XML
    # parser + browser expand it to the real control.
    raw_bidi = sorted({ord(c) for c in text if c in _TROJAN_BIDI})
    if raw_bidi:
        issues.append("trojan-source bidi/format control(s): "
                      + ", ".join(f"U+{cp:04X}" for cp in raw_bidi))
    if _PI_STYLESHEET.search(text):
        issues.append("<?xml-stylesheet?> processing instruction (external stylesheet)")
    if _EXTERNAL_DOCTYPE.search(text):
        issues.append("<!DOCTYPE> with external DTD (SYSTEM/PUBLIC) reference")
    try:
        root = _safe_fromstring(data)
    except DefusedXmlException as exc:
        return issues + [f"forbidden XML construct (entity/external/DTD): {type(exc).__name__}"]
    except ParseError as exc:
        return issues + [f"malformed XML: {exc}"]
    except Exception as exc:  # noqa: BLE001 -- any parse failure is a reject, never a pass
        return issues + [f"unparseable: {type(exc).__name__}: {exc}"]

    parsed_bidi: set[int] = set()
    for el in root.iter():
        el_ns, local = _split(el.tag)
        el_ns_lc = el_ns.lower()   # MediaWiki matches namespaces case-insensitively
        rendered = el_ns_lc in (_SVG_NS, "")   # only SVG / no-namespace elements actually render
        # Trojan bidi in PARSED text/tail (char refs now expanded by the XML parser).
        for s in (el.text, el.tail):
            if s:
                parsed_bidi.update(ord(c) for c in s if c in _TROJAN_BIDI)
        if el_ns_lc not in _VALID_NS and not _BUGGY_INKSCAPE_NS.match(el_ns):
            issues.append(f"<{local}> in disallowed namespace: {el_ns}")
        if local in _BAD_ELEMS:
            issues.append(f"<{local}> element")
        # <style> body: scan the WHOLE text content (itertext) -- CSS on a child's tail is
        # concatenated by the browser, so el.text alone misses a split @import.
        if local == "style" and _css_has_remote("".join(el.itertext())):
            issues.append("<style> body with remote url()/@import/image-set")
        anim_name = ""
        anim_vals: list[str] = []
        for name, val in (el.attrib or {}).items():
            attr_ns, attr_local = _split(name)
            v = val or ""
            parsed_bidi.update(ord(c) for c in v if c in _TROJAN_BIDI)
            if attr_local == "base" and attr_ns == _XML_NS:
                issues.append("xml:base attribute (external base-URL hijack)")
            if attr_local.startswith("on") and rendered:
                issues.append(f"{attr_local}= event-handler attribute")
            if attr_local == "href" and not _href_ok(v, is_anchor=(local == "a")):
                issues.append(f"{attr_local}={v[:48]!r} unsafe URL scheme/target")
            if attr_local == "style" and _css_has_remote(v):
                issues.append("style= attribute with remote url()/@import/image-set")
            elif attr_local != "href" and rendered and _attr_has_remote_url(v):
                issues.append(f"{attr_local}= attribute with remote url()/image-set")
            if attr_local == "handler" and _value_has_remote(v):
                issues.append(f"handler={v[:48]!r} with remote/data/script target")
            if local in _ANIM_ELEMS:
                if attr_local == "attributename":
                    anim_name = v.strip().lower()
                elif attr_local in ("from", "to", "values", "by"):
                    anim_vals.append(v)
        # <animate>/<set> rewriting a parent's href / on* / handler / xml:base, or animating a
        # url-valued attribute to a remote target (html5sec #137 and friends). from/values/by count.
        if local in _ANIM_ELEMS and anim_name:
            if anim_name.startswith("on") or "href" in anim_name or anim_name in _ANIM_BAD_NAMES:
                issues.append(f"<{local} attributeName={anim_name!r}> (animated script/href/handler rewrite)")
            elif anim_name in _URL_ATTRS and any(
                _value_has_remote(x) or _attr_has_remote_url(x) for x in anim_vals
            ):
                issues.append(f"<{local} attributeName={anim_name!r}> (animated to a remote target)")
    # Trojan bidi that surfaced ONLY via a parsed char reference (not already caught raw).
    extra_bidi = sorted(parsed_bidi.difference(raw_bidi))
    if extra_bidi:
        issues.append("trojan-source bidi/format control(s) via character reference: "
                      + ", ".join(f"U+{cp:04X}" for cp in extra_bidi))
    return issues


def _iter_svgs(targets: list[str]):
    """Yield every .svg/.svgz (case-insensitive) under each target dir, or the target file itself."""
    for t in targets:
        p = Path(t)
        if p.is_dir():
            yield from sorted(q for q in p.rglob("*")
                              if q.is_file() and q.suffix.lower() in (".svg", ".svgz"))
        elif p.is_file():
            yield p


def main(argv: list[str]) -> int:
    # Every argv entry is a scan target (no option filtering -- a file literally named "-x.svg"
    # must not be silently dropped). A target that does not exist is an ERROR, fail-closed.
    if not argv:
        print("usage: check_svg_safety.py <path> [<path>...]", file=sys.stderr)
        return 2
    missing = [t for t in argv if not Path(t).exists()]
    if missing:
        for t in missing:
            print(f"UNSAFE-SVG  {t}: scan target does not exist (fail-closed)", file=sys.stderr)
        print(f"\nsvg-safety: FAIL -- {len(missing)} missing target(s)", file=sys.stderr)
        return 1
    bad = 0
    scanned = 0
    for svg in _iter_svgs(argv):
        scanned += 1
        for issue in scan_svg(svg):
            if issue:
                bad += 1
                print(f"UNSAFE-SVG  {svg}: {issue}")
    if bad:
        print(f"\nsvg-safety: FAIL -- {bad} finding(s) across {scanned} SVG(s)", file=sys.stderr)
        return 1
    print(f"svg-safety: PASS -- {scanned} SVG(s) clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
