# web-analyzer-tests

Comprehensive test for the output-lies web text analyzer,
`output-lies.github.io: analyze/analyzer.js`.

`analyzer.js` is the client-side classifier behind the site's Analyze page. It
is a pure, DOM-free module (it also runs under node via `module.exports`), which
is exactly what makes it testable here without a browser. It flags every
codepoint that is not plain printable ASCII and names the class of deception it
belongs to: bidi controls, zero-width and invisible-format characters, deceptive
whitespace, homoglyph-prone scripts, C0/C1 control bytes, line/paragraph
separators, combining marks, variation selectors, tag characters and private
use. It deliberately does not judge intent, and it cannot catch all-ASCII
homoglyphs (`rn` versus `m`) by design.

The suite drives the classifier directly and asserts:

- the class of every boundary codepoint (each range edge, and the codepoint just
  outside it), so a shifted or fenceposted range is caught;
- the known real-world traps (Cyrillic homoglyph, zero-width space, bidi override);
- astral-plane safety (an emoji is one codepoint, counted once);
- `analyze()` token splitting: safe runs coalesce and the item list reconstructs
  the exact input;
- `toAscii()` strips every flagged codepoint while keeping ASCII plus tab/newline;
- `hex()` formatting, including 5-digit astral codepoints.

No root, no network. It resolves `analyzer.js` from `OUTPUT_LIES_REPO` (an
`output-lies.github.io` checkout), then a default under the operator's
`private-sources`, then a sibling checkout. If the module is not found it SKIPs
(exit 77) rather than failing.

## Usage

```
web-analyzer-tests
OUTPUT_LIES_REPO=/path/to/output-lies.github.io web-analyzer-tests
```
