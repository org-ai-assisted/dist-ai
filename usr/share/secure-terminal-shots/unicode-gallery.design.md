# unicode.payload -- design note

Sibling of `truecolor-art.py` (the `art.payload` scene). A display-only, cat-able
Unicode showcase whose purpose is a TEST and DEMONSTRATION that secure-terminal can
show and risk-tint the whole character space -- every glyph, every control, every
format/bidi/invisible class.

Status: DESIGN (not built). This note is the plan of record; the generator, the
manifest, the dist-ai test and the shots/page wiring are the follow-up work.

## Two goals, deliberately split

`render_output` / `marking_class` are FONT-INDEPENDENT (they classify code points and
emit box/badge/glyph text). Glyph DISPLAY is font-bound: the shipped default font is
Hack, falling back to DejaVu Sans Mono, and neither draws CJK (~90k), Hangul (~11k),
Arabic/Hebrew/Indic/Thai, emoji, or the astral symbol blocks. Dumping all ~150k
assigned code points into a Show-mode file would render the majority as tofu -- a
showcase that looks broken and undersells the tool. So:

- DISPLAY (the payload, the shot): the terminal-font-RENDERABLE subset only -- tofu-free
  and handsome.
- COVERAGE (the conformance test): EXHAUSTIVE over every assigned code point, done
  against `marking_class` where fonts do not matter.
- The honest "can we show ALL characters" answer: a detail-mode capture proves a
  font-less code point still gets a readable `<U+XXXX NAME>` identity badge -- never a
  silent tofu.

Same principle that drops unassigned code points ("nothing to draw -> do not draw it")
also drops Private Use (no standard glyph) and shrinks the noncharacter block to a few
labeled examples.

## What secure-terminal does to each class (the thing being demonstrated)

- Display modes: `box` / `show` / `reveal` / `detail` (default). Glyphs render as
  themselves only in `show`; `detail` badges every non-ASCII as `<U+XXXX NAME>`.
- Risk classes (`marking_class`, most dangerous first): `bidi` > `control` >
  `invisible` > `confusable` > `combining` > `nonascii`.
- Structural (Box Drawing `U+2500..257F`, Block Elements `U+2580..259F`, minus the two
  confusable diagonals `U+2571`/`U+2573`): `show` mode renders these in the program's
  OWN colour, not a risk tint; strict modes still neutralize them.
- Non-ASCII spaces -> `SPACE_MARK` (`U+2423`) in `show`; box in strict modes.
- Inspect popup = `describe_codepoint`: name, general category, `\u` escape.

## The payload

Generator `unicode-gallery.py`, pure and deterministic, emits ONLY printable glyphs,
raw control/format bytes, and newlines -- ZERO SGR of its own. All colour you see is
secure-terminal's tint (a traditional terminal shows flat/garbled text; that contrast
is the shot's payoff). It is a Show-mode showcase (glyphs only render as themselves in
`show`).

Layout:

- A curated HERO section first (one specimen per risk class + a spread of scripts and
  symbols) so the captured screenful is striking.
- Then a block-by-block chart over the renderable subset: per block a header
  (name + `U+XXXX..U+YYYY`), a 16-wide grid with hex row/column guides, and a caption
  naming the risk class(es) that block trips. Canonical Unicode-chart look.
- Then the risk-class SPECIMEN sections carrying the raw dangerous bytes (below).
- A footer.

Renderable subset (font-bound; verify against the ACTUAL capture environment's fonts,
which decide tofu, not a remembered list): Basic Latin, Latin-1, Latin Extended-A/B,
IPA, spacing modifiers, combining diacriticals, Greek, Cyrillic, Armenian, Hebrew,
Georgian, general punctuation, super/subscripts, currency, letterlike, number forms,
arrows, math operators, misc technical, Control Pictures, box drawing, block elements,
geometric shapes, Braille, dingbats. Excluded (tofu in Hack/DejaVu): CJK, Hangul, Yi,
Indic, SE-Asian, emoji, astral -- these are covered by the test, not drawn.

## Raw dangerous bytes: inline-isolated, single file

Chosen containment: ONE file, plain `cat`, every raw hostile byte isolated so a
traditional terminal is affected as little as possible.

- Every C0 (`0x00..0x1F`), DEL (`0x7F`), C1 (`U+0080..009F`) specimen ALONE on its own
  line, raw byte LAST before the `\n`, so any escape/CSI it starts aborts at the
  newline.
- `SO` (`0x0E`) is auto-paired with `SI` (`0x0F`) on the same line -- restores G0
  charset, killing the one LINGERING traditional-terminal hazard (a charset shift that
  would otherwise persist down the file).
- Bidi controls (`U+202A..202E`, `U+2066..2069`, `U+200E/200F`) one-per-line -- the
  reorder can never span past the newline.
- Combining marks rendered on a dotted circle (`U+25CC`), the standard isolated
  presentation, so they do not stack onto chart guides.
- Zero-width / invisible / BOM / default-ignorable: labeled, one-per-line, harmless.
- Noncharacters (`U+FDD0..FDEF`, `U+xFFFE/FFFF`): 2-3 LABELED examples, not a 66-cell
  grid.

Honest residual on a TRADITIONAL terminal (documented in the file header; this was the
accepted tradeoff of the single-file inline choice): `BEL` beeps once, `BS`/`CR` do
bounded within-line moves, and a stray `ESC` / C1-CSI is aborted by its newline but may
still be handled oddly by some terminals. Bounded, not zero. secure-terminal neutralizes
all of it.

## Machine-readable companion + conformance test

- NO 150k-row committed JSON. The independent classification is TEST CODE that iterates
  every assigned code point from `unicodedata` at runtime (<1s) and derives the expected
  `marking_class` from FIRST PRINCIPLES -- general category + bidi properties + the
  confusables source + the structural ranges -- WITHOUT calling `sanitize.marking_class`.
  The test then asserts `secure_terminal.marking_class(cp)` matches for all assigned cps,
  so it genuinely catches sanitize drift instead of being a tautology.
- Canary (per the house canary rule): stub `marking_class` to a constant and confirm the
  test goes red; a green run against a stub means zero coverage.
- The shipped "machine-readable" artifact is a COMPACT per-block SUMMARY table
  (block -> risk classes -> counts), the part a human or external tool actually wants.
- Test lives at `usr/share/secure-terminal-tests/test_unicode_gallery.py`; run via the
  authoritative `secure-terminal-tests` runner (PYTHONPATH set, else it tests the stale
  install).

## Determinism / Unicode version

The assigned set depends on `unicodedata.unidata_version`. Stamp it in the payload
header AND the summary table. Regeneration is a no-op only for a fixed version; a
Unicode bump FAILS the test loudly (added/removed code points) and forces a reviewed
regeneration -- never a silent skip.

## Performance reality

- The pure `render_output` / `marking_class` path over 150k code points is trivial: the
  test is exhaustive and fast.
- A live GUI render of a large file is SLOW (per-character Python is the known
  bottleneck) and beyond 4096 distinct code points the mark-format cache stops caching
  (still correct, slower). The renderable subset keeps the DISPLAYED file small; the
  shot captures the hero screenful. The exhaustive tail is never a GUI concern because it
  is not in the displayed file.

## Wiring (mirrors the `art` case)

- `lib-capture.sh`: new `unicode` case in `shots_payload_cmd` (`cat unicode.payload`)
  plus a materialization block calling `unicode-gallery.py` (like the `truecolor-art.py`
  block).
- Shots: `secure-terminal.unicode-show.webp` and `unicode-tui-show.webp` (hero
  screenful), plus one `detail`-mode capture showing font-less code points as identity
  badges.
- Page: a figure + caption on the compatibility/comparison page, fact-checked (every
  count + per-class claim) before deploy, per the site rules. Content images MUST be
  webp (the site image gate).

## Naming

`unicode.payload` (fits the existing `.payload` family and the requester's instinct).
Generator `unicode-gallery.py`; summary `unicode-gallery-summary.<json|tsv>`; test
`test_unicode_gallery.py`.

## Open / deferred

- Renderable-subset block list is font-decided: enumerate it from the ACTUAL capture
  fonts at build time, do not hardcode a remembered set.
- A separately-scoped ARTFUL curated file (a composed scene, not a reference chart) is
  possible if wanted; this note covers the reference-chart + test artifact only.
