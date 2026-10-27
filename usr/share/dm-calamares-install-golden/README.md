# dm-calamares-install content goldens

Per-milestone **expected-text goldens** for the install story's screenshots. Each
`<stage>.tokens` file lists phrases that MUST appear in that milestone's OCR text
(`image-text-assert --spec`); a phrase is matched case-insensitively with whitespace
normalized, so OCR glyph/spacing noise and minor UI drift do not matter, but a WRONG frame
(the expected words absent) fails.

## Verdict policy (graduated)

- A milestone WITH a golden here whose shot's OCR is **missing** an expected token -> the run
  FAILS (a wrong-content milestone must not publish green).
- A milestone with **no** golden here is **UNVALIDATED**: reported, never counted as a
  validated pass, but it does not fail the run -- so coverage can grow without breaking every
  run on day one.
- Structural gates are separate and always on: `image-blank-check` (degenerate frames) and
  `image-dup-check` (a frame stuck across 3+ milestones).

## Approving / adding a golden

1. Get the milestone's shot and read its OCR text: `image-ocr-sidecar <shot>` writes
   `<shot>.ocr.txt`. (Publishing a sidecar per run on the results plane + an on-page validation
   status is a follow-up; until then run `image-ocr-sidecar` on a pulled shot.)
2. Pick 1-3 DISTINCTIVE phrases the milestone's main panel reliably shows (avoid the shared
   sidebar menu words -- they appear on most stages).
3. Write them to `<stage>.tokens` (one per line; `#` starts a comment). Keep them robust: a
   clean, stable phrase beats a long exact transcript.
4. Commit it -- the commit IS the approval.

## Seeded samples

`welcome`, `location`, `summary`, `luks-prompt` are seeded from OCR of a healthy run
(2137-g853b3107b6f3-20261024T054343Z) as templates. Review + extend to the other milestones.
`keyboard` is deliberately left UNVALIDATED (its OCR is noisy) as an example of the graduated
state.
