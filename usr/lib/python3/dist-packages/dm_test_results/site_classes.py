## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Pure-data status + CSS-class contract for the verification site.

NO heavy imports (numpy/Pillow): the generator-owned class manifest must be importable by a
REQUIRED website-tests unit and by the deploy-time contract check WITHOUT pulling the image
stack, so the manifest lives here (a numpy-free leaf) and `site` re-exports it.
"""

## Run-cell statuses. Only STATUS_PASS is green. CSS class = "st-<status>". Status is
## decided objectively from result.json (finished + fresh + verdict PASS + firmware match),
## never from a human golden approval -- there is no NEW/CHANGED "needs approval" state.
STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_INCONCLUSIVE = "inconclusive"
STATUS_INCOMPLETE = "incomplete"
STATUS_NODATA = "nodata"
STATUS_STALE = "stale"
STATUS_UNKNOWN = "unknown"

## The one green status.
STATUS_GREEN = STATUS_PASS

## Every run-cell status, in one tuple, so the st-<status> CSS family is derived from a
## single place (css_class below). A new status added above lands in the family here, so it
## cannot silently reach the site without a matching CSS rule.
ALL_STATUSES = (
    STATUS_PASS, STATUS_FAIL, STATUS_INCONCLUSIVE, STATUS_INCOMPLETE,
    STATUS_NODATA, STATUS_STALE, STATUS_UNKNOWN,
)


def css_class(status):
    return "st-%s" % status


## Generator-owned class contract: every CSS class the HTML generator emits as a literal
## class="..." token (chrome, footer, cards, hero, matrix, step logs), UNION the st-<status>
## family. style.css lives in a SEPARATE repo (org-ai-assisted.github.io), hand-maintained, so
## nothing structurally coupled the two -- a new generator class (the .stage boot caption) shipped
## unstyled and the undefined-classes gate silently blocked every publish. Two sides enforce this
## set: dist_ai.webcheck.site.check_generated_class_contract asserts the served style.css defines
## every class here (catching co-classes undefined-classes cannot), and site_generate_test asserts
## the generator emits nothing outside it. Classes from a --chrome-from lifted masthead are NOT
## listed: they come from an already-styled family page in the same repo, not from the generator.
_STRUCTURAL_CLASSES = frozenset({
    "nav", "wrap", "brand", "ftop", "fcols", "fcol", "self", "fbot", "fcopy",
    "chip", "cat", "catname", "matrix-wrap", "matrix", "legend",
    "hero", "kicker", "line", "sub", "runid", "steplog", "issue", "fg", "stage",
})

GENERATED_CLASSES = _STRUCTURAL_CLASSES | frozenset(css_class(s) for s in ALL_STATUSES)
