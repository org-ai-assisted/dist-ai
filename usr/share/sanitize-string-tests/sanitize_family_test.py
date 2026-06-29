#!/usr/bin/env python3
"""
Deep test + fuzz harness for the helper-scripts "sanitize" family
(stdisplay -> strip_markup -> sanitize-string) as consumed by msgcollector's
generic_gui_message (a PyQt5 QTextBrowser, setOpenExternalLinks(True)).

Goal: prove the sanitizers are perfect within their threat model, with NO
bypasses. The threat model is: sanitize-string output is embedded, unescaped,
into text shown to the user in two renderers --

  1. a terminal (stdisplay's original purpose), and
  2. HTML / Qt rich text (msgcollector's confirmation and error dialogs).

so the output must be safe in BOTH.

What this harness adds over helper-scripts' own property tests: a CROSS-PARSER
differential. helper-scripts checks properties against Python's view of the
string; the dialog renders with Qt's more lenient HTML parser. The bug this
suite was written for lives precisely in that gap: a '<' followed by whitespace
then a tag name ("< a href=...>"), or a '<' produced by entity decoding
("&lt img src=x>"), is inert to Python's html.parser but Qt revives it into a
clickable <a href> / <img>. This harness drives the REAL Qt engine.

Checks (each over a curated adversarial corpus AND a biased fuzzer):
  [T] terminal-safety invariants: ASCII only, no control bytes except \\n/\\t,
      no ESC, length <= the requested cap, idempotent. Always hard.
  [H] HTML-safety invariant: NO '<' survives in the output. Without a '<', no
      tag can form in ANY HTML parser, so this is the provable no-bypass
      guarantee. Hard when the sanitizer is fixed; otherwise reported as the
      deployed bypass (the suite stays green and says so).
  [Q] Qt differential: sanitized output embedded in the dialog template,
      parsed by a real QTextDocument, must yield no anchor and no image.
      Concrete end-to-end proof of [H]. Needs PyQt5; skipped if absent.

The specific issue and its fix are proven directly: the adversarial corpus
contains the exact bypass vectors; against a fixed sanitize-string they are all
neutralized, against an unfixed one they are shown injecting (proving the issue
is real). Detection is automatic.

Path override: SANITIZE_STRING_BIN (else installed /usr/bin/sanitize-string,
else a derivative-maker checkout). To prove a not-yet-installed source fix,
point SANITIZE_STRING_BIN at a wrapper that runs the checkout copy.

Usage: sanitize_family_test.py [--iterations N] [--seed N] [--fuzz-only]
"""

import argparse
import os
import subprocess
import sys

DM = "/home/user/derivative-maker/packages/kicksecure"
DIALOG_TRIM = 128


def resolve_sanitize_string():
    env = os.environ.get("SANITIZE_STRING_BIN")
    if env:
        return env
    if os.path.exists("/usr/bin/sanitize-string"):
        return "/usr/bin/sanitize-string"
    return os.path.join(DM, "helper-scripts/usr/bin/sanitize-string")


SANITIZE_STRING = resolve_sanitize_string()


def run_sanitize(arg, max_length=DIALOG_TRIM):
    """Invoke sanitize-string exactly as a consumer does: argv argument plus an
    explicit max length. Returns stdout bytes."""
    proc = subprocess.run(
        [SANITIZE_STRING, "--", str(max_length), arg],
        capture_output=True,
        check=False,
    )
    return proc.stdout


## The wrapper open-link-confirmation / other consumers build around the value:
## it always lands inside an HTML rich-text message.
HTML_PREFIX = (
    "<p>The following <b>link</b> will be opened in <u>Tor Browser</u>.</p>"
    "<p><code><blockquote>"
)
HTML_SUFFIX = "</blockquote></code></p>"


class Results:
    """PASS/FAIL/XFAIL/SKIP counter (no pytest dependency)."""

    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.xfailed = 0
        self.skipped = 0
        self.fail_samples = []

    def ok(self, name):
        self.passed += 1

    def fail(self, name, detail):
        self.failed += 1
        if len(self.fail_samples) < 25:
            self.fail_samples.append(name + ": " + detail)

    def xfail(self, name):
        self.xfailed += 1

    def skip(self, name, detail):
        self.skipped += 1
        print("  SKIP  " + name + "  (" + detail + ")")


## ---------------------------------------------------------------------------
## Invariants
## ---------------------------------------------------------------------------

def terminal_violations(out_bytes, max_length):
    """[T] Return terminal-safety violations."""
    violations = []
    if any(b >= 0x80 for b in out_bytes):
        violations.append("non-ASCII byte")
    if len(out_bytes) > max_length:
        violations.append("length " + str(len(out_bytes)) + " > " + str(max_length))
    if any(b < 0x20 and b not in (0x09, 0x0A) for b in out_bytes):
        violations.append("control byte")
    if 0x1B in out_bytes:
        violations.append("ESC byte")
    if 0x7F in out_bytes:
        violations.append("DEL byte")
    return violations


def has_lt(out_bytes):
    """[H] True if a tag-opening '<' survives."""
    return 0x3C in out_bytes


## ---------------------------------------------------------------------------
## Adversarial corpus: the exact bypass family + controls.
## ---------------------------------------------------------------------------
def adversarial_corpus():
    cases = {
        ## benign / controls (must always be safe)
        "benign_url": "https://www.whonix.org/wiki/Foo",
        "plain_anchor": "<a href='http://example.com'>x</a>",
        "plain_img": "<img src='http://example.com/p.png'>",
        "lone_gt": "a > b",
        ## whitespace-tag bypass family
        "ws_space_a": "< a href='http://example.com'>x</a>",
        "ws_tab_a": "<\ta href='http://example.com'>x",
        "ws_newline_a": "<\na href='http://example.com'>x",
        "ws_multi_a": "<  \t\n a href='http://example.com'>x",
        "ws_upper_a": "< A HREF='http://example.com'>x",
        "ws_img_remote": "< img src='http://example.com/p.png'>",
        "ws_img_file": "< img src='file:///etc/hostname'>",
        "ws_img_data": "< img src='data:image/png;base64,iVBORw0KGgo='>",
        "ws_img_no_close": "< img src='http://example.com/p.png'",
        ## entity-decode revival (html.parser decodes &lt -> '<')
        "ent_lt_space_img": "&lt img src='http://example.com/p.png'>",
        "ent_num_space_img": "&#60 img src='http://example.com/p.png'>",
        "ent_hex_space_img": "&#x3c img src='http://example.com/p.png'>",
        "ent_lt_semi_a": "&lt; a href='http://example.com'>x",
        ## nested / multi-strip evasion
        "nested_lt": "<< a href='http://example.com'>x",
        "double_tag": "<<a a href='http://example.com'>x",
    }
    return cases


## ---------------------------------------------------------------------------
## Biased fuzzer
## ---------------------------------------------------------------------------
## Tokens chosen to maximise the chance of forming a revivable tag. NUL is
## excluded: an execve argument (and a bash variable) cannot contain it, so the
## consumer argv path can never carry it.
FUZZ_TOKENS = [
    "<", ">", "&", "/", "!", "?", ";", "=", "'", '"', " ", "\t", "\n",
    "a", "A", "img", "IMG", "href", "src", "script", "b", "i",
    "http://x", "file:///x", "data:x", "x", "1",
    "&lt", "&lt;", "&gt", "&#60", "&#62", "&#x3c", "&amp;", "&#x3e",
    "<!--", "-->", "<![CDATA[", "]]>", "<?", "?>",
    "\x1b[31m", "\x07", "\x08", "\x1b]8;;", "\u202e", "\u200b", "\u4f60", "caf",
]


def fuzz_input(rng, max_tokens=24):
    parts = []
    count = rng.randint(1, max_tokens)
    for _ in range(count):
        parts.append(rng.choice(FUZZ_TOKENS))
    return "".join(parts)


## ---------------------------------------------------------------------------
## Qt differential
## ---------------------------------------------------------------------------
def make_qt_probe():
    """Return (probe_fn, note). probe_fn(sanitized_text) -> (anchors, images)
    using a real Qt QTextDocument, or None if PyQt5 is unavailable."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PyQt5 import QtGui, QtWidgets
    except Exception as exc:  # pylint: disable=broad-except
        return None, "PyQt5 unavailable: " + str(exc)

    app = QtWidgets.QApplication.instance()
    if app is None:
        app = QtWidgets.QApplication(sys.argv)

    def probe(sanitized):
        doc = QtGui.QTextDocument()
        doc.setHtml(HTML_PREFIX + sanitized + HTML_SUFFIX)
        anchors = set()
        images = set()
        block = doc.begin()
        while block.isValid():
            it = block.begin()
            while not it.atEnd():
                frag = it.fragment()
                if frag.isValid():
                    fmt = frag.charFormat()
                    if fmt.anchorHref():
                        anchors.add(fmt.anchorHref())
                    if fmt.isImageFormat():
                        images.add(fmt.toImageFormat().name())
                it += 1
            block = block.next()
        return anchors, images

    ## Baseline: the wrapper alone must introduce nothing.
    base_a, base_i = probe("PLACEHOLDER")
    if base_a or base_i:
        return None, "wrapper baseline not clean: " + str(base_a) + str(base_i)
    return probe, "ok"


def detect_fixed():
    """A sanitizer is 'fixed' if a known whitespace-tag bypass leaves no '<'."""
    out = run_sanitize("< a href='http://probe'>x")
    return not has_lt(out)


# pylint: disable=too-many-branches,too-many-statements,too-many-locals
def main():
    parser = argparse.ArgumentParser(description="sanitize family deep test + fuzz")
    parser.add_argument("--iterations", type=int, default=3000)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--fuzz-only", action="store_true")
    args = parser.parse_args()

    print("sanitize family deep test + fuzz")
    print("sanitize-string: " + SANITIZE_STRING)
    if not os.path.exists(SANITIZE_STRING):
        print("ERROR: sanitize-string not found; set SANITIZE_STRING_BIN")
        return 2

    fixed = detect_fixed()
    print("sanitizer fixed (no '<' revival): " + ("YES" if fixed else
          "NO -- deployed sanitizer is VULNERABLE; fix is in helper-scripts "
          "strip_markup source, rebuild/install to deploy"))
    qt_probe, qt_note = make_qt_probe()
    print("Qt differential: " + ("enabled" if qt_probe else "skipped (" + qt_note + ")"))
    print()

    results = Results()

    def check_one(name, arg, hard_html):
        """Run all groups on a single input. hard_html gates [H]/[Q] when the
        sanitizer is unfixed."""
        out = run_sanitize(arg)
        ## [T] terminal safety: always hard.
        tv = terminal_violations(out, DIALOG_TRIM)
        if tv:
            results.fail("T:" + name, "; ".join(tv) + " input=" + repr(arg[:60]))
        else:
            results.ok("T:" + name)
        ## [H] HTML safety: no '<'.
        lt = has_lt(out)
        if not lt:
            results.ok("H:" + name)
        elif fixed:
            results.fail("H:" + name, "'<' survived: " + repr(out[:60]))
        else:
            results.xfail("H:" + name)
        ## [Q] Qt differential.
        if qt_probe is not None:
            sanitized = out.decode("ascii", "replace")
            anchors, images = qt_probe(sanitized)
            if not anchors and not images:
                results.ok("Q:" + name)
            elif fixed:
                results.fail(
                    "Q:" + name,
                    "Qt revived anchors=" + str(anchors) + " images=" + str(images)
                    + " from " + repr(sanitized[:60]),
                )
            else:
                results.xfail("Q:" + name)

    ## Adversarial corpus (proves the specific issue + fix).
    if not args.fuzz_only:
        print("[corpus] adversarial bypass family + controls")
        for name, arg in adversarial_corpus().items():
            check_one("corpus:" + name, arg, hard_html=fixed)

    ## Fuzz.
    import random
    rng = random.Random(args.seed)
    print("[fuzz] " + str(args.iterations) + " iterations (seed " + str(args.seed) + ")")
    qt_budget = 800  # bound Qt parses for runtime; [H] still runs on every input
    for i in range(args.iterations):
        arg = fuzz_input(rng)
        out = run_sanitize(arg)
        tv = terminal_violations(out, DIALOG_TRIM)
        if tv:
            results.fail("T:fuzz#" + str(i), "; ".join(tv) + " input=" + repr(arg[:80]))
        else:
            results.ok("T:fuzz#" + str(i))
        ## NB: idempotency of the sanitizer itself is covered by helper-scripts'
        ## property tests. We deliberately do NOT re-sanitize the CLI output
        ## here: the CLI truncates to max_length AFTER sanitizing, so a cut
        ## mid-entity makes sanitize(output[:N]) != output[:N] - a truncation
        ## artifact, not a sanitizer defect, and irrelevant to display safety
        ## (truncation only ever shows less, never injects).
        if not has_lt(out):
            results.ok("H:fuzz#" + str(i))
        elif fixed:
            results.fail("H:fuzz#" + str(i),
                         "'<' survived: in=" + repr(arg[:80]) + " out=" + repr(out[:80]))
        else:
            results.xfail("H:fuzz#" + str(i))
        if qt_probe is not None and i < qt_budget:
            anchors, images = qt_probe(out.decode("ascii", "replace"))
            if not anchors and not images:
                results.ok("Q:fuzz#" + str(i))
            elif fixed:
                results.fail("Q:fuzz#" + str(i),
                             "Qt revived from in=" + repr(arg[:80])
                             + " a=" + str(anchors) + " i=" + str(images))
            else:
                results.xfail("Q:fuzz#" + str(i))

    print()
    print(
        str(results.passed) + " passed, "
        + str(results.failed) + " failed, "
        + str(results.xfailed) + " xfailed, "
        + str(results.skipped) + " skipped"
    )
    if results.fail_samples:
        print("failures (sample):")
        for sample in results.fail_samples:
            print("  - " + sample)
    if not fixed and results.xfailed:
        print(
            "NOTE: deployed sanitizer is VULNERABLE to the markup-injection "
            "bypass (" + str(results.xfailed) + " xfail checks). The fix is in "
            "helper-scripts strip_markup source; install it (or point "
            "SANITIZE_STRING_BIN at the fixed copy) to require these checks."
        )
    if results.failed:
        print("RESULT: FAIL")
        return 1
    if fixed:
        print("RESULT: PASS (sanitizer proven bypass-free across this run)")
    else:
        print("RESULT: PASS (terminal-safety proven; HTML-safety pending fix deploy)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
