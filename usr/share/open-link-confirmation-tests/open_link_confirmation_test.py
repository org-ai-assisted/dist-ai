#!/usr/bin/env python3
"""
Security-focused test harness for the Kicksecure open-link-confirmation
link/file confirmation dialog.

open-link-confirmation is the $BROWSER / x-www-browser handler. It receives a
URL or file path from a potentially untrusted source (a clicked link, another
application, a downloaded file) and shows a confirmation dialog before opening
it. The argument is the untrusted input; the threat model is "what can a
crafted argument make that dialog show or do".

The script displays the argument by piping it through helper-scripts'
sanitize-string and embedding the result in an HTML message that msgcollector's
generic_gui_message renders in a PyQt5 QTextBrowser. This harness checks the
three properties that matter for that pipeline:

  A. SANITIZATION CONTRACT - drive the REAL sanitize-string exactly as the
     script does ("sanitize-string -- 128 <arg>") over a hostile battery and
     assert the output is display-safe: ASCII only (no unexpected Unicode),
     length <= the cap (no oversized string), no ESC / C0 / C1 / DEL control
     bytes (only newline and tab, which sanitize-string allows).

  B. Qt RICH-TEXT DIFFERENTIAL - embed the sanitized output in the script's
     ACTUAL HTML wrappers (extracted from the shipped msg="..." assignments, not
     a copy kept in this file) and parse each with the REAL Qt QTextDocument (the
     same engine QTextBrowser.setText uses). Assert no anchor (<a href>) and no
     image (<img>) is introduced by the argument, in EVERY rendering context the
     script displays it in. This is where a parser differential bites:
     sanitize-string uses Python's html.parser, the dialog uses Qt's parser, and
     the two disagree about what is a tag (see the KNOWN_VULN registry below). It
     is also where a wrapper regression bites: if a future edit embeds the value
     in a weaker context (an attribute, or without the <code> guard), the real
     wrapper is what gets tested, so the differential sees it.

  C. STATIC AUDIT - read the script source and assert every displayed message
     interpolates only the sanitized representation of the argument, never the
     raw argument. Guards against a future edit that embeds the raw URL.

No root, no network, no real browser. Qt runs offscreen
(QT_QPA_PLATFORM=offscreen). Group B is skipped (loudly) if PyQt5 is absent.

Path overrides (else installed paths, else a derivative-maker checkout):
  OPEN_LINK_CONFIRMATION_BIN  - the open-link-confirmation script
  SANITIZE_STRING_BIN         - the sanitize-string binary
"""

import os
import re
import subprocess
import sys

DM = "/home/user/derivative-maker/packages/kicksecure"


def resolve_sanitize_string():
    env = os.environ.get("SANITIZE_STRING_BIN")
    if env:
        return env
    if os.path.exists("/usr/bin/sanitize-string"):
        return "/usr/bin/sanitize-string"
    return os.path.join(DM, "helper-scripts/usr/bin/sanitize-string")


def resolve_script():
    env = os.environ.get("OPEN_LINK_CONFIRMATION_BIN")
    if env:
        return env
    installed = "/usr/libexec/open-link-confirmation/open-link-confirmation"
    if os.path.exists(installed):
        return installed
    return os.path.join(
        DM,
        "open-link-confirmation/usr/libexec/open-link-confirmation"
        "/open-link-confirmation",
    )


SANITIZE_STRING = resolve_sanitize_string()
SCRIPT = resolve_script()

## The shipped script source, read once in main() after its existence is
## confirmed; the Qt differential drives functions out of it and the static
## audit greps it.
SCRIPT_SOURCE = ""

## The trim length the script passes to sanitize-string for the link/file
## shown in the confirmation dialog (open-link-confirmation: trim="128").
DIALOG_TRIM = 128


class Results:
    """Minimal PASS/FAIL/XFAIL counter (no pytest dependency, matches the
    other dist-ai harnesses)."""

    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.xfailed = 0
        self.skipped = 0

    def ok(self, name):
        self.passed += 1
        print("  PASS  " + name)

    def fail(self, name, detail):
        self.failed += 1
        print("  FAIL  " + name)
        print("        " + detail)

    def xfail(self, name, detail):
        self.xfailed += 1
        print("  XFAIL " + name + "  (known, unfixed)")
        print("        " + detail)

    def skip(self, name, detail):
        self.skipped += 1
        print("  SKIP  " + name + "  (" + detail + ")")


def run_sanitize(arg, max_length=DIALOG_TRIM):
    """Invoke sanitize-string exactly as the script does: as an argv argument,
    with an explicit max length. Returns the raw stdout bytes."""
    proc = subprocess.run(
        [SANITIZE_STRING, "--", str(max_length), arg],
        capture_output=True,
        check=False,
    )
    return proc.stdout


## ---------------------------------------------------------------------------
## Group A: sanitization contract
## ---------------------------------------------------------------------------

## Hostile inputs a crafted link/file argument could carry. NUL is deliberately
## absent: an execve argument cannot contain a NUL byte and a bash variable
## cannot hold one either, so the script's argv path can never carry it.
CONTRACT_CASES = {
    "benign_url": "https://www.whonix.org/wiki/Foo",
    ## Non-ASCII vectors are written as escapes to keep this file ASCII (the
    ## point is to test how sanitize-string handles the decoded characters).
    "accented": "caf\u00e9-na\u00efve",
    "emoji": "click \U0001f4a3 here",
    "rtl_override": "report\u202egnp.exe",  # U+202E right-to-left override
    "zero_width": "who\u200bnix.org",  # U+200B zero-width space
    "cjk": "\u4f60\u597d\u4e16\u754c",
    "ansi_color": "\x1b[31mRED\x1b[0m",
    "osc8_hyperlink": "\x1b]8;;https://example.com\x07click\x1b]8;;\x07",
    "bell_backspace": "a\x07b\x08\x08c",
    "c0_controls": "a\x01b\x02c\x1fd",
    "c1_controls": "a\x85b\x9bc",
    "del": "a\x7fb",
    "tag_script": "<script>alert(1)</script>",
    "entity_numeric": "&#60;script&#62;",
    "long_ascii": "A" * 5000,
    "long_unicode": "\u4f60" * 5000,
    "long_markup": "<b>" * 2000 + "x",
    "long_lt_flood": "<" * 5000 + "script",
    "newline_tab": "line1\nline2\ttabbed",
}


def check_display_safe(out_bytes, max_length):
    """Return a list of contract violations for sanitize-string output."""
    violations = []
    if any(b >= 0x80 for b in out_bytes):
        offenders = [hex(b) for b in out_bytes if b >= 0x80][:8]
        violations.append("non-ASCII bytes present: " + ", ".join(offenders))
    if len(out_bytes) > max_length:
        violations.append(
            "length " + str(len(out_bytes)) + " exceeds cap " + str(max_length)
        )
    ## sanitize-string's allow list is printable ASCII plus newline and tab.
    bad_ctrl = [
        hex(b) for b in out_bytes if b < 0x20 and b not in (0x09, 0x0A)
    ]
    if bad_ctrl:
        violations.append("control bytes present: " + ", ".join(bad_ctrl[:8]))
    if 0x1B in out_bytes:
        violations.append("ESC (0x1b) present")
    if 0x7F in out_bytes:
        violations.append("DEL (0x7f) present")
    return violations


def run_contract(results):
    print("[A] sanitization contract (sanitize-string -- "
          + str(DIALOG_TRIM) + " <arg>)")
    for name, arg in CONTRACT_CASES.items():
        out = run_sanitize(arg)
        violations = check_display_safe(out, DIALOG_TRIM)
        if violations:
            results.fail("contract:" + name, "; ".join(violations))
        else:
            results.ok("contract:" + name)


## ---------------------------------------------------------------------------
## Group B: Qt rich-text differential
## ---------------------------------------------------------------------------

## Each value is the untrusted argument. After sanitize-string, the result is
## placed inside the script's HTML wrapper and parsed by the real Qt
## QTextDocument. "secure" means no anchor and no image survive into the
## rendered document.
INJECTION_CASES = {
    ## Controls: these MUST be neutralized today.
    "tag_anchor": "<a href='http://example.com'>x</a>",
    "tag_img_remote": "<img src='http://example.com/p.png'>",
    "lone_lt": "a < b > c",
    "entity_anchor": "&lt;a href='http://example.com'&gt;x&lt;/a&gt;",
    ## Parser-differential cases (formerly KNOWN_VULN, now fixed and asserted as
    ## hard controls). A '<' followed by whitespace then a tag name is inert to
    ## Python's html.parser (passes through verbatim) but Qt's parser skips the
    ## whitespace and builds the tag; the fixed strip_markup neuters the residual
    ## '<', so none of these inject any more.
    "ws_space_anchor": "< a href='http://example.com'>x</a>",
    "ws_tab_anchor": "<\ta href='http://example.com'>x",
    "ws_newline_anchor": "<\na href='http://example.com'>x",
    "ws_multi_anchor": "<  \t\n a href='http://example.com'>x",
    "ws_upper_anchor": "< A HREF='http://example.com'>x",
    "ws_space_img": "< img src='http://example.com/p.png'>",
    "ws_space_img_file": "< img src='file:///etc/hostname'>",
    "ws_img_no_close": "< img src='http://example.com/p.png'",
}

## Bypasses that are still known-unfixed in the DEPLOYED sanitize-string. Strict
## xfail: a name listed here is expected to inject; if it no longer injects the
## suite FAILS asking you to promote it to a hard control. The parser-
## differential '< tag' bypasses (ws_* below) were the tracked finding here --
## '<' + whitespace + a tag name was inert to Python's html.parser but Qt's
## parser skipped the whitespace and built the tag. The root fix landed in
## helper-scripts strip_markup (neuter residual '<'); the fixed sanitize-string
## now blocks all of them, so they were promoted out of KNOWN_VULN and are
## asserted as hard controls in the loop below (not injected -> PASS; any
## reappearance -> a hard FAIL as a NEW injection vector). The registry is now
## empty. See the sanitize-string-tests suite for the parser-differential proof.
KNOWN_VULN = set()

## The variable the shipped script assigns the sanitized argument to; a function
## builds a display context for the untrusted value iff its msg interpolates it.
DISPLAYED_VALUE_VAR = "input_object_stripped_and_trimmed"

## The shipped functions that build a dialog message embedding the displayed
## argument, and the fixture each needs to reach that message. We source the
## REAL function and drive it -- bash parses its msg="..." natively, so a value
## that flows into an attribute (href/src) or out of the inert <code><blockquote>
## guard is caught, which a regex over the script text cannot see.
##
##   preamble  - bash setup so the function reaches its value-bearing branch
##               (stub browser detection / the qubes open tool / qubesdb).
DIALOG_FUNCTIONS = {
    ## Main confirmation dialog. Sets msg and returns; final() shows it. With no
    ## browser found and a non-empty argument it takes the "will be opened"
    ## branch (the <code><blockquote> wrapper).
    "workstation": (
        'has() { return 1; }\n'
        'is_file=0\n'
        'open_in_tool_bin=""\n'
        'open_in_tool_bin_name=""\n'
        'open_in_tool_bin_name_readlink=""\n'
        'skip_open_link_confirmation=""\n'
    ),
    ## Qubes redirect error dialog. Reaches its msg only when the open tool
    ## fails with output other than "Request refused".
    "qubes_redirect": (
        'qubesdb-read() { printf "vm\\n"; }\n'
        '__olc_open_tool() { printf "open failed\\n"; return 3; }\n'
        'link_confirmation_vm_open_tool=__olc_open_tool\n'
    ),
    ## Sysmaint redirect error dialog. No preconditions before its msg.
    "sysmaint_redirect": "",
}


def extract_function(source, name):
    """Return the verbatim shipped definition of bash function NAME (its
    'name() {' line through the matching top-level '}'), or None."""
    lines = source.splitlines(keepends=True)
    start = None
    opener = re.compile(r"^" + re.escape(name) + r"\(\)\s*\{")
    for index, line in enumerate(lines):
        if opener.match(line):
            start = index
            break
    if start is None:
        return None
    for index in range(start + 1, len(lines)):
        if re.match(r"^\}", lines[index]):
            return "".join(lines[start:index + 1])
    return None


def neutralize_terminal_call(func_src):
    """Replace the generic_gui_message.py invocation (which would spawn the real
    dialog and exit) with a capture of the msg the function just built, so a
    function that fires-and-exits instead emits its message text."""
    out = []
    for line in func_src.splitlines(keepends=True):
        stripped = line.lstrip()
        if "generic_gui_message.py" in line and not stripped.startswith("#"):
            indent = line[: len(line) - len(stripped)]
            out.append(indent + '{ printf "%s" "${msg}"; exit 0; }\n')
        else:
            out.append(line)
    return "".join(out)


def render_dialog_msg(name, value):
    """Source the REAL shipped function NAME and run it to the branch that
    displays the argument, returning the exact msg HTML it builds with VALUE
    substituted for the displayed argument. Returns None if the function is
    absent."""
    func_src = extract_function(SCRIPT_SOURCE, name)
    if func_src is None:
        return None
    func_src = neutralize_terminal_call(func_src)
    driver = (
        "set +e +u\n"
        'input_type="link"\n'
        'input_object_original="http://example.com/x"\n'
        + DISPLAYED_VALUE_VAR + '="${WRAP_VALUE}"\n'
        'extra_long_link=""\n'
        'tb_title="Tor Browser"\n'
        'title=""; msg=""; question=""; button=""\n'
        + DIALOG_FUNCTIONS[name]
        + func_src
        + name + "\n"
        + 'printf "%s" "${msg}"\n'
    )
    child_env = dict(os.environ)
    child_env["WRAP_VALUE"] = value
    ## The shipped functions call bare `sanitize-string`; make the wired binary's
    ## directory resolvable so they run as they would installed.
    bindir = os.path.dirname(SANITIZE_STRING)
    if bindir:
        child_env["PATH"] = bindir + os.pathsep + child_env.get("PATH", "")
    proc = subprocess.run(
        ["bash", "-c", driver],
        capture_output=True,
        check=False,
        env=child_env,
    )
    return proc.stdout.decode("utf-8", "replace")


def qt_active_markup(qtgui, html):
    """Parse html with a real Qt QTextDocument and return (anchors, images)
    actually materialized in the rendered document."""
    doc = qtgui.QTextDocument()
    doc.setHtml(html)
    anchors = set()
    images = set()
    block = doc.begin()
    while block.isValid():
        iterator = block.begin()
        while not iterator.atEnd():
            frag = iterator.fragment()
            if frag.isValid():
                fmt = frag.charFormat()
                if fmt.anchorHref():
                    anchors.add(fmt.anchorHref())
                if fmt.isImageFormat():
                    images.add(fmt.toImageFormat().name())
            iterator += 1
        block = block.next()
    return anchors, images


## A benign, ASCII, sanitize-string-preserved marker that proves a fixture
## actually reaches the branch that displays the argument -- if the rendered msg
## does not contain it, the function changed shape and the differential would be
## testing an empty/wrong string (a vacuous pass), so that is a hard failure.
FIXTURE_MARKER = "OLCMARKER12345"


def run_qt_differential(results):
    print("[B] Qt rich-text differential (real QTextDocument parse)")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PyQt5 import QtGui, QtWidgets
    except Exception as exc:  # pylint: disable=broad-except
        results.skip("qt:all", "PyQt5 unavailable: " + str(exc))
        return

    app = QtWidgets.QApplication.instance()
    if app is None:
        app = QtWidgets.QApplication(sys.argv)
    assert app is not None  # keep the QApplication alive for the widgets built below

    ## Drive each SHIPPED dialog function, not a copy of its wrapper: if the
    ## dialog embeds the value in a new/weaker HTML context (an attribute, or
    ## dropping the <code> guard), driving the real function reflects it.
    covered = 0
    for name in DIALOG_FUNCTIONS:
        if extract_function(SCRIPT_SOURCE, name) is None:
            ## A dialog function that is absent is a real change in the display
            ## surface, not something to skip silently.
            results.fail(
                "qt:" + name + ":present",
                "dialog function " + name + "() not found in " + SCRIPT,
            )
            continue

        ## Anti-vacuous: the fixture must reach the branch that shows the
        ## argument. Prove it by rendering a marker value and requiring it back.
        probe = render_dialog_msg(name, FIXTURE_MARKER)
        if probe is None or FIXTURE_MARKER not in probe:
            results.fail(
                "qt:" + name + ":reaches-display",
                "fixture no longer drives " + name + "() to a message that "
                "displays the argument (marker absent); rendered="
                + repr((probe or "")[:80]),
            )
            continue
        results.ok("qt:" + name + ":reaches-display")
        covered += 1

        ## Baseline: the real wrapper with an inert placeholder must itself
        ## introduce no anchors or images, so anything new is attributable to
        ## the argument.
        base_anchors, base_images = qt_active_markup(
            QtGui, render_dialog_msg(name, "PLACEHOLDER")
        )
        if base_anchors or base_images:
            results.fail(
                "qt:" + name + ":baseline",
                name + "() wrapper itself yields anchors="
                + str(base_anchors) + " images=" + str(base_images)
                + " -- the displayed value is in an active HTML context.",
            )
            continue
        results.ok("qt:" + name + ":baseline")

        for case, arg in INJECTION_CASES.items():
            sanitized = run_sanitize(arg).decode("ascii", "replace")
            html = render_dialog_msg(name, sanitized)
            anchors, images = qt_active_markup(QtGui, html)
            new_anchors = anchors - base_anchors
            new_images = images - base_images
            injected = bool(new_anchors or new_images)
            detail = (
                "sanitized=" + repr(sanitized[:60])
                + " anchors=" + str(new_anchors) + " images=" + str(new_images)
            )
            known = case in KNOWN_VULN
            if injected and known:
                results.xfail("qt:" + name + ":" + case, detail)
            elif injected and not known:
                results.fail(
                    "qt:" + name + ":" + case,
                    "NEW injection vector (not in KNOWN_VULN) in " + name
                    + "(): " + detail,
                )
            elif not injected and known:
                results.fail(
                    "qt:" + name + ":" + case,
                    "expected-fail case no longer injects -> the bypass appears "
                    "FIXED; promote it out of KNOWN_VULN to a hard control. "
                    + detail,
                )
            else:
                results.ok("qt:" + name + ":" + case)

    if covered == 0:
        results.fail(
            "qt:coverage",
            "no shipped dialog function could be driven to display the "
            "argument; the differential tested nothing.",
        )


## ---------------------------------------------------------------------------
## Group C: static audit of the script source
## ---------------------------------------------------------------------------

def run_static_audit(results):
    print("[C] static audit of " + SCRIPT)
    source = SCRIPT_SOURCE

    ## C1: the displayed representation of the argument is produced by
    ## sanitize-string.
    produced_by_sanitize = re.search(
        r"input_object_stripped_and_trimmed=\"\$\(\s*\S*sanitize-string\b",
        source,
    )
    if produced_by_sanitize:
        results.ok("audit:sanitized-via-sanitize-string")
    else:
        results.fail(
            "audit:sanitized-via-sanitize-string",
            "input_object_stripped_and_trimmed is not assigned from "
            "sanitize-string output",
        )

    ## C2: no displayed message embeds the RAW argument. Collect every
    ## title=/msg=/question= assignment body (possibly multi-line, "..."
    ## quoted) plus every generic_gui_message invocation, and assert none
    ## interpolate the raw argument variable or "$@"/"$*".
    raw_tokens = [
        "$input_object_original",
        "${input_object_original}",
        '"$@"',
        '"$*"',
    ]
    ## Match title=/msg=/question= (optionally 'local'-prefixed) assignments
    ## anchored at the start of a line, so commented-out lines (e.g. the
    ## '#msg="..."' note in gateway()) are excluded.
    display_assign = re.compile(
        r'^[ \t]*(?:local[ \t]+)?(?:title|msg|question)='
        r'"(?P<body>(?:[^"\\]|\\.)*)"',
        re.DOTALL | re.MULTILINE,
    )
    offenders = []
    for match in display_assign.finditer(source):
        body = match.group("body")
        for token in raw_tokens:
            if token in body:
                offenders.append(token)
    ## generic_gui_message arguments are built from the title/msg/question
    ## variables above, so auditing those assignments covers the call sites.
    if offenders:
        results.fail(
            "audit:no-raw-argument-in-display",
            "raw argument tokens found in displayed message(s): "
            + ", ".join(sorted(set(offenders))),
        )
    else:
        results.ok("audit:no-raw-argument-in-display")


def main():
    print("open-link-confirmation security test harness")
    print("script:         " + SCRIPT)
    print("sanitize-string: " + SANITIZE_STRING)
    if not os.path.exists(SANITIZE_STRING):
        print("ERROR: sanitize-string not found; set SANITIZE_STRING_BIN")
        return 2
    if not os.path.exists(SCRIPT):
        print("ERROR: open-link-confirmation not found; set "
              "OPEN_LINK_CONFIRMATION_BIN")
        return 2
    global SCRIPT_SOURCE
    try:
        with open(SCRIPT, "r", encoding="utf-8") as handle:
            SCRIPT_SOURCE = handle.read()
    except OSError as exc:
        print("ERROR: cannot read open-link-confirmation script: " + str(exc))
        return 2
    print()

    results = Results()
    run_contract(results)
    print()
    run_qt_differential(results)
    print()
    run_static_audit(results)
    print()

    total = results.passed + results.failed + results.xfailed
    print(
        str(results.passed) + " passed, "
        + str(results.failed) + " failed, "
        + str(results.xfailed) + " xfailed (known/unfixed), "
        + str(results.skipped) + " skipped, "
        + "out of " + str(total) + " checks"
    )
    if results.xfailed:
        print(
            "NOTE: "
            + str(results.xfailed)
            + " known-unfixed markup-injection bypass(es) are present "
            "(< + whitespace + tag survives sanitize-string but Qt renders "
            "it). See KNOWN_VULN in this file."
        )
    if results.failed:
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
