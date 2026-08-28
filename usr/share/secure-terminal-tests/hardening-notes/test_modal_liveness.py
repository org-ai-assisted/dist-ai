#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Modal-site liveness TRIPWIRE for secure_terminal (main.py + terminal.py).

Turns the manual "grep every Qt modal and check for a stale-widget use-after-modal"
sweep -- which three rounds of eyeball audit each missed a member of -- into a
mechanical source invariant. It STATICALLY parses the two source files (never imports
Qt) and inventories every blocking modal call:
  - QMessageBox.<anything>(...)           (question/warning/information/critical/...)
  - QInputDialog/QFileDialog/QColorDialog/QFontDialog.get*(...)
  - <dialog-instance>.exec()              (a QDialog/QMessageBox built in the function)

For each site it demands ONE of:
  (a) its enclosing function later calls a liveness re-check -- _tab_is_live(...),
      self.tabs.indexOf(...), self.current(), or guards on self._closing_tabs -- after
      the modal (the fix pattern for a captured term/widget used post-modal); OR
  (b) the (function, callee) pair is in KNOWN_SAFE with a reason (no widget captured,
      or nothing touched after the modal); OR
  (c) the .exec() is a classified non-dialog loop (QMenu/QApplication) in NON_DIALOG_EXEC.

Anything else FAILS. So a newly-added unguarded modal -- the exact recurrence the manual
sweep could not prevent -- trips this. It is a TRIPWIRE, not a proof: an AST matcher
cannot show a guard protects the RIGHT object or dominates every post-modal dereference
(the adversarial Qt event-sequence suite in the hardening proposal covers that). The
allowlist is keyed by (function, callee) -- stable across line shifts (unlike exact
line/col), so ordinary edits do not churn it, while a new modal TYPE in a function, or an
existing site losing its guard, still trips. A function with two identical modal callees
is the one blind spot; flagged here rather than silently trusted.

Run standalone: python3 test_modal_liveness.py  (SECURE_TERMINAL_REPO overrides the source
root; unset -> the operator's private-sources checkout).

KNOWN LIMITS -- this is a TRIPWIRE, not a proof. Read before promoting it to a REQUIRED
gate (as a prototype it is inert). It attests truth AT REVIEW TIME, and these are its
false-attestation directions:
  - Guard match is by NAME (receiver-qualified: self._tab_is_live / self.tabs.indexOf /
    self.current), not a proof the guarded object is the CAPTURED one, nor that the guard
    DOMINATES every post-modal dereference (a guard in any later branch/closure counts --
    path-insensitive).
  - The allowlist is keyed by (function, callee): a NEW modal type in a function trips, but
    a site whose BODY changes to become unsafe under the SAME callee stays silently
    exempted, and a cross-function reason can go stale invisibly (e.g. _confirm_running_close
    is safe only because close_tab owns the _closing_tabs guard). Therefore EVERY allowlist
    entry is a SECURITY-SENSITIVE assertion that must be RE-REVIEWED on any modal-touching
    change to its function -- not a permanent waiver. The semantic complement (the P0
    event-sequence suite in the README) is what actually proves the guard protects the right
    object; this tripwire only catches "a guard/classification was removed or a new modal
    appeared".
"""

import ast
import os
import sys
from pathlib import Path

## Static/instance modal APIs. get* is matched for the dialog classes so a newly used
## getInt/getItem/getMultiLineText variant is covered without a code change here.
_STATIC_GET_CLASSES = {"QInputDialog", "QFileDialog", "QColorDialog", "QFontDialog"}
_DIALOG_BASES = {"QDialog", "QMessageBox", "QInputDialog", "QFileDialog",
                 "QColorDialog", "QFontDialog"}
## Markers that RE-RESOLVE a live target after a modal returns (the fix pattern).
## RECEIVER-QUALIFIED, not a bare method name: `current`/`indexOf` are generic, so an
## unrelated future `foo.current()` / `list.indexOf(x)` after a modal must NOT falsely
## attest "guarded". (This is still a NAME match, not a proof the guarded object is the
## captured one -- see the module docstring's stated limits.)
_GUARD_CALLS = {"self._tab_is_live", "self.tabs.indexOf", "self.current"}
_GUARD_ATTRS = {"self._closing_tabs"}

## .exec() sites that run an event loop but are NOT QDialog modals holding a captured
## widget -- classified, never a stale-widget waiver. Keyed by (function, callee).
NON_DIALOG_EXEC = {
    ("_tab_context_menu", "menu.exec"): "QMenu.exec for the tab context menu, not a dialog",
    ("contextMenuEvent", "_reviewed_context_menu().exec"):
        "QMenu.exec for the editor context menu; the handler captures no term",
    ("main", "app.exec"): "QApplication.exec is the app's outer event loop",
}

## Modal sites that need NO liveness re-check: they capture no terminal/tab widget, or
## touch nothing lifecycle-sensitive after the modal. Keyed by (function, callee) so a
## line shift does not invalidate them; a NEW modal in the function still trips.
KNOWN_SAFE = {
    ("new_tab_running", "QInputDialog.getText"):
        "creates a NEW tab from the input; captures no existing term",
    ("show_command_palette", "QInputDialog.getText"):
        "runs the text via run_command, which re-resolves self.current() itself",
    ("_show_security_details", "dialog.exec"):
        "detail dialog captures no term and does nothing after exec",
    ("_pick_bell_sound", "QFileDialog.getOpenFileName"):
        "sets a window-global bell path; captures no term",
    ("_pick_bell_sound", "QMessageBox.warning"):
        "terminal-independent warning; returns immediately after",
    ("choose_font", "QFontDialog.getFont"):
        "reads the family BEFORE the modal; set_font_family after re-resolves the target",
    ("_do_save", "QMessageBox.warning"):
        "validation warning inside the still-open shortcuts dialog; no term",
    ("show_shortcuts", "dialog.exec"):
        "shortcuts dialog captures no term and does nothing after exec",
    ("show_about", "dialog.exec"):
        "about dialog captures no term and does nothing after exec",
    ("run_command", "QMessageBox.information"):
        "the /help message captures no widget; returns a status after",
    ("show_global_settings", "dialog.exec"):
        "_apply_global iterates the LIVE tabs after; no single captured term is reused",
    ("_confirm_running_close", "QMessageBox.question"):
        "returns only a bool; close_tab (its caller) owns the _closing_tabs guard + reresolve",
    ("show_locations", "dialog.exec"):
        "locations dialog captures no term; button callbacks carry path strings only",
}


def _source_root():
    env = os.environ.get("SECURE_TERMINAL_REPO")
    base = Path(env) if env else Path("/home/user/private-sources/secure-terminal")
    return base / "usr/lib/python3/dist-packages/secure_terminal"


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _is_modal(node):
    """Return a normalised callee label when `node` is a blocking modal, else None."""
    callee = _dotted(node.func)
    parts = callee.split(".")
    if len(parts) >= 2:
        owner, method = parts[-2], parts[-1]
        if owner == "QMessageBox":
            return f"QMessageBox.{method}"
        if owner in _STATIC_GET_CLASSES and method.startswith("get"):
            return f"{owner}.{method}"
    ## `.exec()` on ANY receiver -- a named dialog/menu OR one built inline
    ## (self._make_menu(...).exec()), which _dotted() would otherwise flatten to bare
    ## "exec" and miss. Label a call-result receiver by the builder's name so the
    ## (function, callee) allowlist key stays stable.
    if isinstance(node.func, ast.Attribute) and node.func.attr in ("exec", "exec_"):
        attr = node.func.attr                    # match PyQt5 .exec_ too, not just .exec
        if callee.endswith("." + attr) and callee != attr:
            return callee
        recv = node.func.value
        if isinstance(recv, ast.Call):
            builder = _dotted(recv.func).split(".")[-1]
            return f"{builder}().{attr}" if builder else f"<expr>().{attr}"
        return f"<expr>.{attr}"
    return None


def _guards_after(func_node, modal_lineno):
    """True if the function re-resolves a live target after `modal_lineno`."""
    for node in ast.walk(func_node):
        if getattr(node, "lineno", 0) <= modal_lineno:
            continue
        if isinstance(node, ast.Call) and _dotted(node.func) in _GUARD_CALLS:
            return True
        if isinstance(node, ast.Attribute) and _dotted(node) in _GUARD_ATTRS:
            return True
    return False


class _Collector(ast.NodeVisitor):
    """Attribute each modal Call to its INNERMOST enclosing function (a call in a nested
    def / lambda belongs to that inner scope, not the outer one)."""

    def __init__(self):
        self.stack = []            # (name, node) of the enclosing function scope
        self.modals = []           # (func_name, func_node, callee_norm, call_node)

    def _enter(self, name, node):
        self.stack.append((name, node))
        self.generic_visit(node)
        self.stack.pop()

    def visit_FunctionDef(self, node):
        self._enter(node.name, node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        ## a call in a deferred lambda callback is not a post-modal guard of the enclosing
        ## function -- give it its own (unnameable) scope so it is not mis-attributed
        self._enter("<lambda>", node)

    def visit_Call(self, node):
        modal = _is_modal(node)
        if modal is not None and self.stack:
            name, func_node = self.stack[-1]
            self.modals.append((name, func_node, modal, node))
        self.generic_visit(node)


def _audit(path):
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src, filename=str(path))
    collector = _Collector()
    collector.visit(tree)
    findings, inventory = [], []
    for func_name, func_node, modal, node in collector.modals:
        key = (func_name, modal)
        inventory.append((path.name, func_name, modal, node.lineno))
        if key in NON_DIALOG_EXEC or key in KNOWN_SAFE:
            continue
        if ".exec" in modal and _receiver_is_dialog(node, func_node) is False:
            findings.append((path.name, func_name, modal, node.lineno,
                             "unclassified .exec() -- add to NON_DIALOG_EXEC or KNOWN_SAFE"))
            continue
        if _guards_after(func_node, node.lineno):
            continue
        findings.append((path.name, func_name, modal, node.lineno,
                         "no post-modal liveness re-check and not in KNOWN_SAFE"))
    return inventory, findings


def _receiver_is_dialog(call_node, func_node):
    """Best-effort: is the .exec() receiver a QDialog/QMessageBox? None if undecidable
    (treated as a real dialog -> must be guarded/allowlisted), False only when clearly a
    constructed non-dialog is not provable -- kept conservative (fail closed)."""
    func = call_node.func
    ## X(...).exec(): decide by the constructor.
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Call):
        ctor = _dotted(func.value.func).split(".")[-1]
        return ctor in _DIALOG_BASES
    ## name.exec(): find where `name` was assigned in the function.
    receiver = _dotted(func).removesuffix(".exec")
    for node in ast.walk(func_node):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if _dotted(tgt) == receiver and isinstance(node.value, ast.Call):
                    ctor = _dotted(node.value.func).split(".")[-1]
                    if ctor in _DIALOG_BASES:
                        return True
                    ## a known non-dialog receiver (menu = QMenu(...)) -> not a dialog
                    if ctor in {"QMenu"}:
                        return False
    return None  ## undecidable -> caller treats as a dialog (conservative)


def main():
    root = _source_root()
    targets = [root / "main.py", root / "terminal.py"]
    missing = [t for t in targets if not t.exists()]
    if missing:
        sys.stderr.write("test_modal_liveness: source not found: %s "
                         "(set SECURE_TERMINAL_REPO)\n" % ", ".join(map(str, missing)))
        return 1
    all_inventory, all_findings = [], []
    for t in targets:
        inv, find = _audit(t)
        all_inventory += inv
        all_findings += find
    print("modal-site inventory (%d sites):" % len(all_inventory))
    for fname, func, modal, lineno in sorted(all_inventory):
        verdict = "FAIL" if any(f[:4] == (fname, func, modal, lineno)
                                for f in all_findings) else "ok"
        print("  [%s] %s:%d  %s.%s" % (verdict, fname, lineno, func, modal))
    if all_findings:
        print("\nFAIL: %d modal site(s) are neither guarded nor classified:"
              % len(all_findings))
        for fname, func, modal, lineno, why in sorted(all_findings):
            print("  %s:%d  %s -> %s  (%s)" % (fname, lineno, func, modal, why))
        print("\nEach must either re-resolve a live target after the modal "
              "(_tab_is_live / tabs.indexOf / current), or be added to KNOWN_SAFE / "
              "NON_DIALOG_EXEC with a reason -- a security-sensitive review.")
        return 1
    print("\nPASS: every modal site is guarded or explicitly classified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
