## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""LPE sink detection for root-privileged shell scripts (the analysis engine
behind dm-root-lpe-audit).

Given a shfmt AST of a script that runs as ROOT, flag the operations that turn
root privilege into a Local Privilege Escalation when they touch a path an
unprivileged user controls -- root writing/chowning recursively inside a home,
following a user symlink, sourcing a user file, a predictable /tmp race, a
world-writable grant, a user-influenced PATH, or trusting $SUDO_USER without
validation.

SCOPE, stated honestly (this is a candidate generator, not a verdict):
  - TAINT is a heuristic over/under-approximation: a path word is 'tainted'
    when it names a user-controlled location by LITERAL prefix (/home, /tmp,
    ...) or expands a user-controlled PARAMETER (HOME, SUDO_USER, user_name,
    home_dir, ...), propagated by a LIGHT in-file dataflow. Cross-file and
    read-from-pipe flows are not tracked -- so a real sink can be missed, and a
    tainted-looking constant can over-report. Exploitability is a REVIEW
    judgement a human makes on each candidate; the tool never claims it.
  - Shell only. A Python root script gets an advisory regex pass elsewhere.

The bash structure (command position, option-vs-operand, quoting, expansions)
is answered by dist_ai.bash_ast (shfmt), never a regex -- so 'chown' inside a
string, or a flag that eats the next word, is handled by the parser.
"""

import re

from dist_ai import bash_ast


## A path naming a location an unprivileged user OWNS by literal prefix -- the
## symlink-in-my-home class. Kept DISJOINT from the temp prefixes below: a
## shared temp path is the predictable-name (tmp-race) class, not this one, so
## the two never double-classify the same operand.
TAINT_LITERAL_PREFIXES = ("/home/",)
## Predictable (non-mktemp) temp locations -- the TOCTOU / symlink-in-/tmp class.
TMP_LITERAL_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")

## Parameters whose value an unprivileged user influences. HOME/USER/LOGNAME and
## the sudo-set SUDO_* come from the invoking (unprivileged) side; the project
## names are derivative-maker's own idioms for "the target user / their home".
BASE_TAINT_PARAMS = frozenset((
    "HOME", "USER", "LOGNAME",
    "SUDO_USER", "SUDO_UID", "SUDO_GID", "SUDO_COMMAND",
))
PROJECT_TAINT_PARAMS = frozenset((
    "user_name", "target_user", "home_dir", "home_folder",
    "user_entry", "user_home", "USERHOME", "USERNAME",
))
## The subset whose trust is an environment/argv decision a reviewer must ratify
## (is this user name validated before it selects a home?).
TRUST_BOUNDARY_PARAMS = frozenset(("SUDO_USER", "SUDO_UID", "SUDO_GID"))
## A call to any of these in the file is evidence the user name/path IS
## validated, so a $SUDO_USER-derived path is not blindly trusted.
VALIDATOR_NAMES = frozenset((
    "is_name_valid", "validate_safe_filename", "is_whole_number", "getent",
))

## argv positional expansions are caller-controlled input.
ARGV_PARAM_RE = re.compile(r"^(?:[1-9][0-9]*|[@*])$")

## Recursive-write sinks and the flags that make each one recurse.
RECURSIVE_WRITE_CMDS = frozenset((
    "chown", "chgrp", "chmod", "cp", "rm", "mv", "rsync", "tar", "install",
))
## Commands where operand[0] is a MODE/OWNER spec, not a path.
NONPATH_FIRST_OPERAND = frozenset(("chown", "chgrp", "chmod"))
RECURSIVE_SHORT = frozenset("rR")
RECURSIVE_LONG = frozenset(("recursive", "archive"))
## Flags that make a sink FOLLOW a symlink (the user-planted-symlink escalation).
SYMLINK_SHORT = frozenset("LH")
SYMLINK_LONG = frozenset(("dereference",))
## Value-taking options per sink, so 'install -m 700 <path>' does not read 700
## as a path operand and '--mode' consumes its value.
SINK_VALUE_SHORT = {
    "install": frozenset("mogtT"),
    "cp": frozenset("tS"),
    "mv": frozenset("t"),
    "rsync": frozenset("e"),
    "tar": frozenset("fCT"),
    "chown": frozenset(),
    "chgrp": frozenset(),
    "chmod": frozenset(),
    "rm": frozenset(),
}
SINK_VALUE_LONG = {
    "install": frozenset(("mode", "owner", "group", "target-directory",
                          "suffix", "backup")),
    "cp": frozenset(("target-directory", "suffix", "backup")),
    "mv": frozenset(("target-directory", "suffix", "backup")),
    "chown": frozenset(("from", "reference")),
    "chgrp": frozenset(("reference",)),
    "chmod": frozenset(("reference",)),
    "rsync": frozenset(("rsh", "chmod", "chown")),
    "tar": frozenset(("file", "directory")),
    "rm": frozenset(),
}

SOURCE_CMDS = frozenset((".", "source"))
SHELL_INTERPRETERS = frozenset(("bash", "sh", "dash", "ksh"))
WRITE_TARGET_CMDS = frozenset(("tee", "touch", "dd", "install", "cp", "mv"))

## A mode that grants write to 'other' (world-writable): octal whose last (other)
## digit has the 2 bit, or a symbolic 'o+w'/'a+w'/'o=...w'.
WORLD_WRITE_OCTAL_RE = re.compile(r"^0?[0-7]{0,3}([0-7])$")
WORLD_WRITE_SYMBOLIC_RE = re.compile(r"(?:^|,)(?:[uga]*o|a)[-+=][^,]*w")


def _word_raw(word, source):
    """A word's spelling: its literal value if fully literal, else raw source
    (so an expansion like '"${home_dir}/x"' keeps its text)."""
    literal = bash_ast.word_string(word)
    return literal if literal is not None else bash_ast.word_source(word, source)


def _op_text(redirect, source):
    """The redirection operator's source text ('>', '>>', '2>', '&>'). shfmt's
    numeric Op code is version-specific, so read the operator from the source
    span instead of pinning the integer."""
    data = source.encode("utf-8")
    start = redirect.get("OpPos", {}).get("Offset")
    word = redirect.get("Word") or {}
    end = word.get("Pos", {}).get("Offset")
    if start is None or end is None or end < start:
        return ""
    return data[start:end].decode("utf-8", "replace").strip()


def mktemp_vars(tree, source):
    """Names of variables assigned from a mktemp command substitution, e.g.
    'tmp="$(mktemp -d)"'. A temp path built from one of these is NOT a
    predictable-name race, so it is excluded from tmp-race."""
    names = set()
    for call in bash_ast.call_exprs(tree):
        for assign in bash_ast.assigns(call):
            value = bash_ast.assign_value(assign)
            if value is None:
                continue
            if "mktemp" in bash_ast.word_source(value, source):
                name = bash_ast.assign_name(assign)
                if name:
                    names.add(name)
    return names


def tainted_params(tree, source):
    """The set of parameter names that are user-controlled in TREE: the seed set
    plus a light in-file dataflow -- a variable assigned a value that expands an
    already-tainted parameter, names a tainted literal prefix, or reads argv,
    becomes tainted; 'for v in <tainted...>' taints v. Iterated to a fixpoint.

    HONEST SCOPE: intra-file only. A value read from a pipe ('find ... | while
    read v') or another file is not propagated -- that under-approximation is
    why the find-walk rule flags the tainted WALK directly, not only its reads.
    """
    tainted = set(BASE_TAINT_PARAMS) | set(PROJECT_TAINT_PARAMS)
    assignments = []
    for call in bash_ast.call_exprs(tree):
        for assign in bash_ast.assigns(call):
            name = bash_ast.assign_name(assign)
            value = bash_ast.assign_value(assign)
            if name:
                assignments.append((name, value))
    ## 'for NAME in WORDS' -- the loop variable takes each word's taint.
    loop_vars = list(_for_loop_taint_pairs(tree, source))

    changed = True
    while changed:
        changed = False
        for name, value in assignments:
            if name in tainted or value is None:
                continue
            if _value_is_tainted(value, source, tainted):
                tainted.add(name)
                changed = True
        for name, words in loop_vars:
            if name in tainted:
                continue
            if any(_value_is_tainted(w, source, tainted) for w in words):
                tainted.add(name)
                changed = True
    return tainted


def _for_loop_taint_pairs(tree, source):
    for node in bash_ast.nodes_of_type(tree, "ForClause"):
        loop = node.get("Loop") or {}
        name = (loop.get("Name") or {}).get("Value")
        items = loop.get("Items") or []
        if name and items:
            yield name, items


def _value_is_tainted(word, source, tainted):
    names = bash_ast.word_param_names(word)
    if names & tainted:
        return True
    if any(ARGV_PARAM_RE.match(n) for n in names):
        return True
    raw = _word_raw(word, source)
    return any(prefix in raw for prefix in TAINT_LITERAL_PREFIXES)


def taint_kind(word, source, tainted):
    """How WORD is tainted, or None. Order: a validated-trust-boundary param, a
    literal prefix, then an ordinary tainted parameter / argv."""
    names = bash_ast.word_param_names(word)
    raw = _word_raw(word, source)
    if names & TRUST_BOUNDARY_PARAMS:
        return "trust-boundary"
    if any(prefix in raw for prefix in TAINT_LITERAL_PREFIXES):
        return "literal"
    if names & tainted:
        return "param"
    if any(ARGV_PARAM_RE.match(n) for n in names):
        return "argv"
    return None


def _classify(call, source, cmd):
    """(opt_texts, operand_words) for CALL, using the sink's own value-option
    sets so a value is never mistaken for a path operand."""
    opts = []
    operands = []
    for kind, word, text in bash_ast.command_tokens(
            call, source,
            value_short=SINK_VALUE_SHORT.get(cmd, frozenset()),
            value_long=SINK_VALUE_LONG.get(cmd, frozenset())):
        if kind == "opt":
            opts.append(text)
        elif kind == "operand":
            operands.append(word)
    return opts, operands


def _has_short(opts, letters):
    for text in opts:
        if text.startswith("-") and not text.startswith("--"):
            if set(text[1:]) & letters:
                return True
    return False


def _has_long(opts, names):
    for text in opts:
        if text.startswith("--"):
            name = text[2:].split("=", 1)[0]
            if bash_ast.resolve_long(name, names) is not None:
                return True
    return False


def _line_of(word):
    return (word.get("Pos") or {}).get("Line") if word else None


def _finding(rule, sink, line, operand, kind, factors, why):
    factors = dict(factors)
    factors["taint"] = kind
    return {
        "rule": rule,
        "sink": sink,
        "line": line,
        "tainted_operand": operand,
        "factors": factors,
        "why": why,
    }


def _recursive_write_finding(call, source, cmd, tainted):
    opts, operands = _classify(call, source, cmd)
    recursive = _has_short(opts, RECURSIVE_SHORT) or _has_long(opts, RECURSIVE_LONG)
    symlink = _has_short(opts, SYMLINK_SHORT) or _has_long(opts, SYMLINK_LONG)
    path_operands = operands[1:] if cmd in NONPATH_FIRST_OPERAND else operands
    for word in path_operands:
        kind = taint_kind(word, source, tainted)
        if kind is None:
            continue
        deletion = cmd == "rm"
        factors = {
            "recursive": recursive, "symlink": symlink, "deletion": deletion,
            "find_walk": False,
        }
        rule = "home-recursive-write" if (recursive or deletion) else "root-write-user-path"
        why = ("root %s%s a user-controlled path" % (
            cmd, " --recursive" if recursive else ""))
        yield _finding(rule, cmd, _line_of(word), _word_raw(word, source),
                       kind, factors, why)
        if symlink:
            yield _finding("symlink-follow", cmd, _line_of(word),
                           _word_raw(word, source), kind,
                           {"recursive": recursive, "symlink": True},
                           "root %s follows a symlink into a user-controlled path"
                           % cmd)
        return


def _find_walk_finding(call, source, tainted):
    words = bash_ast.args(call)
    ## find PATHS... EXPRESSION : paths precede the first '-'/'('/'!' token.
    path_words = []
    has_action = False
    for word in words[1:]:
        text = _word_raw(word, source)
        if text.startswith("-") or text in ("(", "!"):
            if text in ("-exec", "-execdir", "-delete", "-ok", "-okdir"):
                has_action = True
            continue
        if not path_words or not has_action:
            path_words.append(word)
    for word in path_words:
        kind = taint_kind(word, source, tainted)
        if kind is None:
            continue
        yield _finding(
            "home-recursive-write", "find", _line_of(word),
            _word_raw(word, source), kind,
            {"recursive": True, "find_walk": True, "symlink": False,
             "action": has_action},
            "root 'find' walks a user-controlled tree" + (
                " and acts on it (-exec/-delete)" if has_action else ""))
        return


def _source_eval_finding(call, source, cmd, tainted):
    words = bash_ast.args(call)
    if cmd in SOURCE_CMDS:
        targets = words[1:2]
        rule, why = "untrusted-source-eval", "root sources a user-controlled file"
    elif cmd == "eval":
        targets = words[1:]
        rule, why = "untrusted-source-eval", "root 'eval's user-controlled text"
    elif cmd in SHELL_INTERPRETERS:
        ## bash <script>: first non-option operand is the script.
        _opts, operands = _classify(call, source, cmd)
        targets = operands[:1]
        rule, why = "untrusted-source-eval", "root runs a user-controlled script"
    else:
        return
    for word in targets:
        kind = taint_kind(word, source, tainted)
        if kind is not None:
            yield _finding(rule, cmd, _line_of(word), _word_raw(word, source),
                           kind, {}, why)
            return


def _world_writable_finding(call, source, cmd):
    if cmd not in ("chmod", "install", "mkdir"):
        return
    if cmd == "chmod":
        _opts, operands = _classify(call, source, cmd)
        modes = operands[:1]
    else:
        modes = []
        for kind, word, text in bash_ast.command_tokens(
                call, source,
                value_short=frozenset("m"),
                value_long=frozenset(("mode",))):
            if kind == "value":
                modes.append(word)
            elif kind == "opt" and text.startswith("--mode="):
                modes.append(word)
    for word in modes:
        mode = bash_ast.word_string(word)
        if mode is None:
            continue
        mode = mode.split("=", 1)[-1]
        if _is_world_writable(mode):
            yield _finding("world-writable-perms", cmd, _line_of(word), mode,
                           "literal", {"mode": mode},
                           "root grants world-writable permissions (%s)" % mode)
            return


def _is_world_writable(mode):
    octal = WORLD_WRITE_OCTAL_RE.match(mode)
    if octal:
        return bool(int(octal.group(1)) & 2)
    return bool(WORLD_WRITE_SYMBOLIC_RE.search(mode))


def _trust_sudo_user_finding(call, source, cmd, tainted, validated):
    if validated:
        return
    if cmd not in RECURSIVE_WRITE_CMDS and cmd not in WRITE_TARGET_CMDS \
            and cmd not in SOURCE_CMDS:
        return
    for word in bash_ast.args(call)[1:]:
        if bash_ast.word_param_names(word) & TRUST_BOUNDARY_PARAMS:
            yield _finding(
                "trust-sudo-user", cmd, _line_of(word),
                _word_raw(word, source), "trust-boundary",
                {"trust_boundary": True},
                "root uses $SUDO_USER to pick a target without validating it")
            return


def iter_findings(tree, source):
    """Yield every LPE candidate finding in TREE (a root-run script)."""
    tainted = tainted_params(tree, source)
    validated = _file_validates(tree)
    tmp_safe = mktemp_vars(tree, source)

    for call in bash_ast.call_exprs(tree):
        ## A 'PATH=...' statement has no command word, so run the assignment
        ## rule before the command-word guard skips it.
        yield from _path_assignment_finding(call, source, tainted)
        cmd = bash_ast.command_basename(call)
        if cmd is None:
            continue
        if cmd in RECURSIVE_WRITE_CMDS:
            yield from _recursive_write_finding(call, source, cmd, tainted)
        if cmd == "find":
            yield from _find_walk_finding(call, source, tainted)
        if cmd in SOURCE_CMDS or cmd == "eval" or cmd in SHELL_INTERPRETERS:
            yield from _source_eval_finding(call, source, cmd, tainted)
        if cmd in ("chmod", "install", "mkdir"):
            yield from _world_writable_finding(call, source, cmd)
        yield from _trust_sudo_user_finding(call, source, cmd, tainted, validated)

    yield from _redirect_findings(tree, source, tainted, tmp_safe)
    yield from _tmp_operand_findings(tree, source, tmp_safe)


def _file_validates(tree):
    for call in bash_ast.call_exprs(tree):
        if bash_ast.command_basename(call) in VALIDATOR_NAMES:
            return True
    return False


def _path_assignment_finding(call, source, tainted):
    for assign in bash_ast.assigns(call):
        if bash_ast.assign_name(assign) != "PATH":
            continue
        value = bash_ast.assign_value(assign)
        if value is None:
            continue
        raw = _word_raw(value, source)
        elements = raw.split(":")
        risky = False
        for element in elements:
            stripped = element.strip().strip('"').strip("'")
            if stripped == "" or stripped == ".":
                risky = True
            elif not stripped.startswith(("/", "$")):
                risky = True
        if bash_ast.word_param_names(value) & tainted:
            risky = True
        if risky:
            yield _finding("path-hijack", "PATH=", _line_of(value), raw,
                           "literal", {},
                           "root sets PATH with a relative or user-influenced "
                           "element")


def _redirect_findings(tree, source, tainted, tmp_safe):
    for stmt in bash_ast.iter_stmts(tree):
        for redirect in stmt.get("Redirs") or []:
            op = _op_text(redirect, source)
            if ">" not in op:
                continue
            word = redirect.get("Word")
            if not word:
                continue
            ## A predictable temp target is the tmp-race class; a home/param
            ## target is the symlink class. Disjoint prefixes, tmp checked first.
            if _is_predictable_tmp(word, source, tmp_safe):
                yield _finding(
                    "tmp-race", "redirect", _line_of(word),
                    _word_raw(word, source), "literal", {"redirect": op},
                    "root writes (redirect %s) to a predictable temp path" % op)
                continue
            kind = taint_kind(word, source, tainted)
            if kind is not None:
                yield _finding(
                    "symlink-follow", "redirect", _line_of(word),
                    _word_raw(word, source), kind, {"redirect": op},
                    "root writes (redirect %s) into a user-controlled path" % op)


def _tmp_operand_findings(tree, source, tmp_safe):
    for call in bash_ast.call_exprs(tree):
        cmd = bash_ast.command_basename(call)
        if cmd not in WRITE_TARGET_CMDS:
            continue
        _opts, operands = _classify(call, source, cmd)
        for word in operands:
            if _is_predictable_tmp(word, source, tmp_safe):
                yield _finding(
                    "tmp-race", cmd, _line_of(word), _word_raw(word, source),
                    "literal", {}, "root %s a predictable temp path" % cmd)
                break


def _is_predictable_tmp(word, source, tmp_safe):
    if bash_ast.word_param_names(word) & tmp_safe:
        return False
    raw = _word_raw(word, source)
    return any(prefix in raw for prefix in TMP_LITERAL_PREFIXES)
