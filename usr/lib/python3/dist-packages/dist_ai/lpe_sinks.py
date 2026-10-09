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
    when it names a user-controlled location by LITERAL prefix (/home, ...) or
    expands a user-controlled PARAMETER (HOME, SUDO_USER, user_name, home_dir,
    ...), propagated by a LIGHT in-file dataflow. Cross-file and read-from-pipe
    flows are not tracked -- so a real sink can be missed. Exploitability is a
    REVIEW judgement a human makes on each candidate; the tool never claims it.
  - Shell only. A Python root script gets an advisory regex pass elsewhere.

The bash structure (command position, option-vs-operand, quoting, expansions,
wrapper commands, assignments) is answered by dist_ai.bash_ast (shfmt), never a
regex -- so 'chown' inside a string, a flag that eats the next word, a
'command'/'env' wrapper, or a 'declare' assignment is handled by the parser.
"""

import re

from dist_ai import bash_ast


## A path naming a location an unprivileged user OWNS. Matched at a path
## BOUNDARY (start, quote, space, '(', '=', ':'), NOT as a bare substring, so
## '/opt/not/home/user' does not read as a home path. '/root' is root's OWN
## home (an unprivileged user cannot plant a symlink there), so it is NOT here.
## Kept DISJOINT from the temp prefixes: a shared temp path is the tmp-race
## class, not this one.
_HOME_DIRS = ("/home",)
## These are DETECTION PATTERNS the audit scans for, not temp files this tool
## creates -- bandit B108 is a false positive here. (Bare '# nosec' so an older
## bandit that does not parse a per-test-id suffix still honors it.)
_TMP_DIRS = ("/tmp", "/var/tmp", "/dev/shm")  # nosec
## A path boundary. '-' and '+' admit a parameter-expansion default value
## ('"${VAR:-/home/x}"', '"${VAR:+/home/x}"'), a realistic idiom.
_BOUNDARY = r"""(?:^|[\s"'`({=:><|&+-])"""
_PATH_END = r"""(?:/|["'`)}=:><|&\s]|$)"""


def _dir_regex(dirs):
    alt = "|".join(re.escape(d) for d in dirs)
    return re.compile(_BOUNDARY + "(?:" + alt + ")" + _PATH_END)


TAINT_LITERAL_RE = _dir_regex(_HOME_DIRS)
TMP_LITERAL_RE = _dir_regex(_TMP_DIRS)

## Parameters whose value an unprivileged user influences.
BASE_TAINT_PARAMS = frozenset((
    "HOME", "USER", "LOGNAME",
    "SUDO_USER", "SUDO_UID", "SUDO_GID", "SUDO_COMMAND",
))
PROJECT_TAINT_PARAMS = frozenset((
    "user_name", "target_user", "home_dir", "home_folder",
    "user_entry", "user_home", "USERHOME", "USERNAME",
))
## The subset whose trust is an environment/argv decision a reviewer must ratify.
TRUST_BOUNDARY_PARAMS = frozenset(("SUDO_USER", "SUDO_UID", "SUDO_GID"))
## A call to one of these is evidence the user name IS validated, so a
## $SUDO_USER-derived path is not blindly trusted. Narrow on purpose (an
## over-broad list silently suppresses real findings).
VALIDATOR_NAMES = frozenset(("is_name_valid", "validate_safe_filename"))

ARGV_PARAM_RE = re.compile(r"^(?:[1-9][0-9]*|[@*])$")
## A value produced by mktemp (safe, unpredictable) -- an actual command
## substitution calling mktemp, NOT merely a string containing 'mktemp'.
MKTEMP_RE = re.compile(r"(?:\$\(|`)\s*(?:/usr/bin/|/bin/)?mktemp\b")

## Command wrappers that exec their operand unchanged; peeled to the real sink.
WRAPPERS = frozenset(("command", "exec", "nohup", "setsid", "nice", "ionice",
                      "env", "stdbuf"))
## A wrapper's OWN options that take a separate value word -- so the value is
## not mistaken for the wrapped command ('nice -n 10 chown' -> chown, not '10').
WRAPPER_VALUE_SHORT = {
    "nice": frozenset("n"), "ionice": frozenset("cnp"),
    "stdbuf": frozenset("ioe"), "exec": frozenset("a"), "env": frozenset("uS"),
}
## Only MANDATORY-argument long options belong here. An OPTIONAL-argument option
## ('env --block-signal[=SIG]') takes its value only via '=', so in bare space
## form the next word is the wrapped COMMAND -- consuming it would swallow the
## sink. So block-signal is deliberately absent.
WRAPPER_VALUE_LONG = {
    "env": frozenset(("unset",)),
    "nice": frozenset(("adjustment",)),
}
## Wrappers whose presence of a given short option means 'do not execute a
## command' (a query/lookup mode), so nothing after is a sink.
WRAPPER_NOEXEC_SHORT = {"ionice": frozenset("p")}

## Recursive-write sinks.
RECURSIVE_WRITE_CMDS = frozenset((
    "chown", "chgrp", "chmod", "cp", "rm", "mv", "rsync", "tar", "install",
))
NONPATH_FIRST_OPERAND = frozenset(("chown", "chgrp", "chmod"))
## Options that REPLACE the mode/owner argument, so the first operand IS a path.
## '--from' is NOT one: it only FILTERS (chown --from=OLD NEW-OWNER FILE still
## needs the owner operand), so including it mislabels the owner word as a path.
REF_LONG = frozenset(("reference",))
RECURSIVE_SHORT = frozenset("rR")
RECURSIVE_LONG = frozenset(("recursive", "archive"))
## '-a' is archive (recursive) for cp/rsync only. For tar '-a' is
## --auto-compress (tar recurses directories by default anyway), NOT recursion.
ARCHIVE_SHORT_CMDS = frozenset(("cp", "rsync"))
SYMLINK_SHORT = frozenset("LH")
SYMLINK_LONG = frozenset(("dereference",))
## '-h'/--no-dereference is what stops chown following a NAMED symlink. '-P'/'-H'
## are recursion-traversal flags that only apply with '-R', so they do NOT stop
## the non-recursive named-symlink follow.
NODEREF_SHORT = frozenset("h")
NODEREF_LONG = frozenset(("no-dereference",))

## Value-taking options per sink (so a value is not read as a path operand).
SINK_VALUE_SHORT = {
    "install": frozenset("mog"), "cp": frozenset("tS"), "mv": frozenset("St"),
    "rsync": frozenset("e"), "tar": frozenset("fCT"),
}
## MANDATORY-argument options only. '--backup[=CONTROL]' is OPTIONAL-argument
## (space form does not consume the next word), so it is NOT here -- listing it
## would eat the following operand.
SINK_VALUE_LONG = {
    "install": frozenset(("mode", "owner", "group", "target-directory",
                          "suffix")),
    "cp": frozenset(("target-directory", "suffix", "reference")),
    "mv": frozenset(("target-directory", "suffix")),
    "chown": frozenset(("from", "reference")),
    "chgrp": frozenset(("reference",)), "chmod": frozenset(("reference",)),
    "rsync": frozenset(("rsh", "chown", "chmod", "suffix", "backup-dir")),
    "tar": frozenset(("file", "directory")),
}
## Of those, the options whose VALUE is itself a path write-target.
PATH_VALUE_SHORT = {
    "install": frozenset("t"), "cp": frozenset("t"), "mv": frozenset("t"),
    "tar": frozenset("fC"),
}
PATH_VALUE_LONG = {
    "install": frozenset(("target-directory",)),
    "cp": frozenset(("target-directory",)),
    "mv": frozenset(("target-directory",)),
    "tar": frozenset(("file", "directory")),
    "rsync": frozenset(("backup-dir",)),
}

SOURCE_CMDS = frozenset((".", "source"))
SHELL_INTERPRETERS = frozenset(("bash", "sh", "dash", "ksh"))
## Interpreter options that consume a value (so the script operand is not lost).
SHELL_VALUE_SHORT = frozenset("oO")
SHELL_VALUE_LONG = frozenset(("rcfile", "init-file"))
## Plain write-target commands not covered by the recursive-write rule.
PLAIN_WRITE_CMDS = frozenset(("tee", "touch", "dd"))

WORLD_WRITE_OCTAL_RE = re.compile(r"^0?[0-7]{0,3}([0-7])$")
WORLD_WRITE_CLAUSE_RE = re.compile(r"^([ugoa]*)([-+=])(.*)$")


def _word_raw(word, source):
    literal = bash_ast.word_string(word)
    return literal if literal is not None else bash_ast.word_source(word, source)


def _op_text(redirect, source):
    data = source.encode("utf-8")
    start = redirect.get("OpPos", {}).get("Offset")
    word = redirect.get("Word") or {}
    end = word.get("Pos", {}).get("Offset")
    if start is None or end is None or end < start:
        return ""
    return data[start:end].decode("utf-8", "replace").strip()


def all_assignments(tree):
    """Yield (name, value_word) for every variable assignment: a bare or
    env-prefix 'X=y' (CallExpr.Assigns) AND a 'declare/local/export/readonly/
    typeset X=y' (DeclClause.Args), which shfmt models as a separate node."""
    for call in bash_ast.call_exprs(tree):
        for assign in bash_ast.assigns(call):
            name = bash_ast.assign_name(assign)
            if name:
                yield name, bash_ast.assign_value(assign)
    for decl in bash_ast.nodes_of_type(tree, "DeclClause"):
        for assign in decl.get("Args") or []:
            name = (assign.get("Name") or {}).get("Value")
            if name:
                yield name, assign.get("Value")


def mktemp_vars(tree, source):
    names = set()
    for name, value in all_assignments(tree):
        if value is not None and MKTEMP_RE.search(bash_ast.word_source(value, source)):
            names.add(name)
    return names


def tmp_literal_vars(tree, source, mktemp_safe):
    """Variables assigned a LITERAL predictable temp path ('tmp=/tmp/x'), so a
    later use of the variable is still a predictable-name race -- a substring
    'mktemp' in the name does not make it safe (only a mktemp command sub does)."""
    names = set()
    for name, value in all_assignments(tree):
        if value is None or name in mktemp_safe:
            continue
        if TMP_LITERAL_RE.search(bash_ast.word_source(value, source)):
            names.add(name)
    return names


def tainted_params(tree, source):
    """User-controlled parameter names: the seed set plus a light in-file
    dataflow to a fixpoint. Intra-file only (a pipe-read value is not tracked --
    the find-walk rule flags the tainted WALK directly to cover that)."""
    tainted = set(BASE_TAINT_PARAMS) | set(PROJECT_TAINT_PARAMS)
    assignments = list(all_assignments(tree))
    loop_vars = list(_for_loop_taint_pairs(tree))
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


def _for_loop_taint_pairs(tree):
    for node in bash_ast.nodes_of_type(tree, "ForClause"):
        loop = node.get("Loop") or {}
        name = (loop.get("Name") or {}).get("Value")
        items = loop.get("Items") or []
        if name and items:
            yield name, items


def _value_is_tainted(word, source, tainted):
    names = bash_ast.word_param_names(word)
    if names & tainted or any(ARGV_PARAM_RE.match(n) for n in names):
        return True
    return bool(TAINT_LITERAL_RE.search(_word_raw(word, source)))


def taint_kind(word, source, tainted):
    """How WORD is tainted, or None."""
    names = bash_ast.word_param_names(word)
    raw = _word_raw(word, source)
    if names & TRUST_BOUNDARY_PARAMS:
        return "trust-boundary"
    if TAINT_LITERAL_RE.search(raw):
        return "literal"
    if names & tainted:
        return "param"
    if any(ARGV_PARAM_RE.match(n) for n in names):
        return "argv"
    return None


def _peel_wrappers(call, source):
    """(effective_cmd_basename, synthetic_call) after peeling leading wrapper
    commands ('command chown', 'env A=1 cp', 'exec install'). The synthetic call
    exposes the real command in Args[0] so the option/operand scan reads the
    right positions. None when there is no command word left."""
    words = bash_ast.args(call)
    index = 0
    while index < len(words):
        name = bash_ast.word_string(words[index])
        base = name.rsplit("/", 1)[-1] if name else None
        if base not in WRAPPERS:
            break
        vshort = WRAPPER_VALUE_SHORT.get(base, frozenset())
        vlong = WRAPPER_VALUE_LONG.get(base, frozenset())
        noexec_short = WRAPPER_NOEXEC_SHORT.get(base, frozenset())
        index += 1
        ## Skip the wrapper's own options (and their space-separated VALUES, else
        ## the value is mistaken for the wrapped command). env's NAME=VALUE
        ## operands are consumed in the env post-option phase below.
        while index < len(words):
            text = _word_raw(words[index], source)
            if text == "--":
                index += 1
                break
            if text.startswith("-") and text != "-":
                ## A query/lookup option runs no command ('command -v/-V NAME',
                ## 'ionice -p PID'): nothing after it is a sink.
                if base == "command" and set(text[1:]) & set("vV"):
                    return None, None
                if not text.startswith("--") and set(text[1:]) & noexec_short:
                    return None, None
                if text.startswith("--"):
                    lname = text[2:].split("=", 1)[0]
                    if "=" not in text and bash_ast.resolve_long(lname, vlong):
                        index += 1
                else:
                    ## Mirror getopt cluster semantics: a value-taking letter
                    ## consumes the REST of the cluster as its value; only when
                    ## it is the LAST char does it take the next WORD. So
                    ## '-uPASS' (u not last) does NOT eat the following command.
                    cluster = text[1:]
                    for position, letter in enumerate(cluster):
                        if letter in vshort:
                            if position == len(cluster) - 1:
                                index += 1
                            break
                index += 1
                continue
            break
        ## GNU env operand grammar once getopt has stopped: an optional lone '-'
        ## (ignore-environment), then NAME=VALUE operands, then the command. An
        ## operand is an assignment when it has a LITERAL '=' (env uses no
        ## identifier check, so 'X-Y=1'/'0=1'/'--unset=P'/'"PATH=$PATH"' all
        ## count); a '=' that is only expansion syntax ('"${v:=x}"'/'$((a=1))')
        ## is NOT in env's argv, so it reads as the command, not an assignment.
        ## A '--' here is a literal command name, not an option terminator
        ## (getopt already stopped at the first operand).
        ## Static scope (candidate generator, not a verdict): an UNQUOTED
        ## expansion that word-splits or brace-expands into several argv words,
        ## and an ANSI-C $'...' decoding to a different byte, are RUNTIME values
        ## this AST-level scan cannot resolve, so a crafted/obfuscated operand
        ## may mis-peel -- consistent with the accident-not-adversary scope (see
        ## bash_ast.word_string). A plain assignment/command is resolved exactly.
        if base == "env":
            if index < len(words) and _word_raw(words[index], source) == "-":
                index += 1
            while index < len(words) \
                    and "=" in bash_ast.word_literal_text(words[index]):
                index += 1
    effective = words[index:]
    if not effective:
        return None, None
    cmd = bash_ast.command_basename({"Args": effective})
    return cmd, {"Args": effective}


def _sink_operands(call, source, cmd):
    """(opt_texts, positional_words, opt_path_words) for CALL. opt_path_words are
    the values of path-write-target options (cp -t DIR, tar -f FILE, rsync
    --backup-dir DIR), whether inline or a separate word; positional_words are
    the bare operands. Non-path option values are skipped."""
    value_short = SINK_VALUE_SHORT.get(cmd, frozenset())
    value_long = SINK_VALUE_LONG.get(cmd, frozenset())
    path_short = PATH_VALUE_SHORT.get(cmd, frozenset())
    path_long = PATH_VALUE_LONG.get(cmd, frozenset())
    opts = []
    positionals = []
    opt_paths = []
    last_opt = None
    for kind, word, text in bash_ast.command_tokens(
            call, source, value_short=value_short, value_long=value_long):
        if kind == "opt":
            opts.append(text)
            last_opt = text
            ## An inline path value ('--target-directory=DIR', '-tDIR') is
            ## carried in the option WORD itself; its raw text holds the path.
            if _opt_has_inline_path(text, path_short, path_long):
                opt_paths.append(word)
        elif kind == "operand":
            positionals.append(word)
        elif kind == "value" and _opt_is_path(last_opt, path_short, path_long):
            opt_paths.append(word)
    return opts, positionals, opt_paths


## Copy-style sinks whose WRITE target is the LAST positional (plus any
## path-option value); earlier positionals are READ sources, not an LPE.
COPY_DEST_LAST = frozenset(("cp", "mv", "install", "rsync"))


def _opt_is_path(opt_text, path_short, path_long):
    """A separate next word is this option's path value (space form '-t DIR')."""
    if not opt_text:
        return False
    if opt_text.startswith("--"):
        name = opt_text[2:].split("=", 1)[0]
        return bash_ast.resolve_long(name, path_long) is not None
    return bool(opt_text[1:]) and opt_text[-1] in path_short


def _opt_has_inline_path(opt_text, path_short, path_long):
    """This option carries its path value inline ('--target-directory=DIR',
    '-tDIR'), not as a separate word."""
    if opt_text.startswith("--"):
        if "=" not in opt_text:
            return False
        name = opt_text[2:].split("=", 1)[0]
        return bash_ast.resolve_long(name, path_long) is not None
    cluster = opt_text[1:]
    for position, letter in enumerate(cluster):
        if letter in path_short and position < len(cluster) - 1:
            return True
    return False


def _has_short(opts, letters):
    for text in opts:
        if text.startswith("-") and not text.startswith("--") and set(text[1:]) & letters:
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
    return {"rule": rule, "sink": sink, "line": line,
            "tainted_operand": operand, "factors": factors, "why": why}


def _is_recursive(cmd, opts):
    if _has_short(opts, RECURSIVE_SHORT) or _has_long(opts, RECURSIVE_LONG):
        return True
    ## tar processes a whole archive TREE (create/extract recurse into
    ## directories by default), so a tar write into a user path is recursive.
    if cmd == "tar":
        return True
    return cmd in ARCHIVE_SHORT_CMDS and _has_short(opts, frozenset("a"))


def _symlink_follow(cmd, recursive, opts):
    """(follows, explicit): does the sink follow a symlink in its target, and
    was it requested explicitly (-L/--dereference, higher confidence) vs a
    coreutils default (chown/chmod of a named symlink follows it)."""
    if _has_short(opts, SYMLINK_SHORT) or _has_long(opts, SYMLINK_LONG):
        return True, True
    if cmd in ("chown", "chgrp"):
        follows = (not recursive) and not _has_short(opts, NODEREF_SHORT) \
            and not _has_long(opts, NODEREF_LONG)
        return follows, False
    if cmd == "chmod":
        return (not recursive), False
    return False, False


def _recursive_write_finding(call, source, cmd, tainted, tmp_safe, tmp_vars):
    opts, positionals, opt_paths = _sink_operands(call, source, cmd)
    recursive = _is_recursive(cmd, opts)
    follows, explicit = _symlink_follow(cmd, recursive, opts)
    ref = _has_long(opts, REF_LONG)
    if cmd in NONPATH_FIRST_OPERAND and not ref:
        ## operand[0] is the mode/owner spec, not a path.
        positionals = positionals[1:]
    if cmd == "tar":
        ## tar's positionals are archive MEMBERS; the write target is -f/-C.
        path_operands = list(opt_paths)
    elif cmd in COPY_DEST_LAST:
        ## Destination = a path-option value, else the LAST positional; earlier
        ## positionals are read SOURCES (a tainted source is not a write-LPE).
        path_operands = list(opt_paths) + (positionals[-1:] if positionals else [])
    else:
        ## chown/chgrp/chmod/rm: every path operand is a modify target.
        path_operands = positionals + opt_paths
    ## Check EVERY path operand, not just the first: 'cp -r /tmp/src /home/dst'
    ## must report the home destination even though a temp SOURCE comes first.
    for word in path_operands:
        kind = taint_kind(word, source, tainted)
        if kind is None:
            if _is_predictable_tmp(word, source, tmp_safe, tmp_vars):
                yield _finding("tmp-race", cmd, _line_of(word),
                               _word_raw(word, source), "literal", {},
                               "root %s a predictable temp path" % cmd)
            continue
        deletion = cmd == "rm"
        rule = "home-recursive-write" if (recursive or deletion) else "root-write-user-path"
        yield _finding(rule, cmd, _line_of(word), _word_raw(word, source), kind,
                       {"recursive": recursive, "symlink": follows,
                        "deletion": deletion, "find_walk": False},
                       "root %s%s a user-controlled path"
                       % (cmd, " --recursive" if recursive else ""))
        if follows:
            yield _finding("symlink-follow", cmd, _line_of(word),
                           _word_raw(word, source), kind,
                           {"recursive": recursive, "symlink": True,
                            "symlink_explicit": explicit},
                           "root %s follows a symlink into a user-controlled path"
                           % cmd)


FIND_GLOBAL_OPTS = frozenset(("-L", "-H", "-P"))


def _find_walk_finding(call, source, tainted):
    words = bash_ast.args(call)
    ## Skip find's GLOBAL options (-L/-H/-P/-O*/-D*), which legitimately precede
    ## the walk paths, THEN collect the leading path words, stopping at the first
    ## expression primary (a '-name PATTERN' value is not a walk root).
    index = 1
    while index < len(words):
        text = _word_raw(words[index], source)
        if text == "-D":
            ## '-D debugopts' takes a SEPARATE value; skip it too, else the
            ## value reads as a walk root.
            index += 2
            continue
        if text in FIND_GLOBAL_OPTS or text.startswith("-O") or text.startswith("-D"):
            index += 1
            continue
        break
    path_words = []
    for word in words[index:]:
        text = _word_raw(word, source)
        if text.startswith("-") or text in ("(", "!", ")"):
            break
        path_words.append(word)
    has_action = any(
        _word_raw(w, source) in ("-exec", "-execdir", "-delete", "-ok", "-okdir")
        for w in words[1:])
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
        ## 'source FILE [args]': FILE is the FIRST operand; a LEADING '--' (only)
        ## is an end-of-options marker. A later '--' is an argument TO the file.
        rest = words[1:]
        if rest and bash_ast.word_string(rest[0]) == "--":
            rest = rest[1:]
        targets = rest[:1]
        why = "root sources a user-controlled file"
    elif cmd == "eval":
        targets = words[1:]
        why = "root 'eval's user-controlled text"
    elif cmd in SHELL_INTERPRETERS:
        targets = _shell_script_operand(call, source, cmd)
        why = "root runs a user-controlled script"
    else:
        return
    for word in targets:
        kind = taint_kind(word, source, tainted)
        if kind is not None:
            yield _finding("untrusted-source-eval", cmd, _line_of(word),
                           _word_raw(word, source), kind, {}, why)
            return


RC_LONG = frozenset(("rcfile", "init-file"))
## Shells that source --rcfile/--init-file. Only bash/ksh; dash has no such opt.
RC_INTERPRETERS = frozenset(("bash", "ksh"))


def _shell_script_operand(call, source, cmd):
    """The file(s) a shell interpreter runs as root: the -c inline script, else
    the first operand after options, PLUS a --rcfile/--init-file value but ONLY
    for an INTERACTIVE ('-i') bash/ksh -- a non-interactive shell ignores it (so
    flagging it there is a false positive), and dash has no such option."""
    inline = None
    operands = []
    rc_files = []
    interactive = False
    expect = None
    for kind, word, text in bash_ast.command_tokens(
            call, source, value_short=SHELL_VALUE_SHORT | frozenset("c"),
            value_long=SHELL_VALUE_LONG):
        if kind == "opt":
            expect = text
            if not text.startswith("--") and "i" in text[1:]:
                interactive = True
            if text.startswith("--") and "=" in text \
                    and bash_ast.resolve_long(text[2:].split("=", 1)[0], RC_LONG):
                rc_files.append(word)
        elif kind == "value":
            if expect and expect.startswith("--") \
                    and bash_ast.resolve_long(expect[2:].split("=", 1)[0], RC_LONG):
                rc_files.append(word)
            elif expect and not expect.startswith("--") and expect.endswith("c"):
                inline = word
            expect = None
        elif kind == "operand":
            operands.append(word)
    targets = []
    if interactive and cmd in RC_INTERPRETERS:
        targets.extend(rc_files)
    if inline is not None:
        targets.append(inline)
    elif operands:
        targets.append(operands[0])
    return targets


def _world_writable_finding(call, source, cmd):
    ## Collect (mode_string, line) candidates, then flag the first world-writable
    ## grant. install/mkdir modes come from -m/--mode in either spaced ('-m 777',
    ## '--mode 777'), attached ('-m777') or '=' ('--mode=777') form.
    modes = []
    if cmd == "chmod":
        opts, positionals, _opt_paths = _sink_operands(call, source, cmd)
        ## With --reference the mode comes from a FILE, so operand[0] is a path,
        ## not a literal mode -- do not read it as one.
        if not _has_long(opts, REF_LONG):
            for word in positionals[:1]:
                literal = bash_ast.word_string(word)
                if literal is not None:
                    modes.append((literal, _line_of(word)))
    else:
        for kind, word, text in bash_ast.command_tokens(
                call, source, value_short=frozenset("m"),
                value_long=frozenset(("mode",))):
            if kind == "value":
                literal = bash_ast.word_string(word)
                if literal is not None:
                    modes.append((literal, _line_of(word)))
            elif kind == "opt" and text.startswith("--mode="):
                modes.append((text.split("=", 1)[1], _line_of(word)))
            elif kind == "opt" and re.match(r"^-[a-zA-Z]*m.", text):
                ## Attached short mode: '-m777' (m not last in the cluster).
                modes.append((text.split("m", 1)[1], _line_of(word)))
    for mode, line in modes:
        ## NOTE: do NOT split on '=' here -- a symbolic mode ('a=w') USES '=' as
        ## its operator; the '--mode=' prefix was already stripped above.
        if _is_world_writable(mode):
            yield _finding("world-writable-perms", cmd, line, mode, "literal",
                           {"mode": mode},
                           "root grants world-writable permissions (%s)" % mode)
            return


def _is_world_writable(mode):
    octal = WORLD_WRITE_OCTAL_RE.match(mode)
    if octal:
        return bool(int(octal.group(1)) & 2)
    for clause in mode.split(","):
        match = WORLD_WRITE_CLAUSE_RE.match(clause)
        if not match:
            continue
        who, op, perms = match.groups()
        if op == "-" or "w" not in perms:
            continue
        ## Require an EXPLICIT 'o' or 'a' subject. An omitted 'who' ('+w', '=w')
        ## is umask-filtered -- root's default umask 022 drops the other-write
        ## bit -- so it does not reliably grant world-write.
        if "o" in who or "a" in who:
            return True
    return False


def _trust_sudo_user_finding(call, source, cmd, tainted, validated):
    if validated or cmd not in (
            RECURSIVE_WRITE_CMDS | PLAIN_WRITE_CMDS | SOURCE_CMDS):
        return
    for word in bash_ast.args(call)[1:]:
        if bash_ast.word_param_names(word) & TRUST_BOUNDARY_PARAMS:
            yield _finding(
                "trust-sudo-user", cmd, _line_of(word), _word_raw(word, source),
                "trust-boundary", {"trust_boundary": True},
                "root uses $SUDO_USER to pick a target without validating it")
            return


def _plain_write_finding(call, source, cmd, tainted, tmp_safe, tmp_vars):
    """tee/touch/dd: a named WRITE target that is a user path (root follows the
    symlink) or a predictable temp path. For dd only 'of=' is a write target --
    'if=' is the READ source, so flagging it would be a false positive."""
    _opts, positionals, opt_paths = _sink_operands(call, source, cmd)
    operands = positionals + opt_paths
    if cmd == "dd":
        operands = [w for w in operands
                    if _word_raw(w, source).lstrip("\"'").startswith("of=")]
    for word in operands:
        kind = taint_kind(word, source, tainted)
        if kind is not None:
            yield _finding("symlink-follow", cmd, _line_of(word),
                           _word_raw(word, source), kind, {"symlink": True},
                           "root %s writes into a user-controlled path" % cmd)
            continue
        if _is_predictable_tmp(word, source, tmp_safe, tmp_vars):
            yield _finding("tmp-race", cmd, _line_of(word),
                           _word_raw(word, source), "literal", {},
                           "root %s a predictable temp path" % cmd)
            continue


def _path_assignment_finding(name, value, source, tainted):
    if name != "PATH" or value is None:
        return
    raw = _word_raw(value, source)
    risky = False
    for element in raw.split(":"):
        stripped = element.strip().strip('"').strip("'")
        if stripped in ("", ".") or not stripped.startswith(("/", "$")):
            risky = True
    if bash_ast.word_param_names(value) & tainted:
        risky = True
    if risky:
        yield _finding("path-hijack", "PATH=", _line_of(value), raw, "literal",
                       {}, "root sets PATH with a relative or user-influenced "
                       "element")


def _redirect_findings(tree, source, tainted, tmp_safe, tmp_vars):
    for stmt in bash_ast.iter_stmts(tree):
        for redirect in stmt.get("Redirs") or []:
            if ">" not in _op_text(redirect, source):
                continue
            word = redirect.get("Word")
            if not word:
                continue
            if _is_predictable_tmp(word, source, tmp_safe, tmp_vars):
                yield _finding("tmp-race", "redirect", _line_of(word),
                               _word_raw(word, source), "literal", {},
                               "root writes (redirect) to a predictable temp path")
                continue
            kind = taint_kind(word, source, tainted)
            if kind is not None:
                yield _finding("symlink-follow", "redirect", _line_of(word),
                               _word_raw(word, source), kind, {},
                               "root writes (redirect) into a user-controlled path")


def _is_predictable_tmp(word, source, tmp_safe, tmp_vars):
    names = bash_ast.word_param_names(word)
    if names & tmp_safe:
        return False
    if names & tmp_vars:
        return True
    return bool(TMP_LITERAL_RE.search(_word_raw(word, source)))


def _file_validates(tree):
    for call in bash_ast.call_exprs(tree):
        if bash_ast.command_basename(call) in VALIDATOR_NAMES:
            return True
    return False


def iter_findings(tree, source):
    """Yield every LPE candidate finding in TREE (a root-run script)."""
    tainted = tainted_params(tree, source)
    validated = _file_validates(tree)
    tmp_safe = mktemp_vars(tree, source)
    tmp_vars = tmp_literal_vars(tree, source, tmp_safe)

    for name, value in all_assignments(tree):
        yield from _path_assignment_finding(name, value, source, tainted)

    for raw_call in bash_ast.call_exprs(tree):
        cmd, call = _peel_wrappers(raw_call, source)
        if cmd is None:
            continue
        if cmd in RECURSIVE_WRITE_CMDS:
            yield from _recursive_write_finding(
                call, source, cmd, tainted, tmp_safe, tmp_vars)
        if cmd == "find":
            yield from _find_walk_finding(call, source, tainted)
        if cmd in SOURCE_CMDS or cmd == "eval" or cmd in SHELL_INTERPRETERS:
            yield from _source_eval_finding(call, source, cmd, tainted)
        if cmd in ("chmod", "install", "mkdir"):
            yield from _world_writable_finding(call, source, cmd)
        if cmd in PLAIN_WRITE_CMDS:
            yield from _plain_write_finding(
                call, source, cmd, tainted, tmp_safe, tmp_vars)
        yield from _trust_sudo_user_finding(call, source, cmd, tainted, validated)

    yield from _redirect_findings(tree, source, tainted, tmp_safe, tmp_vars)
