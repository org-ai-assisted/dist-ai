## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""The rule registry: every style rule as a Rule object, assembled into explicit
tuples the engine iterates. Plain and greppable -- no import-time discovery.

  SHELL_RULES  -- run over a parsed shell tree (command position, quote/heredoc
                  structure). The set the gate delegates to the AST detector.
  CONFIG_RULES -- self-select by path shape (systemd / apt / cron / workflow
                  YAML) and parse the embedded shell they host.
  TEXT_RULES   -- need no parse (confusables, trailing whitespace).

ALL is their concatenation. A rule with a fix() is auto-fixable; the engine's
fix pass runs exactly those, the detect pass runs SHELL_RULES + CONFIG_RULES."""

from dist_ai import model
from dist_ai.rules import config as _config
from dist_ai.rules import shell as _shell
from dist_ai.rules import text as _text

SHELL_RULES = _shell.RULES
CONFIG_RULES = _config.RULES
TEXT_RULES = _text.RULES

## Rules that also apply to a commit MESSAGE blob (not a tree file): the
## non-ASCII floor only. A message has no path/extension, so a file-kind rule
## (trailing whitespace is scoped to is_text files) does not belong here.
MESSAGE_RULES = tuple(rule for rule in TEXT_RULES if rule.id == "R-001")

## Detect channel emitted to the gate: the AST-parsed shell + config rules.
DETECT_RULES = SHELL_RULES + CONFIG_RULES

ALL = SHELL_RULES + CONFIG_RULES + TEXT_RULES

## Fixable rules, in a stable order (structural shell first, then text), so a
## multi-rule fix on one file is deterministic. A rule is fixable iff it
## overrides Rule.fix.
FIX_RULES = tuple(rule for rule in ALL
                  if type(rule).fix is not model.Rule.fix)
