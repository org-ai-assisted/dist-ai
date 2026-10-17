#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Declarative per-site test config: `.github/web-tests.yml`.

`policies:` DECLARES which policy a site root is checked under (family vs wiki), so
check_site runs only the applicable tests instead of inferring from page markup.

The markup heuristic (`site._looks_like_wiki`) stays the DEFAULT when a root ships
no config, so an unconfigured wiki tree is never mis-reported under family policy --
the config is an explicit OVERRIDE of a safe default, not a thing to remember.

A present-but-malformed config FAILS LOUD (ConfigError), never a silent revert to the
heuristic: a broken selector that quietly ran the wrong policy is exactly the
confident-wrong-answer this layer removes.
"""

import os

# Mirrors the `.github/dm-consumer.yml` convention: one declarative file per repo,
# co-located with the served tree root (family sites) so it rides the checkout.
CONFIG_REL = os.path.join('.github', 'web-tests.yml')

KNOWN_POLICIES = ('family', 'wiki')


class ConfigError(ValueError):
    """web-tests.yml present but malformed -- fail loud, never silently default."""


def config_path(root):
    return os.path.join(root, CONFIG_REL)


def load(root):
    """Parsed web-tests.yml mapping for `root`, or None when the file is ABSENT.

    Only genuine absence (FileNotFoundError) is None. A present-but-unreadable
    (EACCES, a dir in its place), invalid-YAML, or non-UTF-8 file raises ConfigError
    -- so an unreadable authoritative config fails LOUD, never a silent fall-back to
    the markup heuristic. Open-then-except (not os.path.isfile first) is what lets
    'absent' and 'unreadable' diverge: isfile() returns False for BOTH.

    web-tests.yml is a TRUSTED in-repo file (hand-authored in the family site repos,
    emitted by the wiki generator). The trust boundary is repo-write access -- anyone
    who can forge this file can equally commit a malicious index.html or test -- so
    YAML-alias-amplification and symlink-escape hardening are out of scope here."""
    path = config_path(root)
    import yaml  # type: ignore[import-untyped]
    try:
        with open(path, encoding='utf-8') as handle:
            data = yaml.safe_load(handle)
    except FileNotFoundError:
        return None
    except (OSError, yaml.YAMLError, UnicodeDecodeError) as exc:
        raise ConfigError('%s: unreadable or invalid: %s' % (path, exc))
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError('%s: top level must be a mapping' % path)
    return data


def policies(root):
    """Declared policy list for `root`, or None when no config is present.

    None means "no declaration" -- the caller falls back to the markup heuristic.
    A present config with a missing / empty / unknown `policies:` is a ConfigError."""
    data = load(root)
    if data is None:
        return None
    raw = data.get('policies')
    if raw is None:
        raise ConfigError('%s: missing required `policies:` key' % config_path(root))
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list) or not raw:
        raise ConfigError('%s: `policies:` must be a non-empty list' % config_path(root))
    unknown = [p for p in raw if p not in KNOWN_POLICIES]
    if unknown:
        raise ConfigError('%s: unknown policy %r (known: %s)'
                          % (config_path(root), unknown, ', '.join(KNOWN_POLICIES)))
    return list(raw)
