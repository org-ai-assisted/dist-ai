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
    """Parsed web-tests.yml mapping for `root`, or None when the file is absent.

    Raises ConfigError on an unreadable / non-mapping / invalid-YAML file."""
    path = config_path(root)
    if not os.path.isfile(path):
        return None
    import yaml
    try:
        with open(path, encoding='utf-8') as handle:
            data = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError('%s: unreadable or invalid YAML: %s' % (path, exc))
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
