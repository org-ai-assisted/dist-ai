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

    class _NoDupLoader(yaml.SafeLoader):
        """safe_load silently keeps the LAST of duplicate mapping keys, so a duplicated
        `policies:` would quietly mis-select the policy. Reject a duplicate key instead
        (a ConstructorError is a YAMLError -> ConfigError below)."""

    def _mapping(loader, node):
        seen = set()
        for key_node, _value_node in node.value:
            key = loader.construct_object(key_node, deep=True)
            try:
                duplicate = key in seen
            except TypeError:
                # An unhashable (complex `? [..]`) key: skip dedup and let the stock
                # construct_mapping below raise its ConstructorError ('found unhashable key')
                # -- a YAMLError -> ConfigError -- instead of a raw TypeError escaping the wrapper.
                continue
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    'while constructing a mapping', node.start_mark,
                    'found duplicate key %r' % (key,), key_node.start_mark)
            seen.add(key)
        return loader.construct_mapping(node, deep=True)

    _NoDupLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)
    try:
        with open(path, encoding='utf-8') as handle:
            # _NoDupLoader subclasses yaml.SafeLoader (no object construction); it only ADDS
            # duplicate-key rejection, so this is a safe load -- B506 cannot see through the subclass.
            data = yaml.load(handle, Loader=_NoDupLoader)  # nosec B506
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
