#!/usr/bin/env python3

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Tests for privleap's configuration parser and config loading.

Config files are root-owned and trusted, so this is not an attack surface in
the way the comm socket is. It is, however, the place where an administrator's
intent becomes the daemon's authorization rules, and a parser that accepts a
malformed rule, silently drops one, or merges two files wrongly grants access
nobody asked to grant. So what is checked here is that every rejection the
parser is supposed to make actually happens and is reported with a usable
file:line, and that a valid file produces exactly the actions, users and
groups it describes and nothing more.

Runs without root. Permission checks that require a root-owned file are
exercised by stubbing the stat the parser does, and the real check itself is
tested directly against files this account does own.
"""

import argparse
import inspect
import os
import stat
import sys
import tempfile
from types import ModuleType
from typing import Any, Callable

HERE: str = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# pylint: disable=wrong-import-position
from pl_testlib import (  # noqa: E402
    Results,
    current_username,
    import_privleap,
    import_privleapd,
)


class ConfigDir:
    """
    A temporary config directory whose files the parser will accept as
    securely owned, so that parsing behaviour can be tested by an account that
    is not root.
    """

    def __init__(self, pl: ModuleType) -> None:
        self.pl: ModuleType = pl
        self.tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self.path: str = ''
        self.saved_check: Any = None

    def __enter__(self) -> 'ConfigDir':
        self.tmpdir = tempfile.TemporaryDirectory(prefix='privleap-conf-')
        self.path = os.path.join(self.tmpdir.name, 'conf.d')
        os.mkdir(self.path, 0o755)
        ## getattr_static so the staticmethod descriptor itself is saved.
        ## A plain class attribute read hands back the underlying
        ## function, and restoring that would leave PrivleapCommon with an
        ## ordinary method that binds an instance as its first argument.
        self.saved_check = inspect.getattr_static(
            self.pl.PrivleapCommon, 'check_secure_file_permissions'
        )
        ## The real check wants root ownership. It is tested on its own terms
        ## in test_secure_permission_check(); here it would only stand between
        ## the tests and the parser.
        self.pl.PrivleapCommon.check_secure_file_permissions = staticmethod(
            lambda _file_id: True
        )
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.pl.PrivleapCommon.check_secure_file_permissions = (
            self.saved_check
        )
        if self.tmpdir is not None:
            self.tmpdir.cleanup()
            self.tmpdir = None

    def write(self, name: str, text: str) -> Any:
        """Write a config file and return its path."""

        path: str = os.path.join(self.path, name)
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(text)
        os.chmod(path, 0o644)
        return self.pl.Path(path)


def parse(pl: ModuleType, conf: ConfigDir, text: str) -> Any:
    """Parse one config file's text, returning ConfigData or an error string."""

    return pl.PrivleapCommon.parse_config_file(conf.write('test.conf', text))


def test_valid_config_is_parsed_exactly(
    results: Results, pl: ModuleType
) -> None:
    """
    A valid file must yield exactly the actions, users and groups it lists.
    Anything extra is an unintended grant, anything missing is a lost
    restriction.
    """

    print('== a valid config is parsed exactly ==')
    user: str = current_username()
    with ConfigDir(pl) as conf:
        result: Any = parse(
            pl,
            conf,
            f"""
# a comment
  # an indented comment

[persistent-users]
User={user}

[allowed-users]
User={user}
Group=root

[expected-disallowed-users]
User=root

[action:act-one]
Command=echo one
AuthorizedUsers={user}

[action:act-two]
Command=echo two
AuthorizedGroups=root
TargetUser=root
TargetGroup=root
""",
        )
        if not results.check(
            'the config parsed without error', not isinstance(result, str)
        ):
            print(f"  parser said: {result}")
            return
        actions, persistent, allowed_users, allowed_groups, disallowed = result
        results.expect_eq(
            'both actions are present',
            sorted(action.action_name for action in actions),
            ['act-one', 'act-two'],
        )
        results.expect_eq('the persistent user is listed', persistent, [user])
        results.expect_eq(
            'the allowed user is listed', allowed_users, [user]
        )
        results.expect_eq(
            'the allowed group is listed', allowed_groups, ['root']
        )
        results.expect_eq(
            'the expected-disallowed user is listed', disallowed, ['root']
        )
        by_name: dict[str, Any] = {
            action.action_name: action for action in actions
        }
        results.expect_eq(
            'the command is captured verbatim',
            by_name['act-one'].action_command,
            'echo one',
        )
        results.expect_eq(
            'a user grant is recorded',
            by_name['act-one'].auth_users,
            [user],
        )
        results.expect_eq(
            'a group grant is recorded',
            by_name['act-two'].auth_groups,
            ['root'],
        )
        results.expect_eq(
            'the target user is recorded',
            by_name['act-two'].target_user,
            'root',
        )
        results.check(
            'an action with a grant is marked restricted',
            by_name['act-one'].auth_restricted,
        )


def rejection_cases(user: str) -> list[tuple[str, str, str]]:
    """
    Every malformed config the parser is documented to reject, with the
    fragment of the complaint a reader needs to find the problem.
    """

    return [
        (
            'a config line before any header',
            'User=root\n',
            'Config line before header',
        ),
        (
            'an unrecognised header',
            '[nonsense]\nUser=root\n',
            'Unrecognized header',
        ),
        (
            'a line with no equals sign',
            '[allowed-users]\nUser\n',
            'Invalid syntax',
        ),
        (
            'an empty value',
            '[allowed-users]\nUser=\n',
            'Empty config value',
        ),
        (
            'an unknown key under allowed-users',
            '[allowed-users]\nNonsense=root\n',
            'Unrecognized key',
        ),
        (
            'an unknown key under persistent-users',
            '[persistent-users]\nNonsense=root\n',
            'Unrecognized key',
        ),
        (
            'an unknown key under expected-disallowed-users',
            '[expected-disallowed-users]\nNonsense=root\n',
            'Unrecognized key',
        ),
        (
            'an unknown key under an action',
            '[action:act]\nCommand=true\nNonsense=x\n',
            'Unrecognized key',
        ),
        (
            'a persistent user that does not exist',
            '[persistent-users]\nUser=privleap-no-such-account\n',
            'does not exist',
        ),
        (
            'an action with no command',
            f"[action:act]\nAuthorizedUsers={user}\n",
            'No command configured for action',
        ),
        (
            'an action with no authorized users or groups',
            '[action:act]\nCommand=true\n',
            'No authorized users or groups for action',
        ),
        (
            'an action with an invalid name',
            f"[action:bad name]\nCommand=true\nAuthorizedUsers={user}\n",
            'Invalid action name',
        ),
        (
            'two Command keys in one action',
            f"[action:act]\nCommand=true\nCommand=false\n"
            f"AuthorizedUsers={user}\n",
            "Multiple 'Command' keys",
        ),
        (
            'two AuthorizedUsers keys in one action',
            f"[action:act]\nCommand=true\nAuthorizedUsers={user}\n"
            f"AuthorizedUsers=root\n",
            "Multiple 'AuthorizedUsers' keys",
        ),
        (
            'two AuthorizedGroups keys in one action',
            '[action:act]\nCommand=true\nAuthorizedGroups=root\n'
            'AuthorizedGroups=root\n',
            "Multiple 'AuthorizedGroups' keys",
        ),
        (
            'two TargetUser keys in one action',
            f"[action:act]\nCommand=true\nAuthorizedUsers={user}\n"
            f"TargetUser=root\nTargetUser=root\n",
            "Multiple 'TargetUser' keys",
        ),
        (
            'two TargetGroup keys in one action',
            f"[action:act]\nCommand=true\nAuthorizedUsers={user}\n"
            f"TargetGroup=root\nTargetGroup=root\n",
            "Multiple 'TargetGroup' keys",
        ),
        ## A malformed action followed by another header must still be caught:
        ## the parser closes an action when the next header arrives, which is
        ## a different code path from closing it at end of file.
        (
            'a malformed action closed by a following header',
            f"[action:act]\nAuthorizedUsers={user}\n[allowed-users]\n"
            f"User={user}\n",
            'No command configured for action',
        ),
    ]


def test_malformed_configs_are_rejected(
    results: Results, pl: ModuleType
) -> None:
    """Every documented rejection happens, and says which line was wrong."""

    print('== malformed configs are rejected with a usable complaint ==')
    user: str = current_username()
    with ConfigDir(pl) as conf:
        for label, text, want_fragment in rejection_cases(user):
            result: Any = parse(pl, conf, text)
            if not results.check(
                f"{label}: is rejected", isinstance(result, str)
            ):
                continue
            results.check(
                f"{label}: complaint mentions {want_fragment!r}",
                want_fragment in result,
            )
            results.check(
                f"{label}: complaint names the file",
                'test.conf' in result,
            )


def test_config_complaints_are_never_blank(
    results: Results, pl: ModuleType
) -> None:
    """
    A refused config must always say why.

    find_bad_config_header() locates the offending header to build the
    complaint. When it could not find one it returned an empty string, and
    that empty string travelled all the way to the operator as a blank error
    line: the config was correctly refused, with no indication of what was
    wrong with it.
    """

    print('== a refused config always says why ==')
    user: str = current_username()
    with ConfigDir(pl) as conf:
        path: Any = conf.write(
            'test.conf',
            f"[action:act]\nAuthorizedUsers={user}\n[allowed-users]\n"
            f"User={user}\n",
        )
        complaint: str = pl.PrivleapCommon.find_bad_config_header(
            path, 'act', 'No command configured for action:'
        )
        results.check(
            'a locatable header yields a complaint with a line number',
            complaint.startswith(f"{path}:1:error:"),
        )
        missing_complaint: str = pl.PrivleapCommon.find_bad_config_header(
            path, 'no-such-action', 'No command configured for action:'
        )
        results.check(
            'an unlocatable header still yields a complaint',
            missing_complaint != '',
        )
        results.check(
            "an unlocatable header's complaint names the file and reason",
            str(path) in missing_complaint
            and 'No command configured' in missing_complaint,
        )


def test_unknown_identities_are_skipped_not_fatal(
    results: Results, pl: ModuleType
) -> None:
    """
    A config may name an account that does not exist yet, which is why an
    unknown allowed user or group is skipped rather than treated as an error.
    Skipping must not turn into granting.
    """

    print('== unknown accounts in a grant are skipped, not granted ==')
    user: str = current_username()
    with ConfigDir(pl) as conf:
        result: Any = parse(
            pl,
            conf,
            f"""[allowed-users]
User=privleap-no-such-account
Group=privleap-no-such-group
User={user}

[action:act]
Command=true
AuthorizedUsers={user}
""",
        )
        if not results.check(
            'the config parsed without error', not isinstance(result, str)
        ):
            print(f"  parser said: {result}")
            return
        _actions, _persistent, allowed_users, allowed_groups, _dis = result
        results.expect_eq(
            'only the real account is allowed', allowed_users, [user]
        )
        results.expect_eq(
            'no unknown group is allowed', allowed_groups, []
        )

        ## An action whose target account does not exist is dropped entirely
        ## rather than being left runnable with an unresolved target.
        result = parse(
            pl,
            conf,
            f"""[action:act-bad-target]
Command=true
AuthorizedUsers={user}
TargetUser=privleap-no-such-account
""",
        )
        if results.check(
            'a config with an unresolvable target parses',
            not isinstance(result, str),
        ):
            results.expect_eq(
                'an action with an unresolvable target is dropped',
                [action.action_name for action in result[0]],
                [],
            )


def test_duplicate_entries_are_collapsed(
    results: Results, pl: ModuleType
) -> None:
    """Repeating a user or group must not produce a duplicate entry."""

    print('== repeated users and groups are collapsed ==')
    user: str = current_username()
    with ConfigDir(pl) as conf:
        result: Any = parse(
            pl,
            conf,
            f"""[persistent-users]
User={user}
User={user}

[allowed-users]
User={user}
User={user}
Group=root
Group=root

[expected-disallowed-users]
User=root
User=root
""",
        )
        if not results.check(
            'the config parsed without error', not isinstance(result, str)
        ):
            return
        _actions, persistent, allowed_users, allowed_groups, disallowed = (
            result
        )
        results.expect_eq('persistent users are unique', persistent, [user])
        results.expect_eq('allowed users are unique', allowed_users, [user])
        results.expect_eq(
            'allowed groups are unique', allowed_groups, ['root']
        )
        results.expect_eq(
            'expected-disallowed users are unique', disallowed, ['root']
        )


def test_secure_permission_check(results: Results, pl: ModuleType) -> None:
    """
    The permission check is what stops a non-root account from writing the
    rules the daemon runs as root. It is checked here on its own terms, on
    real files, rather than through the parser.
    """

    print('== the config permission check rejects unsafe files ==')
    with tempfile.TemporaryDirectory(prefix='privleap-perm-') as tmpdir:
        path: str = os.path.join(tmpdir, 'conf')
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write('')

        os.chmod(path, 0o666)  # nosec B103 -- the unsafe mode under test
        results.expect_eq(
            'a world-writable file is rejected',
            pl.PrivleapCommon.check_secure_file_permissions(path),
            False,
        )
        os.chmod(path, 0o644)
        ## Owned by this account, not root, so it must still be rejected --
        ## unless this suite is being run as root, in which case it is the
        ## legitimately safe case.
        expected: bool = os.geteuid() == 0
        results.expect_eq(
            'ownership decides whether a 0644 file is accepted',
            pl.PrivleapCommon.check_secure_file_permissions(path),
            expected,
        )
        results.expect_eq(
            'a path that does not exist is rejected',
            pl.PrivleapCommon.check_secure_file_permissions(
                os.path.join(tmpdir, 'absent')
            ),
            False,
        )
        with open(path, 'rb') as handle:
            results.expect_eq(
                'the check accepts an open descriptor too',
                pl.PrivleapCommon.check_secure_file_permissions(
                    handle.fileno()
                ),
                expected,
            )


def test_daemon_config_loading(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    The daemon's own loader must merge several files, apply them in sorted
    order, reject a duplicate action across files, and leave the previously
    loaded configuration untouched when a load fails. A loader that half
    applies a bad config is worse than one that refuses it.
    """

    print("== the daemon's config loader merges and refuses correctly ==")
    user: str = current_username()
    with ConfigDir(pl) as conf:
        saved: dict[str, Any] = {
            name: getattr(pld.PrivleapdGlobal, name)
            for name in (
                'config_dir_list',
                'action_list',
                'persistent_user_list',
                'allowed_user_list',
                'allowed_group_list',
                'expected_disallowed_user_list',
            )
        }
        try:
            pld.PrivleapdGlobal.config_dir_list = [
                pl.Path(conf.path),
                pl.Path(conf.path, 'does-not-exist'),
            ]
            conf.write(
                '10-first.conf',
                f"[allowed-users]\nUser={user}\n\n"
                f"[action:act-first]\nCommand=true\nAuthorizedUsers={user}\n",
            )
            conf.write(
                '20-second.conf',
                f"[action:act-second]\nCommand=true\n"
                f"AuthorizedUsers={user}\n",
            )
            ## Not a config file: must be ignored, not parsed.
            conf.write('notes.txt', 'this is not a config file\n')
            ## A .conf name the validator rejects: must be skipped with a
            ## warning, not accepted and not fatal.
            conf.write('bad%name.conf', f"[allowed-users]\nUser={user}\n")

            results.check(
                'a valid set of config files loads', pld.parse_config_files()
            )
            results.expect_eq(
                'actions from every file are merged',
                sorted(
                    action.action_name
                    for action in pld.PrivleapdGlobal.action_list
                ),
                ['act-first', 'act-second'],
            )
            results.expect_eq(
                'users from every file are merged',
                pld.PrivleapdGlobal.allowed_user_list,
                [user],
            )

            good_actions: list[Any] = pld.PrivleapdGlobal.action_list
            conf.write(
                '30-duplicate.conf',
                f"[action:act-first]\nCommand=false\n"
                f"AuthorizedUsers={user}\n",
            )
            results.expect_eq(
                'a duplicate action across files is refused',
                pld.parse_config_files(),
                False,
            )
            ## Identity alone would still hold if a buggy loader appended
            ## the new file's actions to the live list and then refused, so
            ## the contents are compared too.
            results.check(
                'a refused load leaves the previous configuration in place',
                pld.PrivleapdGlobal.action_list is good_actions,
            )
            results.expect_eq(
                'a refused load did not alter the loaded actions',
                sorted(
                    action.action_name
                    for action in pld.PrivleapdGlobal.action_list
                ),
                ['act-first', 'act-second'],
            )
        finally:
            for key, value in saved.items():
                setattr(pld.PrivleapdGlobal, key, value)


def test_daemon_config_loading_with_no_files(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    No config at all must be a refusal. A daemon that starts with an empty
    rule set looks healthy while answering nothing.
    """

    print('== a config directory with no config files is refused ==')
    with ConfigDir(pl) as conf:
        saved_dirs: Any = pld.PrivleapdGlobal.config_dir_list
        try:
            pld.PrivleapdGlobal.config_dir_list = [pl.Path(conf.path)]
            results.expect_eq(
                'an empty config directory is refused',
                pld.parse_config_files(),
                False,
            )
        finally:
            pld.PrivleapdGlobal.config_dir_list = saved_dirs


def test_insecure_config_dir_is_ignored(
    results: Results, pl: ModuleType, pld: ModuleType
) -> None:
    """
    A config directory anyone can write to must be ignored wholesale, since
    any file in it could have been planted.
    """

    print('== a world-writable config directory is ignored ==')
    with tempfile.TemporaryDirectory(prefix='privleap-insecure-') as tmpdir:
        conf_path: str = os.path.join(tmpdir, 'conf.d')
        os.mkdir(conf_path)
        os.chmod(conf_path, 0o777)  # nosec B103 -- the condition under test
        with open(
            os.path.join(conf_path, 'planted.conf'), 'w', encoding='utf-8'
        ) as handle:
            handle.write('[allowed-users]\nUser=root\n')
        saved_dirs: Any = pld.PrivleapdGlobal.config_dir_list
        try:
            pld.PrivleapdGlobal.config_dir_list = [pl.Path(conf_path)]
            results.expect_eq(
                'a world-writable config directory yields no configuration',
                pld.parse_config_files(),
                False,
            )
        finally:
            pld.PrivleapdGlobal.config_dir_list = saved_dirs
        results.expect_eq(
            'the directory permission check agrees it is unsafe',
            pl.PrivleapCommon.check_secure_file_permissions(conf_path),
            False,
        )
        results.check(
            'the planted file really was world-writable directory content',
            bool(os.stat(conf_path).st_mode & stat.S_IWOTH),
        )


def run_test(
    results: Results, test: Callable[..., None], *args: Any
) -> None:
    """Run one test, turning an unexpected exception into a failure."""

    try:
        test(results, *args)
    except BaseException as exc:  # pylint: disable=broad-exception-caught
        results.check(
            f"{test.__name__} raised {type(exc).__name__}: {exc}", False
        )


def main() -> int:
    """Entry point."""

    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description='privleap configuration parser tests'
    )
    parser.add_argument(
        '--seed', type=int, default=1, help='accepted for interface parity'
    )
    parser.parse_args()

    pl: ModuleType = import_privleap()
    pld: ModuleType = import_privleapd()
    results: Results = Results()

    run_test(results, test_valid_config_is_parsed_exactly, pl)
    run_test(results, test_malformed_configs_are_rejected, pl)
    run_test(results, test_config_complaints_are_never_blank, pl)
    run_test(results, test_unknown_identities_are_skipped_not_fatal, pl)
    run_test(results, test_duplicate_entries_are_collapsed, pl)
    run_test(results, test_secure_permission_check, pl)
    run_test(results, test_daemon_config_loading, pl, pld)
    run_test(results, test_daemon_config_loading_with_no_files, pl, pld)
    run_test(results, test_insecure_config_dir_is_ignored, pl, pld)

    print('')
    return results.report('config parser test')


if __name__ == '__main__':
    sys.exit(main())
