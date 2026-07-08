#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Idempotency / no-bloat coverage for the config-mutating operations.

The GUI writes the torrc drop-in through several paths -- gen_torrc() (apply a
whole bridge/proxy config), set_enabled()/set_disabled() (toggle
DisableNetwork), and the tor-config-sane helper (repair the main torrc). Users
run these repeatedly and switch between them, so none of them may duplicate,
bloat, or corrupt the configuration:

  * running the SAME action repeatedly must converge to identical bytes;
  * switching BETWEEN actions must leave no residue from the previous one;
  * DisableNetwork must never accumulate to more than one active directive.
"""

import os
import re
import subprocess
import tempfile
import unittest

import tcp_testlib as T
from tor_control_panel import torrc_gen, tor_status

CUSTOM_OBFS4 = ("obfs4 1.2.3.4:1234 ABCDEF0123456789ABCDEF0123456789ABCDEF01\n"
                "obfs4 5.6.7.8:5678 0123456789ABCDEF0123456789ABCDEF01234567")
CUSTOM_MEEK = ("meek_lite 192.0.2.20:80 "
               "ABCDEF0123456789ABCDEF0123456789ABCDEF01 url=https://example.com")

## A representative spread of every config gen_torrc() supports.
CONFIGS = {
    "none": ["None", "None", "None"],
    "obfs4": ["obfs4", "None", "None"],
    "snowflake": ["snowflake", "None", "None"],
    "meek": ["meek", "None", "None"],
    "custom_obfs4": ["None", CUSTOM_OBFS4, "None"],
    "custom_meek": ["None", CUSTOM_MEEK, "None"],
    "socks5": ["None", "None", "SOCKS5", "127.0.0.1", "9050", "", ""],
    "obfs4_proxy": ["obfs4", "None", "SOCKS5", "127.0.0.1", "9050", "", ""],
}


def _active_lines(text):
    """Non-comment, non-blank torrc lines."""
    out = []
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            out.append(stripped)
    return out


def _disablenetwork_count(text):
    return sum(1 for ln in _active_lines(text)
               if ln.split()[:1] == ["DisableNetwork"])


class GenTorrcIdempotencyTest(unittest.TestCase):
    """gen_torrc() fully overwrites, so repeats are stable and switches leave
    no residue."""

    def _gen(self, args):
        with T.sandbox() as torrc:
            torrc_gen.gen_torrc(args)
            return torrc.read_text(encoding="utf-8")

    ## Cross-sandbox byte comparison is invalid: the torrc header comment embeds
    ## the (temporary) 50_user.conf path, which differs per sandbox. So compare
    ## repeats/switches WITHIN a single sandbox (constant header path), where a
    ## full-byte comparison is meaningful.

    def test_same_config_repeated_is_byte_identical(self):
        for name, args in CONFIGS.items():
            with self.subTest(config=name), T.sandbox() as torrc:
                torrc_gen.gen_torrc(list(args))
                first = torrc.read_text(encoding="utf-8")
                for _ in range(3):
                    torrc_gen.gen_torrc(list(args))
                    self.assertEqual(
                        torrc.read_text(encoding="utf-8"), first,
                        "{0}: repeated gen_torrc changed the output".format(name))

    def test_switching_configs_leaves_no_residue(self):
        ## Generating config B after some other config A (same file) must equal
        ## generating B directly -- gen_torrc fully overwrites, so A leaves no
        ## trace. Compared within one sandbox so the header path is constant.
        names = list(CONFIGS)
        for i, name in enumerate(names):
            other = names[(i + 1) % len(names)]
            with self.subTest(config=name, after=other), T.sandbox() as torrc:
                torrc_gen.gen_torrc(list(CONFIGS[name]))
                direct = torrc.read_text(encoding="utf-8")
                torrc_gen.gen_torrc(list(CONFIGS[other]))
                torrc_gen.gen_torrc(list(CONFIGS[name]))
                after = torrc.read_text(encoding="utf-8")
                self.assertEqual(
                    direct, after,
                    "{0}: leftover state after switching via {1}".format(name, other))

    def test_none_clears_all_bridge_and_proxy_state(self):
        ## Switching to 'None' must strip UseBridges / ClientTransportPlugin /
        ## Bridge / proxy directives left by a previous config.
        with T.sandbox() as torrc:
            torrc_gen.gen_torrc(["obfs4", "None", "SOCKS5", "127.0.0.1",
                                 "9050", "", ""])
            torrc_gen.gen_torrc(["None", "None", "None"])
            lines = _active_lines(torrc.read_text(encoding="utf-8"))
            self.assertEqual(lines, ["DisableNetwork 0"],
                             "switching to None left residue: {0}".format(lines))

    def test_bridges_do_not_accumulate_on_repeat(self):
        with T.sandbox() as torrc:
            counts = []
            for _ in range(4):
                torrc_gen.gen_torrc(["obfs4", "None", "None"])
                text = torrc.read_text(encoding="utf-8")
                counts.append(sum(1 for ln in _active_lines(text)
                                  if ln.startswith("Bridge ")))
            self.assertEqual(len(set(counts)), 1,
                             "bridge count drifted across repeats: {0}".format(counts))

    def test_roundtrip_between_configs_returns_identical(self):
        with T.sandbox() as torrc:
            torrc_gen.gen_torrc(["obfs4", "None", "None"])
            fresh_obfs4 = torrc.read_text(encoding="utf-8")
            for args in (["snowflake", "None", "None"],
                         ["None", CUSTOM_OBFS4, "None"],
                         ["None", "None", "None"],
                         ["obfs4", "None", "None"]):
                torrc_gen.gen_torrc(list(args))
            self.assertEqual(torrc.read_text(encoding="utf-8"), fresh_obfs4,
                             "a full switch cycle did not return to the fresh config")

    def test_exactly_one_disablenetwork_in_every_config(self):
        for name, args in CONFIGS.items():
            with self.subTest(config=name):
                self.assertEqual(_disablenetwork_count(self._gen(list(args))), 1)


class EnableDisableIdempotencyTest(unittest.TestCase):
    """set_enabled()/set_disabled() toggle DisableNetwork in place without
    duplicating it or disturbing the rest of the config."""

    def test_toggle_back_and_forth_keeps_single_directive(self):
        with T.sandbox() as torrc:
            torrc_gen.gen_torrc(["obfs4", "None", "None"])
            for _ in range(3):
                tor_status.set_disabled()
                text = torrc.read_text(encoding="utf-8")
                self.assertEqual(_disablenetwork_count(text), 1)
                self.assertIn("DisableNetwork 1", _active_lines(text))

                tor_status.set_enabled()
                text = torrc.read_text(encoding="utf-8")
                self.assertEqual(_disablenetwork_count(text), 1)
                self.assertIn("DisableNetwork 0", _active_lines(text))

    def test_disable_preserves_bridge_config(self):
        with T.sandbox() as torrc:
            torrc_gen.gen_torrc(["obfs4", "None", "None"])
            bridges_before = [ln for ln in _active_lines(
                torrc.read_text(encoding="utf-8")) if ln.startswith("Bridge ")]
            tor_status.set_disabled()
            text = torrc.read_text(encoding="utf-8")
            bridges_after = [ln for ln in _active_lines(text)
                             if ln.startswith("Bridge ")]
            self.assertEqual(bridges_before, bridges_after,
                             "toggling DisableNetwork disturbed the bridge lines")
            self.assertEqual(_disablenetwork_count(text), 1)

    def test_repeated_disable_is_stable(self):
        with T.sandbox() as torrc:
            torrc_gen.gen_torrc(["obfs4", "None", "None"])
            tor_status.set_disabled()
            first = torrc.read_text(encoding="utf-8")
            for _ in range(3):
                tor_status.set_disabled()
                self.assertEqual(torrc.read_text(encoding="utf-8"), first,
                                 "repeated set_disabled changed the torrc")

    def test_interleaved_gen_and_toggle_stays_clean(self):
        ## Mix the two kinds of action back and forth: apply a config, disable,
        ## apply a different config, disable again. The result must reflect only
        ## the last config, with a single DisableNetwork and no earlier residue.
        with T.sandbox() as torrc:
            torrc_gen.gen_torrc(["obfs4", "None", "None"])
            tor_status.set_disabled()
            torrc_gen.gen_torrc(["snowflake", "None", "None"])
            tor_status.set_disabled()
            text = torrc.read_text(encoding="utf-8")
            lines = _active_lines(text)
            self.assertEqual(_disablenetwork_count(text), 1)
            self.assertIn("DisableNetwork 1", lines)
            self.assertTrue(any("snowflake" in ln for ln in lines),
                            "the last config (snowflake) is missing")
            self.assertFalse(any("obfs4" in ln for ln in lines),
                             "obfs4 residue after switching to snowflake")

    def test_duplicate_disablenetwork_is_normalized_not_grown(self):
        ## A torrc that somehow carries two DisableNetwork lines with different
        ## values must be normalized to the requested value (no conflict left),
        ## and toggling must not keep growing the count.
        seeded = ("DisableNetwork 1\nUseBridges 1\nDisableNetwork 0\n")
        with T.sandbox(initial_torrc=seeded) as torrc:
            tor_status.set_enabled()
            text = torrc.read_text(encoding="utf-8")
            values = [ln.split()[1] for ln in _active_lines(text)
                      if ln.split()[:1] == ["DisableNetwork"]]
            self.assertTrue(all(v == "0" for v in values),
                            "conflicting DisableNetwork values left: {0}".format(values))
            ## And a subsequent toggle does not add yet more directives.
            count_before = len(values)
            tor_status.set_disabled()
            self.assertLessEqual(
                _disablenetwork_count(torrc.read_text(encoding="utf-8")),
                count_before)


SCRIPT = os.environ.get("TCP_REPO", "").strip()
CONFIG_SANE = os.path.join(
    SCRIPT, "usr/libexec/tor-control-panel/tor-config-sane") if SCRIPT else \
    "/usr/libexec/tor-control-panel/tor-config-sane"


@unittest.skipUnless(os.path.exists(CONFIG_SANE), "tor-config-sane not found")
class ConfigSaneIdempotencyTest(unittest.TestCase):
    """The privileged tor-config-sane repair helper must be safe to run any
    number of times without duplicating the %include or churning the torrc."""

    def _run(self, root):
        env = dict(os.environ)
        env["torrc_dir"] = os.path.join(root, "etc/tor/torrc.d")
        env["main_torrc"] = os.path.join(root, "etc/tor/torrc")
        env["whonix_marker"] = os.path.join(root, "no-marker")
        return subprocess.run(["bash", CONFIG_SANE], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              encoding="utf-8")

    def _read(self, root):
        with open(os.path.join(root, "etc/tor/torrc"), encoding="utf-8") as handle:
            return handle.read()

    def test_repeated_runs_add_include_once_and_stabilize(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "etc/tor"))
            open(os.path.join(root, "etc/tor/torrc"), "w").close()
            self._run(root)
            after_first = self._read(root)
            for _ in range(3):
                self._run(root)
            after_many = self._read(root)
            self.assertEqual(after_first, after_many,
                             "tor-config-sane is not idempotent on the main torrc")
            self.assertEqual(
                len(re.findall(r'(?m)^\s*%include\s+\S*torrc\.d', after_many)), 1)

    def test_migration_then_rerun_is_stable(self):
        ## Start from a torrc with the stale /usr/local include; the first run
        ## migrates it, further runs must not re-add or duplicate anything.
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "etc/tor"))
            with open(os.path.join(root, "etc/tor/torrc"), "w",
                      encoding="utf-8") as handle:
                handle.write("%include /usr/local/etc/torrc.d/*.conf\n")
            self._run(root)
            after_first = self._read(root)
            self._run(root)
            after_second = self._read(root)
            self.assertEqual(after_first, after_second)
            self.assertNotIn("/usr/local/etc/torrc.d", after_second)


if __name__ == "__main__":
    unittest.main()
