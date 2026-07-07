#!/usr/bin/python3 -su

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Feature + regression tests for torrc_gen.gen_torrc() / parse_torrc().

torrc_gen is the pure logic core of tor-control-panel: it turns the GUI's
configuration (bridge type, custom bridges, proxy) into a torrc drop-in file,
and parses an existing torrc back into that configuration. It is exercised here
through tcp_testlib.sandbox(), which redirects the torrc paths to a temp file
and neutralises the privileged 'leaprun acw-write-torrc' helper, so the tests
need no root, no privleap and no Tor daemon.

Covered features (arraybolt3 test plan, Tor Control Panel section):
  * Bridges type None / obfs4 / snowflake / meek / Custom bridges
  * Proxy type None / SOCKS4 / SOCKS5, with and without authentication
  * round-trip: gen_torrc(x) then parse_torrc() recovers x

Regressions guarded:
  * A1 -- custom bridges must be detected on re-parse (typo
    '# Custom briges are used' in parse_torrc); otherwise a later reconfigure
    silently replaces them with default obfs4 bridges.
  * A7 -- a fully specified proxy request must actually emit proxy lines.
"""

import unittest

import tcp_testlib as T
from tor_control_panel import torrc_gen


def _config_lines(text: str) -> list[str]:
    """Non-empty, non-comment torrc lines."""
    return [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


CUSTOM_BRIDGES = (
    "obfs4 1.2.3.4:1234 ABCDEF0123456789ABCDEF0123456789ABCDEF01\n"
    "obfs4 5.6.7.8:5678 0123456789ABCDEF0123456789ABCDEF01234567"
)


class GenTorrcFeatureTest(unittest.TestCase):
    """gen_torrc() emits the expected torrc for each supported configuration."""

    def _gen(self, args):
        with T.sandbox() as torrc:
            torrc_gen.gen_torrc(args)
            return torrc.read_text(encoding="utf-8")

    def test_none_emits_only_disablenetwork0(self):
        lines = _config_lines(self._gen(["None", "None", "None"]))
        self.assertEqual(lines, ["DisableNetwork 0"])

    def test_disablenetwork0_always_present(self):
        for args in (
            ["None", "None", "None"],
            ["obfs4", "None", "None"],
            ["None", "None", "SOCKS5", "127.0.0.1", "9050", "", ""],
        ):
            with self.subTest(args=args):
                self.assertIn("DisableNetwork 0", self._gen(args))

    def test_obfs4_default_bridges(self):
        text = self._gen(["obfs4", "None", "None"])
        self.assertIn("UseBridges 1", text)
        self.assertIn("ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy", text)
        self.assertTrue(any(ln.startswith("Bridge obfs4 ") for ln in _config_lines(text)))

    def test_meek_uses_meek_lite_transport(self):
        text = self._gen(["meek", "None", "None"])
        self.assertIn("ClientTransportPlugin meek_lite exec /usr/bin/obfs4proxy", text)
        self.assertTrue(any(ln.startswith("Bridge meek_lite ") for ln in _config_lines(text)))

    def test_snowflake_default_bridges(self):
        text = self._gen(["snowflake", "None", "None"])
        self.assertIn("ClientTransportPlugin snowflake exec /usr/bin/snowflake-client", text)
        self.assertTrue(any(ln.startswith("Bridge snowflake ") for ln in _config_lines(text)))

    def test_custom_bridges_marker_and_lines(self):
        text = self._gen(["None", CUSTOM_BRIDGES, "None"])
        ## The marker parse_torrc() relies on to recognise custom bridges.
        self.assertIn("# Custom bridges are used", text)
        bridge_lines = [ln for ln in _config_lines(text) if ln.startswith("Bridge ")]
        self.assertEqual(len(bridge_lines), 2)
        self.assertIn("Bridge obfs4 1.2.3.4:1234 ABCDEF0123456789ABCDEF0123456789ABCDEF01", text)
        self.assertIn("Bridge obfs4 5.6.7.8:5678 0123456789ABCDEF0123456789ABCDEF01234567", text)

    def test_socks5_proxy(self):
        text = self._gen(["None", "None", "SOCKS5", "127.0.0.1", "9050", "", ""])
        self.assertIn("Socks5Proxy 127.0.0.1:9050", text)

    def test_socks4_proxy(self):
        text = self._gen(["None", "None", "SOCKS4", "127.0.0.1", "9050", "", ""])
        self.assertIn("Socks4Proxy 127.0.0.1:9050", text)

    def test_socks5_proxy_with_auth(self):
        text = self._gen(["None", "None", "SOCKS5", "127.0.0.1", "9050", "bob", "secret"])
        self.assertIn("Socks5Proxy 127.0.0.1:9050", text)
        self.assertIn("Socks5ProxyUsername bob", text)
        self.assertIn("Socks5ProxyPassword secret", text)

    def test_a7_full_proxy_request_emits_proxy_line(self):
        ## A7: a complete 7-element proxy request must not be silently dropped.
        text = self._gen(["None", "None", "SOCKS5", "127.0.0.1", "9050", "None", "None"])
        self.assertIn("Socks5Proxy 127.0.0.1:9050", text)

    def _plugins(self, custom_bridges):
        text = self._gen(["None", custom_bridges, "None"])
        return [ln for ln in text.splitlines() if ln.startswith("ClientTransportPlugin")]

    def test_f8_vanilla_custom_bridge_does_not_crash(self):
        ## A custom bridge whose first token is not a known pluggable transport
        ## (e.g. a plain IP:port) must not raise ValueError/IndexError; it is
        ## written as a Bridge line with no ClientTransportPlugin.
        text = self._gen(
            ["None", "1.2.3.4:1234 ABCDEF0123456789ABCDEF0123456789ABCDEF01", "None"]
        )
        self.assertIn("Bridge 1.2.3.4:1234 ABCDEF0123456789ABCDEF0123456789ABCDEF01", text)
        self.assertEqual(self._plugins("1.2.3.4:1234 ABCDEF0123456789ABCDEF0123456789ABCDEF01"), [])

    def test_f8_custom_meek_lite_gets_its_plugin(self):
        ## meek bridge lines use the 'meek_lite' transport name; the required
        ## ClientTransportPlugin meek_lite line must still be emitted.
        self.assertEqual(
            self._plugins("meek_lite 192.0.2.20:80 url=https://example.com front=www.example.net"),
            ["ClientTransportPlugin meek_lite exec /usr/bin/obfs4proxy"],
        )

    def test_f8_custom_snowflake_gets_its_plugin(self):
        self.assertEqual(
            self._plugins("snowflake 192.0.2.4:80 fingerprint=ABCD"),
            ["ClientTransportPlugin snowflake exec /usr/bin/snowflake-client"],
        )

    def test_f8_mixed_vanilla_first_still_emits_obfs4_plugin(self):
        ## A vanilla bridge listed before an obfs4 bridge must not hide the
        ## obfs4 ClientTransportPlugin.
        self.assertEqual(
            self._plugins("1.2.3.4:1234 AAAA\nobfs4 5.6.7.8:5678 BBBB"),
            ["ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy"],
        )

    def test_f8_duplicate_transport_plugin_deduplicated(self):
        self.assertEqual(
            self._plugins("obfs4 1.1.1.1:1 AA\nobfs4 2.2.2.2:2 BB"),
            ["ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy"],
        )


class ParseTorrcTest(unittest.TestCase):
    """parse_torrc() recovers the configuration gen_torrc() wrote (round-trip)."""

    def _roundtrip(self, args):
        with T.sandbox():
            torrc_gen.gen_torrc(args)
            return torrc_gen.parse_torrc()

    def test_parse_none(self):
        result = self._roundtrip(["None", "None", "None"])
        self.assertEqual(result[0], "None")
        self.assertEqual(result[1], "None")

    def test_parse_obfs4(self):
        self.assertEqual(self._roundtrip(["obfs4", "None", "None"])[0], "obfs4")

    def test_parse_meek(self):
        ## Transport is 'meek_lite' in torrc but must be reported as 'meek'.
        self.assertEqual(self._roundtrip(["meek", "None", "None"])[0], "meek")

    def test_parse_snowflake(self):
        self.assertEqual(self._roundtrip(["snowflake", "None", "None"])[0], "snowflake")

    def test_parse_socks5(self):
        result = self._roundtrip(["None", "None", "SOCKS5", "127.0.0.1", "9050", "", ""])
        self.assertEqual(result[1], "SOCKS5")
        self.assertEqual(result[2], "127.0.0.1")
        self.assertEqual(result[3], "9050")

    def test_parse_socks4(self):
        self.assertEqual(
            self._roundtrip(["None", "None", "SOCKS4", "127.0.0.1", "9050", "", ""])[1],
            "SOCKS4",
        )

    def test_parse_socks5_auth(self):
        result = self._roundtrip(["None", "None", "SOCKS5", "127.0.0.1", "9050", "bob", "secret"])
        self.assertEqual(result[4], "bob")
        self.assertEqual(result[5], "secret")

    ## --- A1 regression: custom-bridge detection / data loss ------------------

    def test_a1_custom_bridges_detected_on_parse(self):
        """After writing custom bridges, parse_torrc() must report 'Custom bridges'.

        Fails on the unfixed source (parse_torrc looks for the misspelled marker
        '# Custom briges are used', so it reports the transport name 'obfs4').
        """
        result = self._roundtrip(["None", CUSTOM_BRIDGES, "None"])
        self.assertEqual(
            result[0],
            "Custom bridges",
            "custom bridges not detected on re-parse -- a later reconfigure would "
            "replace them with default obfs4 bridges (bug A1)",
        )

    def test_a1_custom_bridges_survive_reconfigure(self):
        """Reproduce the data-loss path: custom bridges, then add a proxy.

        On reconfigure the GUI re-parses the torrc to learn the current bridge
        type. If custom bridges are misdetected as 'obfs4', set_torrc() rewrites
        default bridges. Here we assert the detection that gates that path.
        """
        with T.sandbox() as torrc:
            torrc_gen.gen_torrc(["None", CUSTOM_BRIDGES, "None"])
            ## The GUI would now call parse_torrc() to preserve existing config.
            bridge_type = torrc_gen.parse_torrc()[0]
            self.assertEqual(bridge_type, "Custom bridges")
            ## The user's custom bridge lines are still present in the torrc.
            text = torrc.read_text(encoding="utf-8")
            self.assertIn("Bridge obfs4 1.2.3.4:1234", text)
            self.assertIn("Bridge obfs4 5.6.7.8:5678", text)


if __name__ == "__main__":
    unittest.main()
