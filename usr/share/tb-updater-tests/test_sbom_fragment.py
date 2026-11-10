#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Guard for tb-updater's SBOM fragment producer (tb_sbom_fragment_create in
update-torbrowser).

Tor Browser is installed into the image as a signed tarball, not a .deb, so
debsbom (dpkg-only) cannot see it. update-torbrowser writes a CycloneDX
component fragment describing exactly what it installed; the postinst publishes
it to /usr/share/sbom/fragments.d where derivative-sbom merges it into the
image SBOM. If this producer regresses, Tor Browser silently drops out of the
image SBOM -- a CRA completeness gap that nothing else would catch.

These tests source the REAL update-torbrowser and drive the real function with
only log output stubbed, a fixture cache dir, and a fake tarball, then assert
the emitted CycloneDX component:
  * only the system (--postinst) install path writes a fragment;
  * the fragment carries name/version/supplier/purl and the SHA-256 of the
    exact tarball that was installed;
  * with no tarball present it degrades to a hashless but still-valid fragment.
"""

import hashlib
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import tb_updater_testlib as T  # noqa: E402

try:
    UPDATER = T.update_torbrowser_script()
except SystemExit:
    pytest.skip("tb-updater not available", allow_module_level=True)

FUNC = "tb_sbom_fragment_create"

## Only log output is stubbed; the function's own logic runs as shipped.
STUBS = "log() { :; }\n"

## Refuse to drive an older update-torbrowser that lacks the producer (it would
## otherwise just no-op and the test would falsely pass).
REQUIRE = (
    f'declare -f {FUNC} >/dev/null || {{\n'
    f'   printf \'%s\\n\' "{FUNC} not defined" >&2\n'
    f'   exit {T.DRIVE_UNUSABLE}\n'
    '}'
)

TB_VERSION = "14.5.3"
TB_ARCH = "linux-x86_64"
TB_LINK = (
    "https://www.torproject.org/dist/torbrowser/"
    f"{TB_VERSION}/tor-browser-{TB_ARCH}-{TB_VERSION}.tar.xz"
)


def _base_env(cache_dir, tarball=None):
    env = {
        "tb_cache_folder": str(cache_dir),
        "tbb_version_stripped": TB_VERSION,
        "ARCH_DOWNLOAD": TB_ARCH,
        "tb_browser_name": "tor-browser",
        "tb_title": "Tor Browser",
        "TBB_PACKAGE_LINK": TB_LINK,
        "TBB_PACKAGE_FULL_PATH": str(tarball) if tarball is not None else "",
        ## Force the producer's own defaults, independent of the caller's
        ## environment (an inherited tb_sbom_supplier would make the test
        ## environment-dependent).
        "tb_sbom_supplier": "",
        "tb_sbom_supplier_url": "",
    }
    return env


def _drive(cache_dir, env, who_ami="tb-updater"):
    ## who_ami is assigned at source time (whoami), so it cannot be driven via
    ## the environment; set it in the post-source setup instead. The producer
    ## writes a fragment only on the system install path (who_ami == tb-updater).
    setup = f'{STUBS}who_ami={who_ami!r}\n'
    proc = T.drive_sourced_function(
        UPDATER, FUNC, setup=setup, require=REQUIRE, env=env)
    assert proc.returncode != T.DRIVE_UNUSABLE, proc.stderr
    assert proc.returncode == 0, f"stderr: {proc.stderr}\nstdout: {proc.stdout}"
    return proc


def _fragment(cache_dir):
    path = cache_dir / "sbom-fragment.json"
    assert path.is_file(), "fragment not written"
    return json.loads(path.read_text(encoding="utf-8"))


def test_system_install_writes_fragment_with_hash(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    tarball = tmp_path / "tor-browser.tar.xz"
    payload = b"fake-tor-browser-tarball-content"
    tarball.write_bytes(payload)
    want_hash = hashlib.sha256(payload).hexdigest()

    _drive(cache, _base_env(cache, tarball), who_ami="tb-updater")
    frag = _fragment(cache)

    assert frag["type"] == "application"
    assert frag["name"] == "Tor Browser"
    assert frag["version"] == TB_VERSION
    assert frag["supplier"]["name"] == "The Tor Project"
    assert frag["bom-ref"] == f"tor-browser@{TB_VERSION}"
    ## The component hash is the SHA-256 of the exact installed tarball.
    assert frag["hashes"][0]["alg"] == "SHA-256"
    assert frag["hashes"][0]["content"] == want_hash
    ## purl: generic package, arch qualifier, and the same checksum.
    assert frag["purl"] == (
        f"pkg:generic/tor-browser@{TB_VERSION}"
        f"?arch={TB_ARCH}&checksum=sha256:{want_hash}"
    )
    dist = [r["url"] for r in frag["externalReferences"]
            if r["type"] == "distribution"]
    assert dist == [TB_LINK]


def test_per_user_run_writes_nothing(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    tarball = tmp_path / "tor-browser.tar.xz"
    tarball.write_bytes(b"x")

    ## A direct per-user run (who_ami is the invoking user, not 'tb-updater')
    ## installs a private browser that is not part of the system SBOM.
    _drive(cache, _base_env(cache, tarball), who_ami="user")
    assert not (cache / "sbom-fragment.json").is_file()


def test_missing_tarball_degrades_to_hashless_fragment(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    ## TBB_PACKAGE_FULL_PATH points at a nonexistent file.
    env = _base_env(cache, tmp_path / "absent.tar.xz")
    _drive(cache, env, who_ami="tb-updater")
    frag = _fragment(cache)

    ## A hashless fragment is still a VALID CycloneDX component: the required
    ## type/name/version are present.
    assert frag["type"] == "application"
    assert frag["name"] == "Tor Browser"
    assert frag["version"] == TB_VERSION
    assert "hashes" not in frag
    ## Without a hash the purl carries no checksum qualifier, but stays valid.
    assert frag["purl"] == f"pkg:generic/tor-browser@{TB_VERSION}?arch={TB_ARCH}"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
