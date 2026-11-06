#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression tests for kloak's privilege-separation hardening.

kloak was split into a libinput proxy (/usr/bin/kloak) that fork+execve's a
sandboxed Wayland adapter (/usr/bin/kloakwl). kloakwl builds an in-process
sandbox: an unprivileged user namespace plus mnt/net/ipc/pid/uts/cgroup
namespaces, pivot_root into an empty root, a drop of all capabilities, and a
drop to the unprivileged kloakwl uid/gid. Because kloakwl inherits the systemd
unit's seccomp filter and namespace policy, and is launched via an AppArmor
transition, several invariants must hold together or the daemon dies at startup:

  * kloak.service SystemCallFilter must be GROUP-based, not a hand-maintained
    list of individual syscall names. Groups are arch-neutral (systemd expands
    each to the syscalls that exist on the running arch), so no x86-only name can
    be silently omitted on arm64 -- the root cause of the original arm64 SIGSYS
    crash loop. A bare hand-list is the regression this guards against.
  * RestrictNamespaces must PERMIT the namespaces kloakwl unshares; the former
    RestrictNamespaces=true denied all of them and killed the sandbox.
  * NoNewPrivileges must be OFF: kloak execs kloakwl under a SEPARATE, broader
    AppArmor profile (Px), and no_new_privs forbids an exec transition to a
    non-subset profile, so the spawn is denied ("info=no new privs"). The unit
    SystemCallFilter still installs (root executor) and is inherited by kloakwl.
  * CapabilityBoundingSet must grant CAP_SETUID/CAP_SETGID: kloakwl drops to an
    unprivileged uid BEFORE it unshares, while its effective set is masked to the
    bounding set, so the drop fails EPERM without them. sys_admin/sys_chroot are
    NOT needed -- kloakwl's mount/pivot_root run inside its own new user namespace.
  * usr.bin.kloak must AUTHORIZE the exec of /usr/bin/kloakwl, or AppArmor denies
    the spawn.
  * a usr.bin.kloakwl profile must exist and grant the sandbox operations (user
    namespace creation, mount, pivot_root), capability dac_override (to traverse
    the user-owned /run/user/<uid> to the Wayland socket), the numeric-pid
    uid/gid map writes (AppArmor mediates the resolved pid path, not /proc/self),
    and /tmp for the pivot_root tmpfs tree.
  * the unprivileged kloakwl user/group must be created, or kloakwl FATALs when
    it looks them up to drop privileges.

All files are read from the REAL kloak checkout (resolved via KLOAK_REPO); no
copy, no body-cut.
"""

import os
import re
import unittest

## systemd syscall groups the unit must grant for kloak's proxy work plus
## kloakwl's sandbox setup (unshare, mount/pivot_root, capset, uid/gid drop,
## rlimit). Their presence is the arch-neutral replacement for the old hand-list.
REQUIRED_SYSCALL_GROUPS = (
    '@system-service',
    '@sandbox',
    '@mount',
    '@privileged',
    '@setuid',
)

## Namespaces kloakwl's self_sandbox unshares that RestrictNamespaces must allow;
## omitting any one makes systemd deny that unshare (EPERM) and the sandbox dies.
## CLONE_SYSVSEM and CLONE_NEWTIME have no RestrictNamespaces token, so are not
## listed here.
REQUIRED_NAMESPACES = ('user', 'pid', 'net', 'ipc', 'uts', 'cgroup', 'mnt')

## Every namespace type systemd's RestrictNamespaces understands. With no
## assignment (or an explicit false) all of them are allowed; a positive list
## is an allow-list that restricts to the listed set.
ALL_SYSTEMD_NAMESPACES = frozenset(
    ('cgroup', 'ipc', 'net', 'mnt', 'pid', 'user', 'uts'))

## systemd's full boolean spellings (src/basic/parse-util.c parse_boolean):
## a RestrictNamespaces=/NoNewPrivileges= value equal to one of these IS a
## boolean, not a namespace token. No namespace name collides with them.
SYSTEMD_TRUE = frozenset(('1', 'yes', 'y', 'true', 't', 'on'))
SYSTEMD_FALSE = frozenset(('0', 'no', 'n', 'false', 'f', 'off'))


def _repo() -> str:
    return os.path.abspath(os.environ.get('KLOAK_REPO', '').strip() or '/')


def _read(rel_path: str) -> str:
    with open(os.path.join(_repo(), rel_path), encoding='utf-8') as handle:
        return handle.read()


def _require_source() -> None:
    service = os.path.join(
        _repo(), 'usr', 'lib', 'systemd', 'system', 'kloak.service')
    if not os.path.exists(service):
        ## style-ok: allow-skip: kloak source absent (not a --component run)
        raise unittest.SkipTest(
            'kloak.service not found under %s -- set KLOAK_REPO or install the '
            'kloak source' % service)


class PrivsepHardening(unittest.TestCase):
    service_text: str
    kloak_aa: str
    kloakwl_aa: str
    sysusers_text: str

    @classmethod
    def setUpClass(cls) -> None:
        _require_source()
        cls.service_text = _read('usr/lib/systemd/system/kloak.service')
        cls.kloak_aa = _read('etc/apparmor.d/usr.bin.kloak')
        cls.kloakwl_aa = _read('etc/apparmor.d/usr.bin.kloakwl')
        cls.sysusers_text = _read('debian/kloak.sysusers')

    def _directive_tokens(self, text: str, name: str) -> list[str]:
        ## systemd MERGES repeated SystemCallFilter=/RestrictNamespaces= (and the
        ## other list directives) -- it does NOT take the last line -- so union the
        ## tokens of every matching line. An assignment with an empty value resets
        ## the list (systemd.exec(5)).
        tokens: list[str] = []
        for line in text.splitlines():
            match = re.match(r'\s*%s=(.*)' % re.escape(name), line)
            if match is None:
                continue
            value = match.group(1).strip()
            if value == '':
                tokens = []
                continue
            tokens.extend(value.split())
        return tokens

    def _directive_values(self, text: str, name: str) -> list[str]:
        ## The ordered raw value of EACH matching assignment (not unioned), for a
        ## directive whose repeated-assignment merge is order-sensitive. An empty
        ## value is kept -- it resets the directive (systemd.exec(5)).
        values: list[str] = []
        for line in text.splitlines():
            match = re.match(r'\s*%s=(.*)' % re.escape(name), line)
            if match is None:
                continue
            values.append(match.group(1).strip())
        return values

    def test_syscall_filter_is_group_based(self) -> None:
        tokens = self._directive_tokens(self.service_text, 'SystemCallFilter')
        self.assertTrue(tokens, 'kloak.service has no SystemCallFilter')
        self.assertFalse(
            any(token.startswith('~') for token in tokens),
            'SystemCallFilter is a deny-list (%r); kloak uses an allow-list of '
            'groups' % tokens)
        for group in REQUIRED_SYSCALL_GROUPS:
            self.assertIn(
                group, tokens,
                "SystemCallFilter is missing the %s syscall group. A bare "
                "individual-syscall allow-list is the arm64 SIGSYS trap this "
                "guards against -- arch-neutral groups must cover kloak's proxy "
                "work and kloakwl's sandbox setup. Filter: %r" % (group, tokens))

    def test_restrictnamespaces_permits_sandbox(self) -> None:
        values = self._directive_values(self.service_text, 'RestrictNamespaces')
        self.assertTrue(values, 'kloak.service has no RestrictNamespaces')
        ## Compute the EFFECTIVE allowed namespace set the way systemd merges
        ## repeated RestrictNamespaces= in order (systemd.exec(5)); kloakwl can
        ## only unshare a namespace that ends up allowed:
        ##   * true/yes/1/on     -> allow NONE (restrict all)
        ##   * false/no/0/off/"" -> allow ALL (reset to no restriction)
        ##   * a bare list       -> an allow-list: the FIRST restricts to the
        ##                          listed set, later ones UNION more in
        ##   * a '~' list        -> a deny-list: REMOVE the listed from allowed
        ## So a trailing `=true`, a shortened list, or a '~' deny of a needed
        ## namespace leaves it un-allowed -- the regression this guards. A
        ## boolean is NOT fatal on its own: `=true` followed by the allow-list
        ## re-grants every namespace (verified with systemctl show -p
        ## RestrictNamespaces), so rejecting a boolean token outright would
        ## false-positive on a working config.
        ## Scope: this models the realistic single-[Service] directive -- boolean
        ## reset, positive-list union, '~' deny. It deliberately does NOT
        ## reimplement systemd's full parser (section-keyed directive tables, or
        ## the atomic rejection of a list carrying an unknown token): kloak.service
        ## is one [Service] line, none of those are realistic regressions here,
        ## and a typo that drops a REQUIRED namespace is already caught below.
        allowed = set(ALL_SYSTEMD_NAMESPACES)
        restricted = False
        for value in values:
            lowered = value.lower()
            if value == '' or lowered in SYSTEMD_FALSE:
                allowed = set(ALL_SYSTEMD_NAMESPACES)
                restricted = False
            elif lowered in SYSTEMD_TRUE:
                allowed = set()
                restricted = True
            elif value.startswith('~'):
                deny = {token.lstrip('~') for token in value.split()}
                base = allowed if restricted else set(ALL_SYSTEMD_NAMESPACES)
                allowed = base - deny
                restricted = True
            else:
                listed = set(value.split())
                allowed = listed if not restricted else (allowed | listed)
                restricted = True
        missing = [ns for ns in REQUIRED_NAMESPACES if ns not in allowed]
        self.assertFalse(
            missing,
            "effective RestrictNamespaces does not allow %r that kloakwl's "
            "self_sandbox unshares; allowed set is %r. Assignments (in order): "
            "%r" % (missing, sorted(allowed), values))

    def test_no_new_privileges_off_for_profile_transition(self) -> None:
        tokens = self._directive_tokens(self.service_text, 'NoNewPrivileges')
        self.assertTrue(tokens, 'kloak.service has no NoNewPrivileges')
        self.assertNotIn(
            tokens[-1].lower(), SYSTEMD_TRUE,
            "NoNewPrivileges=%s blocks the kloak->kloakwl AppArmor Px transition: "
            "no_new_privs forbids a transition to kloakwl's broader (non-subset) "
            "profile, so kloak restart-loops" % tokens[-1])

    def test_bounding_set_permits_privilege_drop(self) -> None:
        tokens = self._directive_tokens(self.service_text, 'CapabilityBoundingSet')
        self.assertTrue(tokens, 'kloak.service has no CapabilityBoundingSet')
        for cap in ('CAP_SETUID', 'CAP_SETGID'):
            self.assertIn(
                cap, tokens,
                "CapabilityBoundingSet lacks %s; kloakwl's pre-unshare privilege "
                "drop (setgroups/setresuid) fails EPERM. Value: %r" % (cap, tokens))

    def test_kloak_apparmor_requires_kloakwl_profile_transition(self) -> None:
        ## kloak must exec kloakwl under a discrete/child AppArmor PROFILE
        ## transition (Px/Cx family) -- the thing that gives the privilege
        ## separation: kloakwl runs under its OWN broader profile. An inherit
        ## (ix) transition would run kloakwl under kloak's narrow profile (no
        ## separation, and the sandbox build is then denied); an unconfined
        ## (ux/Ux) transition would drop confinement entirely. Either is a
        ## privsep regression, so a bare ix/ux/Ux must fail this -- it is NOT
        ## enough that SOME transition authorizes the execve. A FALLBACK form
        ## (PUx/Pux, Pix/Cix, ...) must fail too: it runs kloakwl unconfined or
        ## under kloak's own profile when the target profile is absent, silently
        ## losing the separation. So require a BARE profile transition (exactly
        ## P/p/C/c, optionally after read/mem perms). Absence of any rule means
        ## AppArmor denies the spawn.
        match = re.search(
            r'^\s*/usr/bin/kloakwl\s+([^,]*?)\s*,', self.kloak_aa, re.MULTILINE)
        self.assertIsNotNone(
            match,
            'usr.bin.kloak has no exec rule for /usr/bin/kloakwl, so AppArmor '
            'denies the kloak->kloakwl execve')
        assert match is not None  # narrow for mypy; asserted above
        perms = match.group(1).strip()
        ## Split off a named-transition target (`Px -> profile`) first, then read
        ## the exec mode from the head. apparmor_parser accepts file-perm letters
        ## (r/m/w/l/k/a) on EITHER side of the exec 'x' (rPx, Pxr, Pixr all parse),
        ## and 'x' is the only exec marker, so capture the run of transition
        ## letters [pPcCuUi] immediately before that sole 'x'.
        head, named, target = perms.partition('->')
        mode = re.search(r'([pPcCuUi]*)x', head)
        self.assertIsNotNone(
            mode,
            'usr.bin.kloak kloakwl rule %r carries no exec (x) transition mode'
            % perms)
        assert mode is not None  # narrow for mypy; asserted above
        qualifier = mode.group(1)
        self.assertRegex(
            qualifier, r'^[PpCc]$',
            "usr.bin.kloak execs kloakwl with transition mode '%sx', not a BARE "
            "profile (Px/Cx) transition: 'ix' inherits kloak's profile (no "
            "separation), 'ux'/'Ux' runs kloakwl unconfined, and a fallback form "
            "(e.g. 'PUx'/'Pix') drops to unconfined/inherit when the target "
            "profile is absent -- all defeat the privsep" % qualifier)
        ## A named transition must target kloakwl's OWN profile. A bare `Px,`
        ## (no `->`) already transitions to the profile named for the executable
        ## (/usr/bin/kloakwl), which is correct; `-> usr.bin.kloak` (kloak's own
        ## narrow profile) or any other target runs kloakwl confined to the wrong
        ## profile, so its sandbox build (userns/mount/pivot_root) is denied.
        if named:
            self.assertEqual(
                target.strip(), '/usr/bin/kloakwl',
                "usr.bin.kloak execs kloakwl with a named transition to %r, not "
                "kloakwl's own profile (/usr/bin/kloakwl); the wrong target "
                "profile denies kloakwl's sandbox build" % target.strip())

    def test_kloakwl_apparmor_profile_grants_sandbox(self) -> None:
        self.assertIn(
            '/usr/bin/kloakwl', self.kloakwl_aa,
            'usr.bin.kloakwl does not attach to /usr/bin/kloakwl')
        for rule in ('userns', 'mount', 'pivot_root'):
            self.assertRegex(
                self.kloakwl_aa, r'(?m)^\s*%s\b' % rule,
                "usr.bin.kloakwl is missing the '%s' rule kloakwl's sandbox "
                "needs; AppArmor would deny it" % rule)

    def test_kloakwl_apparmor_profile_privdrop_and_mapping(self) -> None:
        self.assertRegex(
            self.kloakwl_aa, r'(?m)^\s*capability\s+dac_override\b',
            'usr.bin.kloakwl lacks capability dac_override; as root (pre-drop) it '
            'cannot traverse the user-owned /run/user/<uid> to the Wayland socket')
        ## The three map files may be written as separate lines
        ## (@{PROC}/@{pid}/uid_map rw) or as one brace alternation
        ## (@{PROC}/@{pid}/{uid_map,gid_map,setgroups} rw); apparmor_parser expands
        ## the brace, so both are equivalent. Accept either shape -- do NOT
        ## reimplement apparmor's full alternation grammar (the realistic profile
        ## is one of these two forms). What matters is a writable rule on the
        ## numeric-@{pid} path, not /proc/self. The brace branch requires the map
        ## name to be a COMPLETE comma-delimited alternative (bounded by { or , on
        ## the left and , or } on the right), not a substring: a \b word boundary
        ## would wrongly accept {uid_map.bak,...} or {task/uid_map,...}, which
        ## AppArmor expands to the .bak / task/ paths, NOT the real map files.
        for mapfile in ('uid_map', 'gid_map', 'setgroups'):
            self.assertRegex(
                self.kloakwl_aa,
                r'(?m)^\s*@\{PROC\}/@\{pid\}/(?:%s|\{(?:[^}]*,)?%s(?:,[^}]*)?\})'
                r'\s+\S*w' % (mapfile, mapfile),
                "usr.bin.kloakwl lacks a writable @{PROC}/@{pid}/%s rule; AppArmor "
                "mediates the resolved numeric-pid path, not the /proc/self magic "
                "symlink, so a @{PROC}/self rule never matches" % mapfile)
        self.assertRegex(
            self.kloakwl_aa, r'(?m)^\s*/tmp/\S*\s+\S*w',
            'usr.bin.kloakwl lacks /tmp write; kloakwl cannot build the tmpfs tree '
            'it pivot_roots into')

    def test_kloakwl_system_user_created(self) -> None:
        ## sysusers 'u' line creates the user and its matching group; kloakwl
        ## getpwnam/getgrnam("kloakwl") and FATALs if either is absent.
        self.assertRegex(
            self.sysusers_text, r'(?m)^\s*u\s+kloakwl\b',
            'debian/kloak.sysusers does not create the kloakwl system user')


if __name__ == '__main__':
    unittest.main()
