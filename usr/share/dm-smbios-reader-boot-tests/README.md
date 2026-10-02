# dm-smbios-reader-boot-tests: boot + functional test harness

Boots a built derivative-maker image, drives a login-free root serial shell, runs
`systemcheck --leak-tests`, and reports one pass/fail exit code. The CI front-end
`dm-smbios-reader-boot-test` (installs the runtime, discovers the boot media by image
kind, forwards to `dm-smbios-reader-boot-tests`) and the whole harness live here
(test-only tooling), not in derivative-maker; derivative-maker CI calls
`dist-ai/usr/bin/dm-smbios-reader-boot-test`.

The name says the hard prerequisite: the harness is functional ONLY on an image
built with derivative-maker `--smbios-reader true`. The login-free serial shell AND
`--session` selection are delivered entirely by a kernel cmdline injected through the
SMBIOS Type-1 serial -> in-image GRUB reader -> kernel chain (see below); a released
image carries no reader, so the injection is a silent no-op and every leg times out
with a ~0-byte serial log (flagged by the image-test 0-byte-log diagnostic).

- `dm-smbios-reader-image-test` -- orchestrator: picks a backend (`--backend
  {auto,qemu,vbox}`), obtains a pexpect child, drives the SAME serial conversation,
  reports 0 PASS / 5 FAIL / 2 SETUP.
- `dm-smbios-reader-qemu` -- builds the qemu argv (does not boot). `--test-console`,
  `--smbios-append`, `--screendump`, `--iso`/`--disk`, `--emit-argv`, `--emit-cmdline`.
- `dm-smbios-reader-vbox` -- the VBox/AMD-V backend. `serial-up`/`serial-down` build
  + boot a VM wired for serial driving; also the OCR run/install lanes + `emit-argv`.
- `debug/` -- boot-once/poke-many dev tooling (`dmserial.py`); not gated.

## Backends: QEMU (default) and VBox/AMD-V (`--backend vbox`)

Both run the identical `systemcheck` serial battery; they differ only in how the VM
is booted and how the serial console is reached.

- **qemu** -- `dm-smbios-reader-image-test` gets qemu argv from `dm-smbios-reader-qemu
  --emit-argv`, spawns it under pexpect, reads the serial pty.
- **vbox** -- for the AMD OVH image-test server, which has AMD-V (svm) but no
  `/dev/kvm`, so qemu falls back to slow software TCG (~10-15 min) while VirtualBox
  uses AMD-V natively (~2-3 min). `dm-smbios-reader-image-test` gets the RAW cmdline
  payload from `dm-smbios-reader-qemu --emit-cmdline` (the SINGLE source both backends
  inject), calls `dm-smbios-reader-vbox serial-up` to build + boot a headless VM with
  COM1 wired to a host UNIX socket + the payload injected via VBox DMI, connects the
  socket with `pexpect.fdpexpect.fdspawn`, and drives `run_checks` unchanged.
  `--backend auto` picks vbox when VBoxManage is present AND `/dev/kvm` is absent AND
  the CPU is AMD, else qemu. VBoxManage is a HARD dependency of the vbox lane -- its
  absence is a loud SETUP error, never a skip.
- **DMI vendor must be QEMU.** The in-image GRUB reader fires only when SMBIOS Type-1
  Manufacturer reads `QEMU`, so the vbox backend sets DMI vendor=QEMU; under VBox DMI
  the serial carries SINGLE commas (qemu's `-smbios` doubles them, VBox takes the
  value verbatim).
- **AMD-V serialisation.** VBox shares AMD-V across its own VMs (the fleet runs many
  concurrently), so an `fcntl` run-mutex serialises concurrent BOOT-TEST runs only
  (VM-name / RAM contention), NOT the fleet; `dm-smbios-reader-vbox ensure-amd-v`
  still guards the KVM<->VBox boundary (it refuses to yank AMD-V from a running KVM
  VM). Each run asserts, from the VM's `VBox.log`, that AMD-V/VT-x is actually in use
  (SETUP if not) so a silently-degraded run cannot pass as the fast path.

### VBox lane: items to confirm in the live server integration test

The pure logic + argv builders are unit-tested without a VBox host; these need the
real VirtualBox 7.x server (see the `vbox-image-testing` skill) to confirm:

- **EFI DMI.** The `pcbios` DMI extradata keys supply SeaBIOS; whether an EFI /
  efi-secureboot guest reads the SAME keys is VBox-version-dependent. If it does not,
  the EFI cmdline injection is a no-op -> the serial shell never binds (0-byte log).
  Confirm `dmidecode` in an EFI guest shows vendor=QEMU + the `dm-cmdline` serial; if
  not, add the EFI device's DMI key path in `dm-smbios-reader-vbox` `build_dmi_argv`.
- **Disk format.** `--mtype multiattach` (the non-destructive `-snapshot` analogue)
  needs a differencing-capable format (VDI/VMDK/VHD); a RAW disk is rejected. dm
  images are often qcow2/raw, so confirm the format works (convert raw->vdi if not).

## Kernel cmdline injection: firmware -> GRUB -> kernel (no image edit)

The tester injects kernel cmdline (session selection, `console=ttyS0`,
`systemd.debug_shell`) through the REAL firmware->GRUB->kernel chain via SMBIOS,
so all three firmware paths (BIOS, EFI, EFI-secureboot) are exercised and the
image is never modified:

- `dm-smbios-reader-qemu` passes `-smbios type=1,serial=dm-cmdline=<cmdline>`. Commas in the
  value MUST be doubled (`console=ttyS0,,115200n8`) or qemu's `-smbios` parser
  splits on them.
- A GRUB reader (near the top of grub.cfg) reads SMBIOS Type-1 field 7 (system
  serial number -- a real string-ref field GRUB can read; Type-11 OEM strings
  have no such field) and, on the `dm-cmdline=` sentinel, exposes the rest as
  `${dm_smbios_extra}`. `insmod smbios; insmod regexp` first.
- The reader lives in TWO places, one per image kind:
  - ISO: `iso-build-data/grub-config/smbios-reader.cfg`, inlined into the ISO's
    `config.cfg` by `help-steps/dm-raw-to-iso` (derivative-maker main tree) when
    `4310_convert-raw-to-iso` passes `--smbios-reader`.
  - Disk (qcow2/vbox): `vm-config-dist` `etc/grub.d/01_smbios-reader` +
    `etc/default/grub.d/99_smbios-cmdline.cfg` (appends `\${dm_smbios_extra}` to
    every generated kernel line). Regenerated on every `update-grub`.
- No SMBIOS set -> `${dm_smbios_extra}` empty -> no-op (normal boot unaffected).
- Kept identical between the two copies by `dm-grub-smbios-tests`.

### The reader is OPT-IN: build with `--smbios-reader true`

**A released image carries no reader.** Boot-test images must be built with the
derivative-maker build option `--smbios-reader true`, or every boot leg times out
with a 0-byte serial log. `.github/workflows/local-boot-test.yml` passes it.

Why, in one line: the reader turns a firmware-supplied string into kernel command
line, and the kernel command line is the part of the boot chain Secure Boot does
not authenticate.

- **Impact if shipped.** Whoever can write SMBIOS Type 1 Serial gets arbitrary
  trailing kernel cmdline, so `init=/bin/sh` -- unauthenticated root. The
  placeholder is appended to `GRUB_CMDLINE_LINUX_DEFAULT`, which trails everything
  `grub-mkconfig` emits, and the kernel takes the last occurrence. Kicksecure sets
  no `lockdown=` (commented out in `40_signed_modules.cfg`), and lockdown would not
  stop `init=` anyway.
- **Who can write it without OS root.** Supermicro SUM `EditDmiInfo`/`ChangeDmiInfo`
  over IPMI with no OS on the box; HPE via RBSU through iLO KVM; any OEM/reseller/
  refurbisher DMI editor. Stock Redfish is narrower -- `SerialNumber` is
  `readonly: true`, only `AssetTag` is writable. Set once in the supply chain it
  is persistent: survives disk wipe and reinstall.
- **Severity: hardening gap, not a CVE.** Every attacker who can reach it can
  already do worse; it grants convenience, stealth and persistence, not a new
  capability. Do NOT call it a Secure Boot bypass -- Secure Boot never covered the
  cmdline. Under SEV-SNP/TDX it would be a genuine boundary crossing, which is
  exactly why systemd stopped trusting SMBIOS there (PR #28301).
- **Prior art.** Reading SMBIOS into the cmdline is the GRUB `smbios` module's
  designed purpose, so this is not a GRUB flaw. No other distro ships it in
  grub.cfg. systemd ships the equivalent (Type 11 `io.systemd.stub.
  kernel-cmdline-extra`) but measures it into PCR12; ours is measured nowhere.

Second, weaker layer for an image that IS built with the reader: the serial number
is read only when SMBIOS Type 1 Manufacturer says `QEMU`. That is detectability,
not a boundary -- the same vendor DMI tool sets Manufacturer -- but it forces the
machine to advertise itself as a QEMU guest to `dmidecode` and every inventory
system instead of hiding in a field nobody reads.

Rejected as too complex for the benefit: blessed-token selectors, an
operator-supplied unlock device (`search --fs-uuid`), and a signed config fragment
(`verify_detached`). Notes for whoever revisits this -- all measured, not assumed:
GRUB has NO unspoofable virtualization detection and cannot have one (`cpuid`
exposes only `--long-mode`/`--pae`, cannot set a variable; the SMBIOS Type 0 VM bit
is unset under SeaBIOS; GRUB script has no command substitution, so `lspci` and
friends are unusable as conditions). `pgp`, `gcry_rsa`, `gcry_sha256`,
`verify_detached` and `search` DO work under Secure Boot lockdown, so the signed
fragment remains available if a stronger boundary is ever needed.

## Serial-console gotchas (hard-won)

- **`-nodefaults` cancels `-nographic`'s serial.** `-nographic`'s serial device
  is a "default", so `-nodefaults` strips it: the guest gets no ttyS0 and the
  root shell never appears (zero serial output). Drive the console EXPLICITLY:
  `-display none -serial mon:stdio -vga none`. (`-nodefaults` is used to drop the
  phantom q35 IDE CD-ROM `ide2-cd0`, which otherwise makes udisks log a benign
  `sr0` IDENTIFY-PACKET-DEVICE error the journal check flags.)
- **Headless GUI images need the rads GPU-skip.** With no DRM device, labwc fails
  and floods the journal. rads master skips the desktop when headless -- keep the
  `rads` gitlink at/after that commit.
- **When injecting, drive serial + boot immediately.** The reader, on a non-empty
  `${dm_smbios_extra}`, runs `serial --unit=0 ...; terminal_output serial console;
  set timeout=0`. `timeout=0` is essential: a headless tester cannot dismiss the
  GRUB menu, so any countdown hangs the boot. Normal boot keeps `gfxterm`.
- **The serial log is written by qemu, NOT by the pexpect reader.** `dm-smbios-reader-image-test`
  reads the console through a pexpect pty only to DRIVE the conversation. A verbose
  guest burst (`systemcheck`'s ~40 checks) emits faster than the Python reader
  drains the pty; qemu then DROPS the bytes it cannot hand to the full pty, so the
  reader sees only the tail (early checks, e.g. the `check_services` failed-unit
  list, are lost). Fix: `dm-smbios-reader-image-test` passes `dm-smbios-reader-qemu --serial-logfile <log>`,
  which wires an explicit `-chardev stdio,...,logfile=<log> -serial chardev:...`
  instead of `-serial mon:stdio`. qemu copies every serial byte to that regular
  file with a blocking write BEFORE the lossy pty write, so the log is COMPLETE
  regardless of reader speed. The pty stream still carries the trailing exit-code
  sentinel (emitted after the burst, when the pty is calm), so driving stays
  reliable. Do not also write the log from Python -- two writers would race.

## systemcheck in the boot test: skip environment/timing checks

The default check is `systemcheck --cli --leak-tests --verbose`. Two of its
checks are environment/timing dependent, not image-integrity, and flake a healthy
image red -- skipped for the test via systemcheck's own `systemcheck_skip_functions`
knob (a `/etc/systemcheck.d/50_boot-test.conf` drop-in written into the RUNNING
guest only; the image and real-user systemcheck are untouched):

- `check_operating_system` -- a snapshot-pinned image always has apt updates
  pending ("packages can be updated"); freshness, not a boot failure.
- `check_tor_bootstrap` -- the live Tor Connection / time-sync check races Tor's
  async bootstrap over the CI network; bootstrap time is highly variable (one run
  <4 min, the next exceeds it or is throttled), so it is non-deterministic and
  cannot gate CI. Tor's CONFIG is still validated by `check_tor_config` /
  `check_tor_enabled`; only the live network connection is skipped. A bounded
  pre-wait for "Bootstrapped 100%" did NOT fix this -- no wait guarantees success.

## Disk images: BIOS vs EFI grub

qcow2/vbox disks built via grml-debootstrap with `--vmefi` install BOTH BIOS and
EFI grub ONLY when `is_grub_bios_compatible` (grml-debootstrap chroot-script)
detects the `bios_grub` partition during the loop-device build. When that
detection fails, `MAIN_GRUB_PACKAGE=grub-efi-amd64` (EFI-only): no
`/boot/grub/i386-pc`, so **BIOS boot of the disk is dead (zero serial)** even
though the `bios_grub` partition exists. EFI disk legs boot fine. Symptom to
recognize: qcow2/vbox BIOS legs produce an empty serial log while the EFI legs
of the same image boot to a shell.

## CI dispatch notes

- `local-boot-test.yml` has `concurrency: cancel-in-progress: true` keyed by
  `workflow-ref`. A `rerun-failed-jobs` on an old run and a fresh dispatch of the
  SAME workflow+ref cancel each other -- only ONE run per ref at a time.
- Boot legs check out `dist-ai` fresh at job runtime, so a harness fix can be
  validated by re-running the boot legs against EXISTING build artifacts (fast,
  no rebuild) -- as long as no competing run cancels it.
- CI mirrors submodules to org-ai-assisted (`configure-fork-mirror`), then checks
  out the parent gitlink SHA UNLESS an exact `refs/heads/ai` branch exists on the
  fork for that submodule (`checkout-fork-branch` switches to it). The target SHA
  must be reachable on org-ai-assisted.
