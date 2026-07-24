# dm-image-boot-tests: boot + functional test harness

Boots a built derivative-maker image in qemu, drives a login-free root serial
shell, runs `systemcheck --leak-tests`, and reports one pass/fail exit code.
Invoked from derivative-maker `ci/boot-test`; the harness itself lives here
(test-only tooling), not in derivative-maker.

- `dm-image-test` -- orchestrator: gets qemu argv from `dm-qemu --emit-argv`,
  spawns it under pexpect, drives the conversation over serial.
- `dm-qemu` -- builds the qemu argv (does not boot). `--test-console`,
  `--smbios-append`, `--screendump`, `--iso`/`--disk`.
- `debug/` -- boot-once/poke-many dev tooling (`dmserial.py`); not gated.

## Kernel cmdline injection: firmware -> GRUB -> kernel (no image edit)

The tester injects kernel cmdline (session selection, `console=ttyS0`,
`systemd.debug_shell`) through the REAL firmware->GRUB->kernel chain via SMBIOS,
so all three firmware paths (BIOS, EFI, EFI-secureboot) are exercised and the
image is never modified:

- `dm-qemu` passes `-smbios type=1,serial=dm-cmdline=<cmdline>`. Commas in the
  value MUST be doubled (`console=ttyS0,,115200n8`) or qemu's `-smbios` parser
  splits on them.
- A GRUB reader (near the top of grub.cfg) reads SMBIOS Type-1 field 7 (system
  serial number -- a real string-ref field GRUB can read; Type-11 OEM strings
  have no such field) and, on the `dm-cmdline=` sentinel, exposes the rest as
  `${dm_smbios_extra}`. `insmod smbios; insmod regexp` first.
- The reader lives in TWO places, one per image kind:
  - ISO: `live-build-data/grub-config/config.cfg` (derivative-maker main tree).
  - Disk (qcow2/vbox): `vm-config-dist` `etc/grub.d/01_smbios-reader` +
    `etc/default/grub.d/99_smbios-cmdline.cfg` (appends `\${dm_smbios_extra}` to
    every generated kernel line). Regenerated on every `update-grub`.
- No SMBIOS set -> `${dm_smbios_extra}` empty -> no-op (normal boot unaffected).

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
