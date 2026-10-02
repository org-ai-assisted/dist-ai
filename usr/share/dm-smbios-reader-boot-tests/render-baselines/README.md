# Render baselines

Committed reference screenshots for tolerant render verification (`dm-smbios-reader-vbox verify`
+ `test_dm_render_verify.py`). Each captures a known-good page so a gate run can
assert the guest rendered approximately right (not black / garbled / wrong theme)
and, with `--expect`, that the expected text is present.

## Layout

`<image>-<resolution>/<checkpoint>.png` -- baselines are PER RESOLUTION on purpose:
the comparison resize-normalises geometry but the installer relayouts per screen
size, so a 1280x800 (BIOS/live) baseline is not interchangeable with a 1920x1080
(EFI GOP) one. Capture and commit a set per resolution actually gated.

Present:
- `kicksecure-calamares-1280x800/` -- Calamares pages at the BIOS/live 1280x800 mode
  (`welcome`, `location`, `partitions`, `partitions-luks`).

To add: `kicksecure-calamares-1920x1080/` for the EFI/EFI+SB path (capture from an
`--firmware efi-secureboot` run).

## Matching

`dm-smbios-reader-vbox verify --shot S --baseline B [--tol 0.05] [--expect TEXT ...]` -- tolerant
mean per-channel pixel diff (0 = identical). The whole-screen diff is coarse (pages
sharing the sidebar + chrome differ only ~0.05-0.09), so `--expect` OCR text is the
content-level assertion; the pixel diff catches gross failures (black screen, broken
theme). Keep `--tol` near 0.05.

## Regenerating

Capture with `vbox-guestctl <vm> shot <out.png>` at the checkpoint, or wire capture
into the driver (dm-calamares-install) at each `wait_for`. Commit the PNG here.
Re-baseline deliberately when the installer's appearance legitimately changes.
