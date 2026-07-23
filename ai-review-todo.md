# Pending AI reviews

## dm-image-boot-tests suite (codex: DONE + addressed; coderabbit: pending)
- codex (detached retry) returned 6 findings, all reconciled + fixed in the
  follow-up commit:
  - P1 aggregate-always-SKIPs -> removed from integration_suites (standalone-only,
    like iso-boot-tests); runs via the dedicated boot-test lane, not the aggregate.
  - qemu-utils added to Depends (dm-qemu needs qemu-img); arm64 qemu + UEFI as
    Recommends.
  - runner accepts --disk=/--iso= equals-form.
  - dm-image-test: single overall deadline across all phases (was per-phase; a
    short --timeout could still run ~10 min via the 60x probe).
  - dm-qemu reports the per-boot workdir for ALL --emit-argv paths (EFI OVMF_VARS
    too, not just direct-kernel); dm-image-test rmtree's it after qemu exits.
- coderabbit timed out with zero output on BOTH runs (large moved-files diff /
  sandbox load) -- NOT reviewed. Re-run coderabbit alone on a backoff:
  `ai-review HEAD~1 --with coderabbit` once the diff is just the fix commit.
