#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## style-ok: R-003  ## 3-space indent, matching the dm-image-build subject + the sibling *_test.sh

## Regression for dm-image-build's source-freshness guard, --ref sync and dpkg-audit surfacing --
## the guards that stop a SILENT stale build (an OLD commit that greens yet tested nothing) and
## surface a wedged host dpkg state UP FRONT:
##   - checkout BEHIND its org-ai-assisted upstream tip, default -> REFUSE (exit 2), naming the
##     behind-count, the exact `git reset --hard 'org-ai-assisted/<branch>'`, --ref and --allow-stale
##   - behind + --allow-stale                -> WARN and proceed (exit 0 under --check-only)
##   - --ref <commit>                        -> fetch + reset --hard lands the intended commit
##   - up-to-date checkout, default          -> exit 0, no false "BEHIND" refusal
##   - detached HEAD                         -> WARN and proceed (cannot check != stale)
##   - dpkg --audit non-empty                -> prominent WARNING carrying the audit output
##   - dpkg --audit empty                    -> no warning
## Drives the REAL dm-image-build binary against a throwaway git repo whose org-ai-assisted remote
## is a local bare upstream (no network), via --check-only (runs the guards + audit, then exits
## WITHOUT building). sudo + dpkg are PATH shims; git is REAL, so the guard's own git plumbing is
## exercised, not reimplemented.
## CANARY: pre-change dm-image-build has no --check-only/--ref/--allow-stale and no guard, so every
## invocation errors as an unknown argument (exit 2) -- the --allow-stale/--ref/audit/fresh/detached
## "exit 0" assertions FAIL on the old code, and the behind case passes only by accident (exit 2 for
## the wrong reason, with none of the message strings present, so those sub-asserts FAIL).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## Deterministic commit identity for the throwaway repos (no dependence on global git config).
export GIT_AUTHOR_NAME=dm-image-build-tests GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=dm-image-build-tests GIT_COMMITTER_EMAIL=test@example.invalid

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

subject=""
for candidate in "${DM_IMAGE_BUILD:-}" \
   "${test_dir}/../../bin/dm-image-build" \
   "/usr/bin/dm-image-build"; do
   [ -n "${candidate}" ] || continue
   if [ -x "${candidate}" ]; then
      subject="$(readlink --canonicalize -- "${candidate}")"
      break
   fi
done
[ -n "${subject}" ] || { printf '%s\n' "FATAL: dm-image-build not found (set DM_IMAGE_BUILD)." >&2; exit 1; }

work="$(mktemp --directory)"
# shellcheck disable=SC2317  ## runs via the EXIT trap
cleanup() { safe-rm --recursive --force -- "${work}"; }
trap cleanup EXIT

## PATH shims: sudo is a no-op that, when SUDO_CALLS is exported, records its args there (so a test
## can assert the cascade's `sudo ... --configure -a` did NOT fire under --check-only); dpkg answers
## --print-architecture and emits an --audit report from a fixture file (empty when the fixture is
## unset). git is deliberately NOT shimmed -- the guard runs real git.
shimbin="${work}/bin"
mkdir -p -- "${shimbin}"
cat > "${shimbin}/sudo" <<'SUDO_STUB'
#!/bin/bash
[ -z "${SUDO_CALLS:-}" ] || printf '%s\n' "$*" >> "${SUDO_CALLS}"
exit 0
SUDO_STUB
cat > "${shimbin}/dpkg" <<'DPKG_STUB'
#!/bin/bash
case "${1:-}" in
   --print-architecture)
      printf '%s\n' amd64
      ;;
   --audit)
      if [ -n "${STUB_DPKG_AUDIT:-}" ] && [ -r "${STUB_DPKG_AUDIT}" ]; then
         cat -- "${STUB_DPKG_AUDIT}"
      fi
      ;;
esac
exit 0
DPKG_STUB
chmod +x -- "${shimbin}/sudo" "${shimbin}/dpkg"

errf="${work}/stderr"
auditfix="${work}/audit.txt"

## make_repo N behind|fresh: build upstream bare (branch 'ai', 2 commits) + a checkout whose
## org-ai-assisted remote is that bare. 'behind' resets the checkout to the PARENT (1 commit behind
## the tip); 'fresh' leaves it at the tip. Sets REPO, SHA_TIP, SHA_OLD.
make_repo() {
   local n="$1" state="$2" up seed co
   up="${work}/up-${n}.git"
   seed="${work}/seed-${n}"
   co="${work}/co-${n}"
   git init --quiet --bare --initial-branch=ai "${up}"
   git init --quiet --initial-branch=ai "${seed}"
   (
      cd -- "${seed}"
      printf '%s' a > f; git add f; git commit --quiet -m c1
      printf '%s' b > f; git add f; git commit --quiet -m c2
      git remote add origin "${up}"; git push --quiet origin ai
   )
   SHA_TIP="$(git -C "${seed}" rev-parse HEAD)"
   SHA_OLD="$(git -C "${seed}" rev-parse 'HEAD~1')"
   git clone --quiet --origin org-ai-assisted "${up}" "${co}"
   if [ "${state}" = "behind" ]; then
      git -C "${co}" reset --hard --quiet "${SHA_OLD}"
   fi
   REPO="${co}"
}

## run_subject ARGS...: run the REAL dm-image-build --check-only on REPO with the PATH shims; sets
## RC and captures stderr to ${errf}. STUB_DPKG_AUDIT (if exported by the caller) reaches the dpkg
## shim through the inherited environment.
run_subject() {
   RC=0
   true > "${errf}"
   PATH="${shimbin}:${PATH}" "${subject}" --dir "${REPO}" --check-only "$@" >/dev/null 2>"${errf}" || RC=$?
}

pass=0
fail=0
check() { if [ "$2" -eq 0 ]; then pass=$(( pass + 1 )); printf '%s\n' "PASS: $1"; else fail=$(( fail + 1 )); printf '%s\n' "FAIL: $1"; fi; }

## --- behind, default: REFUSE (exit 2) naming the remedy ---------------------------------------
make_repo 1 behind
run_subject
rc=0; [ "${RC}" -eq 2 ] || rc=1
check 'behind checkout, default -> refuse with exit 2' "${rc}"
rc=0; grep --quiet 'BEHIND' "${errf}" || rc=1
check 'refusal names the behind drift' "${rc}"
rc=0; grep --quiet -- "git reset --hard 'org-ai-assisted/ai'" "${errf}" || rc=1
check 'refusal prints the exact reset --hard command (branch quoted)' "${rc}"
rc=0; grep --quiet -- '--ref' "${errf}" || rc=1
check 'refusal mentions --ref' "${rc}"
rc=0; grep --quiet -- '--allow-stale' "${errf}" || rc=1
check 'refusal mentions --allow-stale' "${rc}"

## --- behind + --allow-stale: WARN and proceed past the guard -----------------------------------
make_repo 2 behind
run_subject --allow-stale
rc=0; [ "${RC}" -eq 0 ] || rc=1
check 'behind + --allow-stale -> proceeds (exit 0 under --check-only)' "${rc}"
rc=0; grep --quiet 'STALE' "${errf}" || rc=1
check 'behind + --allow-stale -> warns about the STALE tree' "${rc}"

## --- --ref: fetch + reset --hard lands the intended commit -------------------------------------
make_repo 3 behind
run_subject --ref "${SHA_TIP}"
rc=0; [ "${RC}" -eq 0 ] || rc=1
check '--ref -> exit 0 (proceeds, guard skipped)' "${rc}"
rc=0; [ "$(git -C "${REPO}" rev-parse HEAD)" = "${SHA_TIP}" ] || rc=1
check '--ref fetch+reset lands the intended commit' "${rc}"

## --- up-to-date checkout, default: no false "BEHIND" refusal -----------------------------------
make_repo 4 fresh
run_subject
rc=0; [ "${RC}" -eq 0 ] || rc=1
check 'up-to-date checkout, default -> exit 0 (no false stale refusal)' "${rc}"
rc=0; if grep --quiet 'BEHIND' "${errf}"; then rc=1; fi
check 'up-to-date checkout -> no BEHIND error' "${rc}"

## --- dpkg --audit non-empty: prominent WARNING carrying the audit output -----------------------
make_repo 5 fresh
printf '%s\n' 'The following packages are in a mess due to serious problems:' ' grub-efi-amd64' > "${auditfix}"
export STUB_DPKG_AUDIT="${auditfix}"
run_subject
unset STUB_DPKG_AUDIT
rc=0; [ "${RC}" -eq 0 ] || rc=1
check 'dpkg audit non-empty -> still exit 0 (surfaced, not fatal)' "${rc}"
rc=0; grep --quiet 'half-configured' "${errf}" || rc=1
check 'dpkg audit non-empty -> prominent WARNING printed' "${rc}"
rc=0; grep --quiet 'grub-efi-amd64' "${errf}" || rc=1
check 'dpkg audit output surfaced verbatim' "${rc}"

## --- dpkg --audit empty: no warning (no false positive) ---------------------------------------
make_repo 6 fresh
run_subject
rc=0; if grep --quiet 'half-configured' "${errf}"; then rc=1; fi
check 'clean dpkg audit -> no half-configured warning' "${rc}"

## --- detached HEAD: cannot check, WARN and proceed (not a hard fail) ---------------------------
make_repo 7 behind
git -C "${REPO}" checkout --quiet --detach HEAD
run_subject
rc=0; [ "${RC}" -eq 0 ] || rc=1
check 'detached HEAD -> proceeds (exit 0), not a hard fail' "${rc}"
rc=0; grep --quiet -i 'detached' "${errf}" || rc=1
check 'detached HEAD -> warning explaining the check was skipped' "${rc}"

## --- enum validation: --freshness / --freedom reject a non-enum value at PARSE time, so
## --check-only cannot report "args validated" for a bogus value --------------------------------
make_repo 8 fresh
run_subject --freshness bogus
rc=0; [ "${RC}" -eq 2 ] || rc=1
check '--freshness bogus -> exit 2 (not a false --check-only "validated")' "${rc}"
rc=0; grep --quiet -- 'freshness must be frozen or current' "${errf}" || rc=1
check '--freshness bogus -> error names the valid values' "${rc}"
run_subject --freedom maybe
rc=0; [ "${RC}" -eq 2 ] || rc=1
check '--freedom maybe -> exit 2 (enum validated)' "${rc}"
rc=0; grep --quiet -- 'freedom must be true or false' "${errf}" || rc=1
check '--freedom maybe -> error names the valid values' "${rc}"
run_subject --freshness frozen --freedom true
rc=0; [ "${RC}" -eq 0 ] || rc=1
check 'valid --freshness/--freedom enums -> exit 0 (accepted)' "${rc}"

## --- parent core.autocrlf forced OFF before the --ref reset (no CRLF smudge) ----------------------
## With core.autocrlf=true the reset's checkout smudges LF->CRLF in the working tree, which
## git_sanity_test (and derivative-update) then see as "modified" -> exit 3. The fix forces
## autocrlf=false BEFORE the reset, so the checkout keeps LF. CANARY: old code (reset first, then
## autocrlf in the post-check-only cascade) writes CR into the working file, failing the no-CR assert.
acr_up="${work}/up-acr.git"
acr_seed="${work}/seed-acr"
acr_co="${work}/co-acr"
git init --quiet --bare --initial-branch=ai "${acr_up}"
git init --quiet --initial-branch=ai "${acr_seed}"
(
   cd -- "${acr_seed}"
   printf '%s\n' line1 line2 line3 > textfile; git add textfile; git commit --quiet -m c1
   printf '%s\n' line1 line2 line3 line4 > textfile; git add textfile; git commit --quiet -m c2
   git remote add origin "${acr_up}"; git push --quiet origin ai
)
acr_tip="$(git -C "${acr_seed}" rev-parse HEAD)"
git clone --quiet --origin org-ai-assisted "${acr_up}" "${acr_co}"
git -C "${acr_co}" reset --hard --quiet "$(git -C "${acr_seed}" rev-parse 'HEAD~1')"
git -C "${acr_co}" config core.autocrlf true
REPO="${acr_co}"
run_subject --ref "${acr_tip}"
rc=0; [ "${RC}" -eq 0 ] || rc=1
check 'autocrlf=true + --ref -> exit 0' "${rc}"
crlf_probe="$(od -An -c "${REPO}/textfile")"
rc=0; case "${crlf_probe}" in *'\r'*) rc=1 ;; esac
check 'autocrlf=true + --ref -> working tree keeps LF (autocrlf forced off before the reset)' "${rc}"

## --- --check-only is READ-ONLY: no repo config write, no root dpkg mutation ----------------------
## The parent core.autocrlf=false normalization is scoped to the re-checkout paths (--ref reset,
## build cascade) and `dpkg --configure -a` is gated to the build path, so --check-only mutates
## NOTHING. CANARY: old code wrote core.autocrlf=false AND ran sudo dpkg --configure -a before the
## check-only exit -- the config flip is the single root cause of the worktree-smudge symptom too.
roc_up="${work}/up-roc.git"
roc_seed="${work}/seed-roc"
roc_co="${work}/co-roc"
git init --quiet --bare --initial-branch=ai "${roc_up}"
git init --quiet --initial-branch=ai "${roc_seed}"
(
   cd -- "${roc_seed}"
   printf '%s\n' alpha bravo charlie > textfile; git add textfile; git commit --quiet -m c1
   git remote add origin "${roc_up}"; git push --quiet origin ai
)
## Fresh checkout (at the upstream tip) so the freshness guard passes and --check-only reaches its
## exit; a known core.autocrlf makes a stray config write detectable.
git clone --quiet --origin org-ai-assisted "${roc_up}" "${roc_co}"
git -C "${roc_co}" config core.autocrlf true
REPO="${roc_co}"
export SUDO_CALLS="${work}/sudo-calls.log"; touch -- "${SUDO_CALLS}"
run_subject
unset SUDO_CALLS
rc=0; [ "${RC}" -eq 0 ] || rc=1
check '--check-only (no --ref, fresh) -> exit 0' "${rc}"
rc=0; [ "$(git -C "${REPO}" config --local core.autocrlf)" = "true" ] || rc=1
check '--check-only leaves core.autocrlf UNCHANGED (read-only; no config write)' "${rc}"
rc=0; if grep --quiet -- '--configure' "${work}/sudo-calls.log"; then rc=1; fi
check '--check-only does NOT run sudo dpkg --configure (mutation gated to build path)' "${rc}"

printf '%s\n' "" "$(basename -- "$0"): ${pass} pass, ${fail} fail"
[ "${fail}" -eq 0 ] || exit 1
exit 0
