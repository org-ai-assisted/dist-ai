#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Guards developer-meta-files' debian/control dependency classification.
## developer-meta-files is apt-installed on the dm BUILD HOST at
## build-steps.d/1400_local-dependencies (genmkfile deb-install), where the apt
## sources are frozen trixie only (no backports). 'debsbom' lives exclusively in
## trixie-backports/sid, so a hard 'Depends: debsbom' is unsatisfiable there and
## the whole dry-run/build aborts with "held broken packages". debsbom is needed
## only by dm-sbom-archive (a manual maintainer tool, not on the build path);
## images obtain it via the dist-general-cli metapackage. So debsbom must be a
## Recommends/Suggests, never a hard Depends. The realistic regression is a
## control-file sync re-promoting it to Depends.
##
## Structural only (parses the control file). No root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

if [ -n "${DERIVATIVE_MAKER_DIR:-}" ]; then
  dm_checkout="${DERIVATIVE_MAKER_DIR}"
else
  dm_checkout="${HOME}/derivative-maker"
fi

pass_count=0
pass() {
  pass_count=$(( pass_count + 1 ))
  printf '%s\n' "PASS: $*"
}
test_failures=0
fail() {
  test_failures=$((test_failures + 1))
  printf '%s\n' "FAIL: $*" >&2
}

rel='debian/control'
candidates=()
[ -z "${DEVELOPER_META_FILES_DIR:-}" ] || candidates+=( "${DEVELOPER_META_FILES_DIR}/${rel}" )
candidates+=( "${dm_checkout}/packages/kicksecure/developer-meta-files/${rel}" )
subject=""
for candidate in "${candidates[@]}"; do
  if [ -r "${candidate}" ]; then
    subject="${candidate}"
    break
  fi
done
## debian/control is a source artifact, not shipped to /usr; an installed-only run
## with no checkout genuinely has no subject.
if [ -z "${subject}" ]; then
  printf '%s\n' "SKIP: developer-meta-files debian/control not found (set DEVELOPER_META_FILES_DIR)." >&2
  ## style-ok: allow-skip: control file absent without a developer-meta-files checkout
  exit 77
fi

## Print a deb822 field's logical value across EVERY stanza, joining RFC822
## continuation lines. Values ACCUMULATE (not overwrite), so a hard Depends in a
## non-final binary 'Package:' stanza is still caught if the package ever grows a
## second binary. The Source stanza has Build-Depends, which '^Depends:' skips.
extract_field() {
  local field="$1"
  awk -v field="${field}" '
    BEGIN { infield = 0; val = "" }
    {
      if (infield) {
        if ($0 ~ /^[ \t]/) { line = $0; sub(/^[ \t]+/, "", line); val = val " " line; next }
        infield = 0
      }
      if ($0 ~ "^" field ":[ \t]*") { line = $0; sub("^" field ":[ \t]*", "", line); val = val " " line; infield = 1 }
    }
    END { print val }
  ' "${subject}"
}

## True if package NAME is a dependency token in the deb822 relationship field
## VALUE. Splits on ',' and '|' (alternatives), drops version '(...)' and ':arch'
## qualifiers. Pure bash word-splitting -- no pipe into a quiet grep (R-161).
field_has_dep() {
  local value="$1" name="$2" token
  value="${value//,/ }"
  value="${value//|/ }"
  for token in ${value}; do
    token="${token%%(*}"
    token="${token%%:*}"
    if [ "${token}" = "${name}" ]; then
      return 0
    fi
  done
  return 1
}

depends_val="$(extract_field Depends)"
recommends_val="$(extract_field Recommends)"
suggests_val="$(extract_field Suggests)"

if field_has_dep "${depends_val}" debsbom; then
  fail "debsbom is a hard Depends (unsatisfiable on the trixie-only build host at 1400_local-dependencies); move it to Recommends/Suggests"
else
  pass "debsbom is not a hard Depends"
fi

if field_has_dep "${recommends_val} ${suggests_val}" debsbom; then
  pass "debsbom is kept as Recommends/Suggests"
else
  fail "debsbom dropped entirely; dm-sbom-archive needs it -- keep it as Recommends/Suggests"
fi

printf '%s\n' "${pass_count} pass, ${test_failures} fail, 0 skip"
if [ "${test_failures}" -ne 0 ]; then
  exit 1
fi
exit 0
