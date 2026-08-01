#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Regression test for legacy-dist 'debian/legacy-dist.preinst': the
## keyboard-configuration model it preseeds.
##
## THE BUG IT GUARDS: the preinst preseeded the model description
## "Generic 105-key PC (intl.)". No such model exists -- it is in neither
## xkb rules file -- so debconf discarded the answer and the package fell back to
## prompting or to a default, silently, on every install. A preseed for a
## nonexistent choice fails exactly like no preseed at all, which is why it went
## unnoticed.
##
## Validated against the AUTHORITATIVE list rather than a hardcoded string: the
## model description and the modelcode preseeded by the preinst must be a
## matching pair in /usr/share/X11/xkb/rules/*.lst, which is where
## keyboard-configuration's Choices come from.
##
## Needs no root, no network, no build.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

test_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./help_steps_test_lib.bsh
source "${test_dir}/help_steps_test_lib.bsh"

preinst=""
locate_subject() {
   local candidate

   for candidate in "${LEGACY_DIST_PREINST:-}" \
      "${LEGACY_DIST_DIR:-}/debian/legacy-dist.preinst" \
      "${DERIVATIVE_MAKER_DIR:-}/packages/kicksecure/legacy-dist/debian/legacy-dist.preinst" \
      "${HOME}/derivative-maker/packages/kicksecure/legacy-dist/debian/legacy-dist.preinst"; do
      [ -n "${candidate}" ] || continue
      if [ -r "${candidate}" ]; then
         preinst="${candidate}"
         return 0
      fi
   done
   return 1
}

if ! locate_subject; then
   printf '%s\n' "SKIP: legacy-dist.preinst not found (set LEGACY_DIST_PREINST)." >&2
   exit 77
fi

xkb_rules=""
for candidate in /usr/share/X11/xkb/rules/base.lst /usr/share/X11/xkb/rules/evdev.lst; do
   if [ -r "${candidate}" ]; then
      xkb_rules="${candidate}"
      break
   fi
done
if [ -z "${xkb_rules}" ]; then
   printf '%s\n' "SKIP: no /usr/share/X11/xkb/rules/*.lst here; cannot validate the model against the real list (install xkb-data)." >&2
   exit 77
fi

## The '! Model' section only; the same tokens appear under layouts and options.
model_list="$(sed -n '/^! model/,/^!/p' -- "${xkb_rules}")"
if [ -z "${model_list}" ]; then
   printf '%s\n' "FAILED: could not read the model section of ${xkb_rules}." >&2
   exit 1
fi

## CANARY: the lookup below must be able to MISS. If the rules file matched
## anything, every assertion here would pass regardless of what is preseeded.
case "${model_list}" in
   *"Generic 105-key PC (intl.)"*)
      fail "canary broken: '(intl.)' IS in ${xkb_rules}, so this test cannot detect the bug it exists for"
      ;;
   *)
      pass "canary: 'Generic 105-key PC (intl.)' is absent from ${xkb_rules}, as a nonexistent model should be"
      ;;
esac

## The preseed line is 'name<TAB>template<TAB>type<TAB>value' inside a quoted
## argument, so the value runs to the closing quote -- not to end of line, which
## carries '| debconf-set-selections'.
extract_preseed() {
   local template="$1"

   sed -n "s|.*keyboard-configuration/${template}[[:space:]][[:space:]]*[a-z][a-z]*[[:space:]][[:space:]]*\\([^\"]*\\)\".*|\\1|p" \
      -- "${preinst}" | head -1
}

model_description="$(extract_preseed model)"
model_code="$(extract_preseed modelcode)"

## Hard stop, not a 'fail' that falls through: every assertion below compares
## against these, and an empty value matches everything, so continuing would
## turn the rest of this file into vacuous passes.
if [ -z "${model_description}" ] || [ -z "${model_code}" ]; then
   fail "preinst preseeds no keyboard-configuration/model (got '${model_description}') or modelcode (got '${model_code}')"
   printf '%s\n' "FAILED: ${test_failures} assertion(s); refusing to compare against an empty value." >&2
   exit 1
fi
pass "preinst preseeds model '${model_description}' and modelcode '${model_code}'"

## The description must be a real choice, or debconf discards the answer.
case "${model_list}" in
   *"${model_description}"*)
      pass "preseeded model '${model_description}' exists in ${xkb_rules}"
      ;;
   *)
      fail "preseeded model '${model_description}' is not in ${xkb_rules}; debconf will discard the preseed"
      ;;
esac

## description and code must be the SAME row, not two valid values that disagree.
matched_row="$(printf '%s\n' "${model_list}" \
   | grep -E "^[[:space:]]*${model_code}[[:space:]]+" || true)"
if [ -z "${matched_row}" ]; then
   fail "modelcode '${model_code}' is not a model in ${xkb_rules}"
else
   case "${matched_row}" in
      *"${model_description}"*)
         pass "modelcode '${model_code}' and model '${model_description}' are the same row"
         ;;
      *)
         fail "modelcode '${model_code}' names '${matched_row##*[[:space:]][[:space:]]}', not '${model_description}'"
         ;;
   esac
fi

if [ "${test_failures}" -ne 0 ]; then
   printf '%s\n' "FAILED: ${test_failures} assertion(s)." >&2
   exit 1
fi
printf '%s\n' "OK: keyboard preseed model."
