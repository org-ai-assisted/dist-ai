#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Shared extraction for the virtualbox-host toolchain drift guards. SOURCED by
## virtualbox_host_toolchain_consistency_test.sh (offline) and
## virtualbox_recommends_coverage_test.sh (needs the Oracle apt index); not a test
## itself (no *_test.sh suffix). The callers set the strict shell options and
## 'set -o noglob' (these helpers rely on word-splitting unquoted token lists).
##
## NOT a bash parser: it matches the one known, simple toolchain lines in
## dist-installer-cli and FAILS loudly (return 1) if their shape changes, rather
## than parsing arbitrary shell.
## style-ok: no-strict -- sourced-only fragment; the callers set the strict-mode preamble

## Resolve the installer path from a usability-misc checkout.
vbox_installer_path() {
   local repo="${USABILITY_MISC_REPO:-}"
   if [ -z "${repo}" ]; then
      repo="${HOME}/derivative-maker/packages/kicksecure/usability-misc"
   fi
   printf '%s\n' "${repo}/usr/bin/dist-installer-cli"
}

## Resolve the kicksecure-meta-packages control from a derivative-maker checkout.
vbox_meta_control_path() {
   local dm="${DERIVATIVE_MAKER_DIR:-}"
   if [ -z "${dm}" ]; then
      dm="${HOME}/derivative-maker"
   fi
   printf '%s\n' "${dm}/packages/kicksecure/kicksecure-meta-packages/debian/control"
}

## Normalize a package-name list into a sorted space-delimited set. Folds any
## linux-headers-<arch>/<flavour> to the family token 'linux-headers' (the installer
## uses linux-headers-$(dpkg --print-architecture), the meta uses linux-headers-amd64,
## Oracle Recommends a long alternative chain -- all mean "the kernel headers meta").
## Drops linux-image* (a kernel image, not build toolchain) and substvars.
normalize_set() {
   local token out=""
   for token in $1; do
      case "${token}" in
         linux-headers*)
            token="linux-headers"
            ;;
         linux-image*)
            continue
            ;;
      esac
      out="${out} ${token}"
   done
   # shellcheck disable=SC2086
   printf '%s\n' ${out} | sort --unique | tr '\n' ' ' | tr --squeeze-repeats ' '
}

## Echo the installer's normalized VirtualBox-host build toolchain set. The oracle-repo
## workaround installs the compiler toolchain on ONE 'install_pkg gcc ... udev' line;
## the kernel headers meta via the linux_headers variable. Return 1 on a shape change.
vbox_installer_toolchain_set() {
   local installer="$1" lines count args
   lines="$(grep -E '^[[:space:]]*install_pkg gcc( |$)' -- "${installer}" || true)"
   count="$(printf '%s\n' "${lines}" | grep --count . || true)"
   if [ "${count}" != "1" ]; then
      printf '%s\n' "installer: expected exactly 1 'install_pkg gcc ...' toolchain line, found ${count} (shape changed -- update the guard)" >&2
      return 1
   fi
   args="${lines##*install_pkg }"
   if grep --quiet --extended-regexp 'linux_headers="linux-headers-\$\(dpkg --print-architecture\)"' -- "${installer}"; then
      args="${args} linux-headers-ARCH"
   else
      printf '%s\n' "installer: linux_headers assignment not found in expected form (shape changed -- update the guard)" >&2
      return 1
   fi
   normalize_set "${args}"
}

## Echo the virtualbox-host meta's normalized build toolchain set: its Depends minus the
## virtualbox-* host alternatives and substvars. Return 1 if the package is absent.
vbox_meta_toolchain_set() {
   local meta_control="$1" raw flat token keep=""
   raw="$(grep-dctrl --exact-match --field=Package virtualbox-host --show-field=Depends --no-field-names -- "${meta_control}" || true)"
   if [ -z "${raw}" ]; then
      printf '%s\n' "meta: virtualbox-host package or its Depends not found in ${meta_control}" >&2
      return 1
   fi
   flat="$(printf '%s' "${raw}" \
      | tr '\n' ' ' \
      | sed -e 's/,/ /g' -e 's/([^)]*)//g' -e 's/\[[^]]*\]//g' -e 's/|/ /g' -e 's/${[^}]*}//g')"
   for token in ${flat}; do
      case "${token}" in
         virtualbox-*)
            continue
            ;;
         *)
            keep="${keep} ${token}"
            ;;
      esac
   done
   normalize_set "${keep}"
}
