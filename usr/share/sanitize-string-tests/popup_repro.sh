#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Live graphical proof of the markup-injection bypass, end to end through the
## real production path: sanitize-string -> generic_gui_message (PyQt5
## QTextBrowser). Run it on a desktop (needs a display).
##
## The payload is a '<' followed by a space then a tag name. sanitize-string's
## Python html.parser does not treat it as a tag and passes it through, but the
## dialog's Qt parser revives it into a live, clickable <a href>. On a FIXED
## sanitize-string the residual '<' becomes '_' and the link is inert, proving
## the fix. Point SANITIZE_STRING_BIN at a fixed copy to see the difference.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

sanitize_string_bin="${SANITIZE_STRING_BIN:-/usr/bin/sanitize-string}"
gui_message='/usr/libexec/msgcollector/generic_gui_message'

## '<' + space + tag name: inert to sanitize-string, revived by Qt.
payload="< a href='http://example.com/injected'>CLICK ME (injected link)</a>"

sanitized="$("${sanitize_string_bin}" -- 128 "${payload}")"

## Same wrapper open-link-confirmation builds for its confirmation dialog.
msg="<p>The following <b>link</b> will be opened in <u>Tor Browser</u>.</p>
<p><code><blockquote>${sanitized}</blockquote></code></p>"

printf '%s\n' "payload:   ${payload}"
printf '%s\n' "sanitized: ${sanitized}"
printf '%s\n' "If the popup shows a CLICKABLE link, the sanitizer is vulnerable."
printf '%s\n' "If it shows literal '_ a href=...' text, the fix is in effect."

"${gui_message}" "warning" "Confirm Open" "${msg}" "Continue?" "yesno"
