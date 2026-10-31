#!/usr/bin/awk -f

# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# AI-Assisted

# Make an LXQt panel.conf REPRODUCIBLE for a story screenshot: freeze the
# worldclock to a token-free literal (the wall clock is the only tray element
# that changes run to run), and OPTIONALLY drop the lone `volume` plugin.
#
# The single source shared by the HOST capture-config seeder
# (dm-calamares-install gui_seed_capture_config) and the GUEST in-guest edit
# (gui_freeze_guest_clock), so the freeze logic cannot drift between them.
#
# Variables (awk -v):
#   fmt           the frozen clock text printed into customFormat (e.g. 00:00).
#   drop_volume   1 = also remove the standalone `volume` plugin (host desktop:
#                 headless, no audio device -> a false red "!" badge); 0/unset =
#                 leave the plugin list untouched (guest: keep its real tray).
#
# worldclock freeze: insert formatType=custom + customFormat=fmt +
# timeShowSeconds=false right after [worldclock], and drop any pre-existing
# copies of those three keys in the section so no duplicate survives.

# Drop the lone `volume` token by EXACT match (split on commas, trim, rebuild),
# so a 'volumeXXX' plugin is never prefix-mangled. Gated: skipped when
# drop_volume is 0/unset, so the line falls through to the verbatim print below.
/^plugins=/ && drop_volume {
   val = substr($0, index($0, "=") + 1)
   n = split(val, a, ",")
   out = ""
   for (i = 1; i <= n; i++) {
      t = a[i]
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", t)
      if (t == "volume") {
         continue
      }
      out = (out == "" ? t : out ", " t)
   }
   print "plugins=" out
   next
}

/^\[worldclock\]/ {
   print
   print "formatType=custom"
   print "customFormat=" fmt
   print "timeShowSeconds=false"
   inw = 1
   next
}

inw && /^\[/ {
   inw = 0
}

inw && /^(formatType|customFormat|timeShowSeconds)=/ {
   next
}

{
   print
}
