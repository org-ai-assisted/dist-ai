/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for kloak's parse_inotify_events() -- the untrusted
 * kernel-buffer walk that extracts device node names from inotify records.
 * arraybolt3 split it out of handle_inotify_events and deliberately made it
 * assert-free specifically so it can be fuzzed, so this drives it with
 * arbitrary bytes and lets ASAN/UBSAN find any over-read or bad advance.
 *
 * Fidelity: production reads into a fixed INOTIFY_READ_BUF_LEN buffer and passes
 * the actual read length, so the name regexec can scan past the logical length
 * but stays inside that allocation. The harness mirrors that -- a full-size
 * zeroed buffer with the fuzz input copied into the front and buf_len bounded to
 * the input -- so a reported OOB is a real walk bug, not an artifact of a
 * tight malloc.
 *
 * Maintained HERE in dist-ai; the kloak-tests-fuzz runner stages it into kloak's
 * build tree's fuzz/ dir, hence the "../src/kloak.c" include.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef KLOAK_FUZZING
#define KLOAK_FUZZING
#endif
#include "../src/kloak.c"

static int reg_ready = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *buf = NULL;
  ssize_t buf_len = 0;
  ssize_t pos = 0;
  ssize_t prev = 0;
  bool do_attach = false;

  if (!reg_ready) {
    applayer_regex_init();
    reg_ready = 1;
  }

  if (size > (size_t)(INOTIFY_READ_BUF_LEN)) {
    size = (size_t)(INOTIFY_READ_BUF_LEN);
  }
  buf = calloc(1, (size_t)(INOTIFY_READ_BUF_LEN));
  if (buf == NULL) {
    return 0;
  }
  memcpy(buf, data, size);
  buf_len = (ssize_t)size;

  while (pos >= 0 && pos < buf_len) {
    prev = pos;
    (void)parse_inotify_events(buf, buf_len, &pos, &do_attach);
    if (pos <= prev) {
      break;
    }
  }

  free(buf);
  return 0;
}
