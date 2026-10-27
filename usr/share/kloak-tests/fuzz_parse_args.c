/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for kloak's remaining untrusted command-line value parsers:
 * parse_uint31_arg / parse_uint32_arg (the --delay / --start-delay / --color
 * numeric arguments) and lookup_keycode (the key names in --escape-keys).
 * parse_esc_key_str has its own harness; together these cover the CLI
 * string->value surface.
 *
 * Unlike parse_esc_key_str these are return-based (no exit() on bad input) and
 * allocate nothing, so no exit interception or global reset is needed; a crash
 * under ASAN/UBSAN is the only finding.
 *
 * Maintained HERE in dist-ai (not vendored in the kloak submodule); the
 * kloak-tests-fuzz runner stages it into kloak's build tree's fuzz/ dir, hence
 * the "../src/kloak.c" include relative to that staged location.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef KLOAK_FUZZING
#define KLOAK_FUZZING
#endif
#include "../src/kloak.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *buf = NULL;
  int32_t v31 = 0;
  uint32_t v32 = 0;

  buf = malloc(size + 1U);
  if (buf == NULL) {
    return 0;
  }
  memcpy(buf, data, size);
  buf[size] = '\0';

  (void)parse_uint31_arg(buf, 10, &v31);
  (void)parse_uint31_arg(buf, 16, &v31);
  (void)parse_uint32_arg(buf, 10, &v32);
  (void)parse_uint32_arg(buf, 16, &v32);
  (void)lookup_keycode(buf);

  free(buf);
  return 0;
}
