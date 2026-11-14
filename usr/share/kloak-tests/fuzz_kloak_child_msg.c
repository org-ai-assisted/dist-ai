/*
 * Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
 * See the file COPYING for copying conditions.
 *
 * AI-Assisted
 *
 * libFuzzer harness for the PARENT's decode of messages from the sandboxed,
 * explicitly-UNTRUSTED child: process_child_message() (src/kloak.c.in) and the
 * CTP ring parser it drives (get_msg_from_peer / pop_ring_buffer_msg, KLOAK
 * variant in src/kloak-shared.h). kloak-shared.h states the child "is NOT
 * trusted by the parent", so this is a named untrusted surface -- yet only the
 * CHILD side (PTC decode) was fuzzed; the parent side had no harness at all.
 *
 * Drives the REAL code device-less, like fuzz_kloakwl_input_sequence.c in the
 * opposite direction: a pipe into recv_read_fd, the real get_msg_from_peer +
 * process_child_message. Maintained HERE in dist-ai (not vendored); the
 * kloak-tests-fuzz runner stages it into kloak's build tree's fuzz/ dir so
 * ci/cfuzz-build.sh compiles it with the kloak.c.in harnesses (KLOAK build),
 * hence the "../src/kloak.c" include.
 *
 * Two fatal paths in process_child_message are INTERCEPTED (redefined to longjmp
 * before including kloak.c, as fuzz_parse_esc_key_str.c does): WAYLAND_LOST
 * exits 0, and a valid-but-unexpected type at that point (INIT_ACK) errx(1)s --
 * both are correct handling of child input, not crashes, so they unwind back
 * here. Only the THREE types the parser accepts are sent: an unknown/NONE type
 * on the wire trips the parser's by-design assert(false) (hostile-input WONTFIX
 * class), and POINTER_SPACE_DATA coordinates are kept >= 0, mirroring the
 * serializer's own assert (kloak-shared.h:687/759) -- so only genuine UB/OOB in
 * the accepted decode is a finding.
 */

#define _GNU_SOURCE

#include <assert.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

/* Intercept kloak's fatal exits so the child-input rejection paths unwind here
 * instead of ending the fuzzer run. Defined after the real <stdlib.h>/<err.h>
 * declarations and before kloak.c, so only kloak.c's CALLS expand. */
static jmp_buf g_reject;
#define exit(code) longjmp(g_reject, 1)
#define err(code, ...) longjmp(g_reject, 1)
#define errx(code, ...) longjmp(g_reject, 1)

#ifndef KLOAK_FUZZING
#define KLOAK_FUZZING
#endif
#include "../src/kloak.c"

static int fuzz_pipe[2] = { -1, -1 };
static bool fuzz_ready = false;

static void fuzz_setup_once(void) {
  if (fuzz_ready) {
    return;
  }
  init_fd_urandom();
  init_msg_ring();
  if (pipe(fuzz_pipe) != 0) {
    _exit(1);
  }
  recv_read_fd = fuzz_pipe[0];
  fuzz_ready = true;
}

/* Build a CTP frame exactly as the child's send_msg_to_peer writes it
 * (kloak-shared.h:669-696): [enum ctp_packet_type], and for POINTER_SPACE_DATA
 * two int32 coordinates. coord == NULL builds a payload-less frame. Returns the
 * length. A drift in this layout vs the parser fails the fuzzer loudly. */
static size_t build_ctp_frame(unsigned char *buf, enum ctp_packet_type type,
    const int32_t *coord) {
  size_t pos = 0;
  memcpy(buf + pos, &type, sizeof(type));
  pos += sizeof(type);
  if (coord != NULL) {
    memcpy(buf + pos, &coord[0], sizeof(int32_t));
    pos += sizeof(int32_t);
    memcpy(buf + pos, &coord[1], sizeof(int32_t));
    pos += sizeof(int32_t);
  }
  return pos;
}

static void pipe_write(int fd, const unsigned char *buf, size_t len) {
  if (len > 0 && write(fd, buf, len) != (ssize_t)(len)) {
    _exit(1);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  size_t off = 0;

  fuzz_setup_once();

  /* Each step: 1 selector byte picks one of the THREE child->parent packet
   * types the parser accepts. An unknown/NONE type on the wire trips the
   * parser's by-design `assert(false)` (hostile-input WONTFIX class), so the
   * fuzzer stays in-envelope and only genuine UB/OOB in the accepted decode is
   * a finding. POINTER_SPACE_DATA pulls two non-negative int32 coordinates
   * (mirroring the serializer's own >= 0 assert). */
  while (off < size) {
    uint8_t selector = data[off++];
    enum ctp_packet_type type = CTP_PACKET_INIT_ACK;
    const int32_t *coord_arg = NULL;
    int32_t coord[2] = { 0, 0 };
    unsigned char frame[sizeof(enum ctp_packet_type) + sizeof(int32_t) * 2];
    size_t frame_len = 0;
    bool split = ((selector >> 2) & 1u) != 0u;

    switch (selector % 3u) {
    case 0:
      type = CTP_PACKET_INIT_ACK;
      break;
    case 1:
      type = CTP_PACKET_WAYLAND_LOST;
      break;
    default: /* case 2 */
      type = CTP_PACKET_POINTER_SPACE_DATA;
      if (off + sizeof(int32_t) * 2 > size) {
        return 0;
      }
      memcpy(&coord[0], data + off, sizeof(int32_t));
      off += sizeof(int32_t);
      memcpy(&coord[1], data + off, sizeof(int32_t));
      off += sizeof(int32_t);
      coord[0] &= 0x7fffffff;
      coord[1] &= 0x7fffffff;
      coord_arg = coord;
      break;
    }

    frame_len = build_ctp_frame(frame, type, coord_arg);
    if (split && frame_len > sizeof(enum ctp_packet_type)) {
      /* Write the type first, pop (the parser must return NULL on the
       * incomplete payload -- the short-payload branch, kloak-shared.h:735/751),
       * then the payload, and pop again to complete. */
      pipe_write(fuzz_pipe[1], frame, sizeof(enum ctp_packet_type));
      if (setjmp(g_reject) == 0) {
        process_child_message();
      }
      pipe_write(fuzz_pipe[1], frame + sizeof(enum ctp_packet_type),
        frame_len - sizeof(enum ctp_packet_type));
      if (setjmp(g_reject) == 0) {
        process_child_message();
      }
    } else {
      pipe_write(fuzz_pipe[1], frame, frame_len);
      if (setjmp(g_reject) == 0) {
        process_child_message();
      }
    }

    /* Decode-correctness oracle (not just crash-freedom): a POINTER_SPACE_DATA
     * frame must have decoded into pointer_space_data exactly (kloak.c.in:836).
     * A broken/dropped decode makes the fuzzer fire here. */
    if (type == CTP_PACKET_POINTER_SPACE_DATA) {
      assert(pointer_space_data.x == coord[0]
        && pointer_space_data.y == coord[1]);
    }
  }

  return 0;
}
