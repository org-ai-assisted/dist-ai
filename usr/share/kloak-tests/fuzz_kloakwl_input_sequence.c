/*
SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted

libFuzzer harness for kloak's INPUT-EVENT SEQUENCE processing in the sandboxed
Wayland adapter (src/kloakwl.c): the child's process_parent_message and the
cursor/scroll state machine it drives (update_virtual_cursor's off-screen glide
via make_virtual_cursor_pos_sane/traverse_line, update_mouse_scroll's
accumulation, and the coordinate-space transforms). These are the paths a stream
of mouse-move / mouse-click / scroll / key events flows through, and the audit
flagged them as the untested sequence surface (kloakwl.c had no fuzz coverage).

Drives the REAL code device-less, exactly as kloakwl_harness.c's
unit_release_jitter_mouse does (KLOAK_FUZZING seam, a pipe into recv_read_fd, the
real get_msg_from_peer + process_parent_message), so no compositor is needed. The
delayed RELEASE path (release_scheduled_input_events) is NOT driven: it emits over
a live wl_proxy, so the queue is drained instead -- the arithmetic/state crash
surface for an event SEQUENCE is the ingestion path here.

Frames are fed in fuzzer-controlled SHAPES, not one-whole-frame-per-read: a frame
may be split across several writes (so get_msg_from_peer sees a partial frame and
pop_ring_buffer_msg must return NULL and resume), and several frames may be
batched into the pipe before being popped one at a time. This exercises the ring
reassembly / continuity logic (short-payload NULL branches, multi-frame reads,
and the magic-ring wrap) that a one-frame-per-call harness never reaches.

Payloads are kept in the realistic envelope the parent actually sends (finite,
integer-valued coordinates; positive screen geometry) so the fuzzer explores
event ORDERINGS and accumulation, not kloak's by-design defensive asserts on
out-of-envelope compositor input (the hostile-compositor WONTFIX class). Built by
ci/cfuzz-build.sh with ASan + UBSan (minus signed-overflow, which production traps
and the fuzzer defines via -fwrapv), so it surfaces real memory-safety bugs.
*/
#define KLOAK_FUZZING
#include "../src/kloakwl.c"

#include <stdint.h>
#include <string.h>
#include <unistd.h>

/* A built PTC wire frame, mirroring send_msg_to_peer (which is compiled out of
 * this KLOAKWL TU): button events are [type][uint32 code][uint8 pressed]; cursor
 * and scroll events are [type][double x][double y]. The real get_msg_from_peer
 * must parse these back, so a drift in the layout fails the fuzzer loudly. */
#define FRAME_CAP (sizeof(enum ptc_packet_type) + sizeof(double) * 2)

static size_t build_button_frame(unsigned char *buf, enum ptc_packet_type type,
    uint32_t button_code, uint8_t pressed) {
  size_t pos = 0;
  memcpy(buf + pos, &type, sizeof(type));
  pos += sizeof(type);
  memcpy(buf + pos, &button_code, sizeof(button_code));
  pos += sizeof(button_code);
  memcpy(buf + pos, &pressed, sizeof(pressed));
  pos += sizeof(pressed);
  return pos;
}

static size_t build_coord_frame(unsigned char *buf, enum ptc_packet_type type,
    double x, double y) {
  size_t pos = 0;
  memcpy(buf + pos, &type, sizeof(type));
  pos += sizeof(type);
  memcpy(buf + pos, &x, sizeof(x));
  pos += sizeof(x);
  memcpy(buf + pos, &y, sizeof(y));
  pos += sizeof(y);
  return pos;
}

/* Two horizontally adjacent 1920x1080 screens: a valid global space whose shared
 * edge exercises make_virtual_cursor_pos_sane's cross-screen glide and the
 * off-screen-into-the-void handling. */
static struct output_geometry fuzz_geom0 = { .x = 0, .y = 0,
  .width = 1920, .height = 1080 };
static struct output_geometry fuzz_geom1 = { .x = 1920, .y = 0,
  .width = 1920, .height = 1080 };
static int fuzz_pipe[2] = { -1, -1 };
static bool fuzz_ready = false;

static void fuzz_setup_once(void) {
  ssize_t i = 0;
  if (fuzz_ready) {
    return;
  }
  init_fd_urandom();
  init_msg_ring();
  if (pipe(fuzz_pipe) != 0) {
    _exit(1);
  }
  recv_read_fd = fuzz_pipe[0];
  max_delay = 1000;
  TAILQ_INIT(&evq_head);
  should_draw_cursor = false;
  for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
    state.output_geometries[i] = NULL;
  }
  state.output_geometries[0] = &fuzz_geom0;
  state.output_geometries[1] = &fuzz_geom1;
  if (!recalc_global_space()) {
    _exit(1);
  }
  fuzz_ready = true;
}

/* Free whatever process_parent_message queued, so the event queue does not grow
 * across the millions of fuzzer iterations (the real release path would drain it
 * over a wl_proxy, which is absent here). */
static void drain_queue(void) {
  struct input_packet *pkt = NULL;
  while ((pkt = TAILQ_FIRST(&evq_head)) != NULL) {
    TAILQ_REMOVE(&evq_head, pkt, evq_entries);
    free(pkt);
  }
}

static void pipe_write(const unsigned char *buf, size_t len) {
  if (len > 0 && write(fuzz_pipe[1], buf, len) != (ssize_t)(len)) {
    _exit(1);
  }
}

/* Feed a built frame to the pipe in `chunks` writes, popping after each write.
 * A write that leaves the frame incomplete makes get_msg_from_peer see a partial
 * frame (pop returns NULL, nothing queued); the completing write then yields the
 * event -- the short-payload / cross-read reassembly path. chunks == 1 is the
 * whole-frame-in-one-read case. */
static void feed_frame(const unsigned char *buf, size_t len, unsigned chunks) {
  size_t off = 0;
  unsigned c = 0;
  if (chunks < 1u) {
    chunks = 1u;
  }
  for (c = 0; c < chunks; c++) {
    size_t remaining = len - off;
    size_t left_chunks = chunks - c;
    size_t take = (c + 1u == chunks) ? remaining : (remaining / left_chunks);
    pipe_write(buf + off, take);
    off += take;
    if (process_parent_message()) {
      drain_queue();
    }
  }
  /* Any trailing bytes (when len did not divide evenly) plus a final pop. */
  if (off < len) {
    pipe_write(buf + off, len - off);
  }
  while (process_parent_message()) {
    drain_queue();
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  size_t off = 0;

  fuzz_setup_once();

  /* Fresh cursor + scheduler state per run so one input's sequence does not
   * leak into the next. */
  cursor_x = 0.0;
  cursor_y = 0.0;
  prev_cursor_x = 0.0;
  prev_cursor_y = 0.0;
  prev_release_time = 0;
  vert_scroll_accum = 0.0;
  horiz_scroll_accum = 0.0;
  drain_queue();

  /* Each step: 1 selector byte picks the event type AND the feed shape. The
   * payload is pulled from the following bytes, kept finite and in the realistic
   * envelope. Stop when a whole step no longer fits. */
  while (off < size) {
    uint8_t selector = data[off++];
    unsigned char frame[FRAME_CAP];
    size_t frame_len = 0;
    /* High bits of the selector choose how the frame is fed: 1-3 chunks (split
     * frame -> partial-read reassembly) and whether to batch a second frame
     * into the pipe before popping (multi-frame-per-read). */
    unsigned chunks = ((selector >> 3) & 3u) + 1u;
    bool batch = ((selector >> 5) & 1u) != 0u;

    switch (selector % 5u) {
    case 0: /* relative pointer motion */
    case 1: /* absolute pointer motion */
    case 2: { /* scroll */
      int16_t raw_x = 0;
      int16_t raw_y = 0;
      enum ptc_packet_type type = PTC_PACKET_CURSOR_REL_EVENT;
      if (off + (sizeof(int16_t) * 2) > size) {
        return 0;
      }
      memcpy(&raw_x, data + off, sizeof(raw_x));
      off += sizeof(raw_x);
      memcpy(&raw_y, data + off, sizeof(raw_y));
      off += sizeof(raw_y);
      if ((selector % 5u) == 1u) {
        type = PTC_PACKET_CURSOR_ABS_EVENT;
      } else if ((selector % 5u) == 2u) {
        type = PTC_PACKET_SCROLL_EVENT;
      }
      /* int16 -> double: always finite, integer-valued, and small enough that
       * repeated relative accumulation stays well inside the isfinite/INT32
       * asserts over any realistic input length. */
      frame_len = build_coord_frame(frame, type, (double)(raw_x),
        (double)(raw_y));
      break;
    }
    case 3: /* mouse click */
    case 4: { /* keyboard key */
      uint32_t code = 0;
      uint8_t pressed = 0;
      enum ptc_packet_type type = (selector % 5u) == 3u
        ? PTC_PACKET_CLICK_EVENT : PTC_PACKET_KB_EVENT;
      if (off + sizeof(uint32_t) + sizeof(uint8_t) > size) {
        return 0;
      }
      memcpy(&code, data + off, sizeof(code));
      off += sizeof(code);
      pressed = data[off++] & 1u;
      frame_len = build_button_frame(frame, type, code, pressed);
      break;
    }
    default:
      break;
    }

    if (frame_len == 0) {
      continue;
    }
    if (batch) {
      /* Two identical frames written back-to-back, then popped one at a time:
       * get_msg_from_peer reads both in one go and pop_ring_buffer_msg must
       * yield exactly two events across successive calls. */
      pipe_write(frame, frame_len);
      pipe_write(frame, frame_len);
      while (process_parent_message()) {
        drain_queue();
      }
    } else {
      feed_frame(frame, frame_len, chunks);
    }
  }

  return 0;
}
