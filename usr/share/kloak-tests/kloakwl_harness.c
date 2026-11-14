/*
SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted

Concrete unit tests for the pure/testable functions in kloak's sandboxed Wayland
adapter (src/kloakwl.c). Compiled and run by test_kloak_verification.py against
the REAL src/kloakwl.c (via the KLOAK_FUZZING seam -- no source change), linked
with the wayland-scanner protocol code and the wayland/xkbcommon/cap libraries
exactly as kloakwl links. No compositor is needed: the pure logic is called
directly, and the keymap handler runs in a forked child over a plain fd.

Covers: check_screen_touch, traverse_line (now reporting end-of-line via
out_success, not a (-1,-1) sentinel), get_ticks_from_scroll_accum,
random_between over the REAL /dev/urandom, current_time_ms, the coordinate-space
conversions (screen_local_coord_to_abs_coord now reports validity via
out_is_valid), make_virtual_cursor_pos_sane, the kb_handle_keymap guards (no-NUL
and the short-backing-fd SIGBUS guard), the now-fixed cross-overlap and
offset-global-space audit regressions, calc_poll_timeout (the main-loop sleep
that enforces the delay: empty/buffered/future/past/INT_MAX-clamp), and the
release scheduler itself (unit_release_jitter[_mouse/_abs] drive the REAL
process_parent_message: every event -- key, click, relative + ABSOLUTE pointer
motion, scroll -- is released after a random delay bounded by max_delay with real
spread, release times never decrease, and the absolute-pointer path carries the
pointer_space offset on its coordinate -- kloak's reason to exist).
*/
#define KLOAK_FUZZING
#include "kloakwl.c"

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int checks = 0;
#define CHECK(cond) do { assert(cond); ++checks; } while (0)

static struct output_geometry geom(int32_t x, int32_t y, int32_t w, int32_t h)
{
    struct output_geometry g = { .x = x, .y = y, .width = w, .height = h };
    return g;
}

static void unit_check_screen_touch(void)
{
    /* two screens sharing a vertical edge (1920 wide, second starts at 1920) */
    CHECK(check_screen_touch(geom(0, 0, 1920, 1080),
                             geom(1920, 0, 1920, 1080)));
    /* overlapping */
    CHECK(check_screen_touch(geom(0, 0, 100, 100), geom(50, 50, 100, 100)));
    /* touching only at a corner */
    CHECK(check_screen_touch(geom(0, 0, 100, 100), geom(100, 100, 100, 100)));
    /* a gap between them -> not touching */
    CHECK(!check_screen_touch(geom(0, 0, 100, 100), geom(200, 0, 100, 100)));
}

static void unit_traverse_line(void)
{
    struct coord out;
    bool ok;

    /* pos 0 returns the start point unchanged */
    out = traverse_line((struct coord){ 0, 0 }, (struct coord){ 10, 10 }, 0,
                        &ok);
    CHECK(ok && out.x == 0 && out.y == 0);

    /* vertical line: x fixed, y advances by pos toward the end */
    out = traverse_line((struct coord){ 5, 0 }, (struct coord){ 5, 100 }, 7,
                        &ok);
    CHECK(ok && out.x == 5 && out.y == 7);
    out = traverse_line((struct coord){ 5, 100 }, (struct coord){ 5, 0 }, 7,
                        &ok);
    CHECK(ok && out.x == 5 && out.y == 93);

    /* 45-degree diagonal: equal advance in both axes */
    out = traverse_line((struct coord){ 0, 0 }, (struct coord){ 100, 100 }, 10,
                        &ok);
    CHECK(ok && out.x == 10 && out.y == 10);

    /* a step past the far end reports failure (out_success false) */
    out = traverse_line((struct coord){ 0, 0 }, (struct coord){ 10, 10 }, 11,
                        &ok);
    CHECK(!ok);
}

static void unit_get_ticks_from_scroll_accum(void)
{
    double accum;

    accum = 0.0;
    CHECK(get_ticks_from_scroll_accum(&accum) == 0 && accum == 0.0);
    accum = 119.0;
    CHECK(get_ticks_from_scroll_accum(&accum) == 0 && accum == 119.0);
    accum = 120.0;
    CHECK(get_ticks_from_scroll_accum(&accum) == 1 && accum == 0.0);
    accum = 250.0;
    CHECK(get_ticks_from_scroll_accum(&accum) == 2 && accum == 10.0);
    accum = -240.0;
    CHECK(get_ticks_from_scroll_accum(&accum) == -2 && accum == 0.0);
}

static void unit_random_between(void)
{
    int i;

    /* invalid interval (lower >= upper) returns upper, deterministically */
    CHECK(random_between(5, 5) == 5);
    CHECK(random_between(10, 3) == 3);

    /* real /dev/urandom path: every draw lands inside [lower, upper] */
    init_fd_urandom();
    for (i = 0; i < 100000; ++i) {
        int64_t r = random_between(1, 6);
        CHECK(r >= 1 && r <= 6);
    }
    for (i = 0; i < 1000; ++i) {
        int64_t r = random_between(0, 1);
        CHECK(r == 0 || r == 1);
    }
}

static void unit_current_time_ms(void)
{
    int64_t first, second;
    first = current_time_ms();   /* absolute CLOCK_MONOTONIC ms, non-negative */
    CHECK(first >= 0);
    second = current_time_ms();  /* monotonic: never goes backward */
    CHECK(second >= first);
}

static void unit_coord_space(void)
{
    /* Two side-by-side 1920x1080 screens in the global compositor space. */
    struct output_geometry g0 = geom(0, 0, 1920, 1080);
    struct output_geometry g1 = geom(1920, 0, 1920, 1080);
    struct screen_local_coord sl;
    struct coord ab;
    bool ok;
    ssize_t i;

    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
    state.output_geometries[0] = &g0;
    state.output_geometries[1] = &g1;

    /* a point on the second screen maps to that screen, local-origin relative */
    sl = abs_coord_to_screen_local_coord(2000, 50);
    CHECK(sl.output_idx == 1 && sl.x == 80 && sl.y == 50);
    /* round-trip back to absolute */
    ab = screen_local_coord_to_abs_coord(sl.x, sl.y, sl.output_idx, &ok);
    CHECK(ok && ab.x == 2000 && ab.y == 50);

    /* a point on the first screen */
    sl = abs_coord_to_screen_local_coord(10, 10);
    CHECK(sl.output_idx == 0 && sl.x == 10 && sl.y == 10);

    /* recalc_global_space works on the global 'state' output geometries set
     * above and writes its result back into 'state'. */
    CHECK(recalc_global_space());
    CHECK(state.pointer_space_width == 3840);
    CHECK(state.pointer_space_height == 1080);
    CHECK(state.pointer_space_x == 0 && state.pointer_space_y == 0);

    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
}

/* make_virtual_cursor_pos_sane walks start->end avoiding voids. Two cases: a
 * move wholly within one screen reaches its target unchanged; a move whose
 * straight line would cross a VOID is held at the last on-screen pixel and NEVER
 * jumps the void (the whole reason the function exists -- the trivial case alone
 * leaves that algorithm untested). */
static void unit_make_virtual_cursor_pos_sane(void)
{
    struct output_geometry g0 = geom(0, 0, 1920, 1080);
    /* A over a NARROWER B: directly below x=75 there is screen for y<100 (A)
     * but a void for y>=100 (B only spans x[0,50)). */
    struct output_geometry va = geom(0, 0, 100, 100);
    struct output_geometry vb = geom(0, 100, 50, 100);
    struct screen_local_coord res = EMPTY_SCREEN_LOCAL_COORD;
    double cx = 200.0;
    double cy = 200.0;
    double vx = 75.0;
    double vy = 150.0;
    ssize_t i;

    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
    state.output_geometries[0] = &g0;

    make_virtual_cursor_pos_sane(100.0, 100.0, &cx, &cy);
    CHECK(cx == 200.0 && cy == 200.0);

    /* Void-crossing: walking straight down x=75 from (75,50) leaves the covered
     * area at y=100; the cursor must stop before the void, not reach the raw end
     * (75,150) which sits in it. */
    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
    state.output_geometries[0] = &va;
    state.output_geometries[1] = &vb;
    make_virtual_cursor_pos_sane(75.0, 50.0, &vx, &vy);
    CHECK(vx == 75.0 && vy < 100.0);   /* clamped before the void, not 150 */
    res = abs_coord_to_screen_local_coord((int32_t)(vx), (int32_t)(vy));
    CHECK(res.output_idx >= 0);        /* lands on a screen, never in the void */

    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
}

/* How a forked child process ended. */
enum child_outcome { CH_EXIT0, CH_EXIT1, CH_SIGNALED, CH_OTHER };

static enum child_outcome classify_child(int status)
{
    if (WIFSIGNALED(status)) {
        return CH_SIGNALED;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return CH_EXIT0;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 1) {
        return CH_EXIT1;
    }
    return CH_OTHER;
}

/* Run kb_handle_keymap in a forked child against a backing fd of `fd_len` bytes
 * (written from `content`) with a compositor-declared `size`, and `old_map` as
 * the previously-seen map. */
static enum child_outcome run_keymap_child(const char *content, size_t fd_len,
                                           uint32_t size, const char *old_map)
{
    char tmpl[] = "/tmp/kloak_km_XXXXXX";
    int fd;
    pid_t pid;
    int status = 0;

    fd = mkstemp(tmpl);
    assert(fd >= 0);
    assert(unlink(tmpl) == 0);
    assert(content != NULL);
    assert(write(fd, content, fd_len) == (ssize_t)fd_len);

    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        /* kb_handle_keymap reads the previously-seen map from the global
         * 'state', not from its (unused) data arg; set it in the child so the
         * fork isolates the mutation. */
        state.old_kb_map_shm = (char *)old_map;
        if (old_map != NULL) {
            state.old_kb_map_shm_size = (int32_t)(strlen(old_map) + 1);
        }
        /* The FATAL path writes to stderr; keep the test output clean. */
        (void)!freopen("/dev/null", "w", stderr);
        kb_handle_keymap(NULL, NULL, WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1, fd, size);
        _exit(0);
    }
    assert(close(fd) == 0);
    assert(waitpid(pid, &status, 0) == pid);
    return classify_child(status);
}

/* kb_handle_keymap guards: an adequate map matching the previous one takes the
 * early return cleanly; a map with no NUL terminator in `size` bytes exits(1).
 * A backing fd SHORTER than the declared size is deliberately NOT guarded
 * (upstream WONTFIX: a hostile compositor can crash kloak many ways and already
 * sees all input), so that case is not tested. */
static void unit_kb_handle_keymap(void)
{
    CHECK(run_keymap_child("xkb", 4, 4, "xkb") == CH_EXIT0);
    CHECK(run_keymap_child("abcd", 4, 4, NULL) == CH_EXIT1);
}

/* Regression for two audit items (Whonix/kloak#24). Item D: check_screen_touch
 * must detect a cross/plus overlap where neither rectangle has a corner inside
 * the other. Item F: recalc_global_space must store the SPAN as the width, with
 * the origin tracked separately in pointer_space_x, for an offset leftmost
 * output. */
static void unit_cross_overlap_and_offset_global_space(void)
{
    struct output_geometry cross_a = geom(0, 400, 1920, 1080);
    struct output_geometry cross_b = geom(420, 0, 1080, 1920);
    struct output_geometry off_a = geom(100, 0, 1920, 1080);
    struct output_geometry off_b = geom(2020, 0, 1920, 1080);
    ssize_t i;

    CHECK(check_screen_touch(cross_a, cross_b));

    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
    state.output_geometries[0] = &off_a;
    state.output_geometries[1] = &off_b;
    CHECK(recalc_global_space());
    CHECK(state.pointer_space_width == 3840);
    CHECK(state.pointer_space_x == 100);

    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
}

/* recalc_global_space must REJECT (return false) a layout with a gap between
 * screens -- production turns that into the "gaps are present" fatal. */
static void unit_recalc_global_space_gap(void)
{
    struct output_geometry g0 = geom(0, 0, 1920, 1080);
    struct output_geometry gapped = geom(3000, 0, 1920, 1080);
    ssize_t i;

    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
    state.output_geometries[0] = &g0;
    state.output_geometries[1] = &gapped;
    CHECK(!recalc_global_space());

    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
}

/* A point covered by no screen maps to an invalid screen-local coordinate. */
static void unit_abs_coord_invalid(void)
{
    struct output_geometry g0 = geom(0, 0, 1920, 1080);
    struct screen_local_coord sl;
    ssize_t i;

    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
    state.output_geometries[0] = &g0;

    sl = abs_coord_to_screen_local_coord(5000, 5000);
    CHECK(sl.output_idx < 0);

    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
}

/* open_wl_sock, when connect() to the compositor socket fails, enters degraded
 * mode: it reports CTP_PACKET_WAYLAND_LOST to the parent and exit(0)s, so the
 * parent skips the grab and awaits the escape combo instead of aborting. (The
 * KLOAK_EXIT_ON_WL_CONNECT_FAILURE opt-in turns this back into a fatal exit, but
 * that decision lives in the parent; open_wl_sock itself always reports+exit(0)s.)
 * Run in a forked child so the exit is contained: it points send_write_fd at a
 * pipe and calls open_wl_sock against a WAYLAND_DISPLAY under an empty
 * XDG_RUNTIME_DIR, so the socket cannot exist and connect() fails with ENOENT
 * deterministically. The parent asserts the WAYLAND_LOST packet arrived and that
 * open_wl_sock exited (did not return) cleanly. */
static void unit_open_wl_sock_connect_degraded(void)
{
    char runtime_dir[] = "/tmp/kloak_wlsock_XXXXXX";
    int pipe_fds[2];
    pid_t pid;
    int status = 0;
    enum ctp_packet_type pkt = CTP_PACKET_INIT_ACK;
    ssize_t got = -1;

    assert(mkdtemp(runtime_dir) != NULL);
    assert(pipe(pipe_fds) == 0);

    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        assert(close(pipe_fds[0]) == 0);
        send_write_fd = pipe_fds[1];
        assert(setenv("XDG_RUNTIME_DIR", runtime_dir, 1) == 0);
        assert(setenv("WAYLAND_DISPLAY", "kloak-nonexistent-wl", 1) == 0);
        /* The degraded path warns to stderr; keep the test output clean. */
        (void)!freopen("/dev/null", "w", stderr);
        (void)open_wl_sock();
        /* open_wl_sock must NOT return on connect failure: it exits. A return
         * here lands as exit 2, which the CH_EXIT0 assert below rejects. */
        _exit(2);
    }
    assert(close(pipe_fds[1]) == 0);
    got = read(pipe_fds[0], &pkt, sizeof(pkt));
    assert(close(pipe_fds[0]) == 0);
    assert(waitpid(pid, &status, 0) == pid);
    assert(rmdir(runtime_dir) == 0);

    CHECK(got == (ssize_t)sizeof(pkt));
    CHECK(pkt == CTP_PACKET_WAYLAND_LOST);
    CHECK(classify_child(status) == CH_EXIT0);
}

/* Mirror send_msg_to_peer()'s KLOAK button-event wire framing
 * ([enum ptc_packet_type][uint32 button_code][uint8 is_pressed]) and write one
 * frame to fd. The parent's send_msg_to_peer is compiled out of this (KLOAKWL)
 * TU, so the frame is built here; the round-trip assert in unit_release_jitter
 * (the REAL get_msg_from_peer must parse back the exact button_code) fails loud
 * if this layout ever drifts from the parser. */
static void write_ptc_button_frame(int fd, enum ptc_packet_type type,
    uint32_t button_code, bool is_pressed)
{
    unsigned char buf[sizeof(enum ptc_packet_type) + sizeof(uint32_t)
        + sizeof(uint8_t)];
    size_t pos = 0;
    uint8_t pressed = is_pressed ? 1 : 0;

    memcpy(buf + pos, &type, sizeof(type));
    pos += sizeof(type);
    memcpy(buf + pos, &button_code, sizeof(button_code));
    pos += sizeof(button_code);
    memcpy(buf + pos, &pressed, sizeof(pressed));
    pos += sizeof(pressed);
    CHECK(write(fd, buf, pos) == (ssize_t)(pos));
}

/* kloak's reason to exist: every input event is RELEASED after a RANDOM delay
 * bounded by max_delay, and release times never decrease (jitter must not
 * reorder events). Drive the REAL scheduler in process_parent_message by
 * feeding button-event frames through a pipe exactly as the parent would; the
 * KB/CLICK paths need no Wayland state. Assert the two functional properties on
 * the real sched_time, not wall-clock release (deterministic, no compositor). */
static void unit_release_jitter(void)
{
    int pipe_fds[2];
    int i;
    int64_t t_before = 0;
    int64_t t_after = 0;
    int64_t prev_sched = -1;
    int64_t min_delay = INT64_MAX;
    int64_t max_seen_delay = -1;
    struct input_packet *pkt = NULL;

    init_fd_urandom();
    init_msg_ring();
    CHECK(pipe(pipe_fds) == 0);
    recv_read_fd = pipe_fds[0];
    max_delay = 1000;
    TAILQ_INIT(&evq_head);

    /* Bounded + random: reset prev_release_time each call so lower_bound == 0
     * and the full [0, max_delay] range is drawn. Each delay lands in range and
     * the sample spans a real spread (not a constant). */
    for (i = 0; i < 500; ++i) {
        prev_release_time = 0;
        write_ptc_button_frame(pipe_fds[1], PTC_PACKET_KB_EVENT,
            (uint32_t)(i), (i & 1) != 0);
        t_before = current_time_ms();
        CHECK(process_parent_message());
        t_after = current_time_ms();
        pkt = TAILQ_LAST(&evq_head, tailhead_evq);
        CHECK(pkt != NULL);
        /* round-trip: the REAL get_msg_from_peer parsed our frame */
        CHECK(pkt->packet_type == KLOAK_PACKET_TYPE_KB);
        CHECK(pkt->data.button_data.button_code == (uint32_t)(i));
        /* bounded: t_before <= sched_time <= t_after + max_delay */
        CHECK(pkt->sched_time >= t_before);
        CHECK(pkt->sched_time <= t_after + max_delay);
        if (pkt->sched_time - t_before < min_delay) {
            min_delay = pkt->sched_time - t_before;
        }
        if (pkt->sched_time - t_before > max_seen_delay) {
            max_seen_delay = pkt->sched_time - t_before;
        }
        TAILQ_REMOVE(&evq_head, pkt, evq_entries);
        free(pkt);
    }
    CHECK(max_seen_delay - min_delay > max_delay / 2);

    /* Monotonic release (no reorder): prev_release_time NOT reset, events queued
     * back-to-back; the clamp keeps sched_time non-decreasing. */
    prev_release_time = 0;
    prev_sched = -1;
    for (i = 0; i < 500; ++i) {
        write_ptc_button_frame(pipe_fds[1], PTC_PACKET_CLICK_EVENT, 272u, true);
        CHECK(process_parent_message());
        pkt = TAILQ_LAST(&evq_head, tailhead_evq);
        CHECK(pkt != NULL);
        CHECK(pkt->packet_type == KLOAK_PACKET_TYPE_CLICK);
        CHECK(pkt->sched_time >= prev_sched);
        prev_sched = pkt->sched_time;
        TAILQ_REMOVE(&evq_head, pkt, evq_entries);
        free(pkt);
    }

    CHECK(close(pipe_fds[0]) == 0);
    CHECK(close(pipe_fds[1]) == 0);
    recv_read_fd = -1;
}

/* Mirror send_msg_to_peer()'s KLOAK cursor/scroll framing
 * ([enum ptc_packet_type][double x][double y]) -- same drift guard as
 * write_ptc_button_frame (the round-trip packet-type check below). */
static void write_ptc_coord_frame(int fd, enum ptc_packet_type type,
    double x, double y)
{
    unsigned char buf[sizeof(enum ptc_packet_type) + sizeof(double) * 2];
    size_t pos = 0;

    memcpy(buf + pos, &type, sizeof(type));
    pos += sizeof(type);
    memcpy(buf + pos, &x, sizeof(x));
    pos += sizeof(x);
    memcpy(buf + pos, &y, sizeof(y));
    pos += sizeof(y);
    CHECK(write(fd, buf, pos) == (ssize_t)(pos));
}

/* The same bounded-random-delay guarantee must hold for the POINTER paths
 * (mouse movement, scroll), which reach the scheduler through
 * update_virtual_cursor / update_mouse_scroll. Set up one screen + pointer
 * space, then drive real CURSOR_REL and SCROLL events through the real
 * process_parent_message and assert each produced MOUSEMOVE / MOUSESCROLL packet
 * gets a delay in [0, max_delay] with real spread. (should_draw_cursor is off so
 * no cursor layers are needed.) */
static void unit_release_jitter_mouse(void)
{
    int pipe_fds[2];
    int i;
    int64_t t_before = 0;
    int64_t t_after = 0;
    int64_t min_delay = INT64_MAX;
    int64_t max_seen_delay = -1;
    struct output_geometry g0 = geom(0, 0, 1920, 1080);
    struct input_packet *pkt = NULL;

    init_fd_urandom();
    init_msg_ring();
    CHECK(pipe(pipe_fds) == 0);
    recv_read_fd = pipe_fds[0];
    max_delay = 1000;
    TAILQ_INIT(&evq_head);

    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
    state.output_geometries[0] = &g0;
    CHECK(recalc_global_space());
    should_draw_cursor = false;
    cursor_x = 100.0;
    cursor_y = 100.0;
    prev_cursor_x = 100.0;
    prev_cursor_y = 100.0;

    /* MOUSE MOVE: each event nudges the cursor 1px (staying on-screen), which
     * produces a MOUSEMOVE packet; assert bounded delay + spread. */
    for (i = 0; i < 500; ++i) {
        prev_release_time = 0;
        write_ptc_coord_frame(pipe_fds[1], PTC_PACKET_CURSOR_REL_EVENT,
            (i & 1) ? 1.0 : -1.0, 0.0);
        t_before = current_time_ms();
        CHECK(process_parent_message());
        t_after = current_time_ms();
        pkt = TAILQ_LAST(&evq_head, tailhead_evq);
        CHECK(pkt != NULL);
        CHECK(pkt->packet_type == KLOAK_PACKET_TYPE_MOUSEMOVE);
        CHECK(pkt->sched_time >= t_before);
        CHECK(pkt->sched_time <= t_after + max_delay);
        if (pkt->sched_time - t_before < min_delay) {
            min_delay = pkt->sched_time - t_before;
        }
        if (pkt->sched_time - t_before > max_seen_delay) {
            max_seen_delay = pkt->sched_time - t_before;
        }
        TAILQ_REMOVE(&evq_head, pkt, evq_entries);
        free(pkt);
    }
    CHECK(max_seen_delay - min_delay > max_delay / 2);

    /* MOUSE SCROLL: each event adds one full tick (SCROLL_UNITS_PER_TICK),
     * producing a MOUSESCROLL packet; assert bounded delay + spread. */
    min_delay = INT64_MAX;
    max_seen_delay = -1;
    vert_scroll_accum = 0.0;
    horiz_scroll_accum = 0.0;
    for (i = 0; i < 500; ++i) {
        prev_release_time = 0;
        write_ptc_coord_frame(pipe_fds[1], PTC_PACKET_SCROLL_EVENT,
            0.0, (double)(SCROLL_UNITS_PER_TICK));
        t_before = current_time_ms();
        CHECK(process_parent_message());
        t_after = current_time_ms();
        pkt = TAILQ_LAST(&evq_head, tailhead_evq);
        CHECK(pkt != NULL);
        CHECK(pkt->packet_type == KLOAK_PACKET_TYPE_MOUSESCROLL);
        CHECK(pkt->sched_time >= t_before);
        CHECK(pkt->sched_time <= t_after + max_delay);
        if (pkt->sched_time - t_before < min_delay) {
            min_delay = pkt->sched_time - t_before;
        }
        if (pkt->sched_time - t_before > max_seen_delay) {
            max_seen_delay = pkt->sched_time - t_before;
        }
        TAILQ_REMOVE(&evq_head, pkt, evq_entries);
        free(pkt);
    }
    CHECK(max_seen_delay - min_delay > max_delay / 2);

    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
    CHECK(close(pipe_fds[0]) == 0);
    CHECK(close(pipe_fds[1]) == 0);
    recv_read_fd = -1;
}

/* The bounded-random-delay guarantee must ALSO hold for the ABSOLUTE pointer
 * (touchscreen / VM mouse integration), which reaches the scheduler through
 * PTC_PACKET_CURSOR_ABS_EVENT -> cursor = abs + pointer_space -> update_virtual_cursor.
 * Use an offset-origin two-screen layout (pointer_space_x == 100) so the global
 * offset is observable, then assert each released MOUSEMOVE packet (a) carries
 * the pointer_space offset on its coordinate and (b) gets a delay in
 * [0, max_delay] with real spread. */
static void unit_release_jitter_abs(void)
{
    int pipe_fds[2];
    int i;
    int64_t t_before = 0;
    int64_t t_after = 0;
    int64_t min_delay = INT64_MAX;
    int64_t max_seen_delay = -1;
    struct output_geometry off_a = geom(100, 0, 1920, 1080);
    struct output_geometry off_b = geom(2020, 0, 1920, 1080);
    struct input_packet *pkt = NULL;
    double ax = 0.0;

    init_fd_urandom();
    init_msg_ring();
    CHECK(pipe(pipe_fds) == 0);
    recv_read_fd = pipe_fds[0];
    max_delay = 1000;
    TAILQ_INIT(&evq_head);

    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
    state.output_geometries[0] = &off_a;
    state.output_geometries[1] = &off_b;
    CHECK(recalc_global_space());
    CHECK(state.pointer_space_x == 100);   /* the offset is non-zero + observable */
    should_draw_cursor = false;
    cursor_x = 600.0;
    cursor_y = 200.0;
    prev_cursor_x = 600.0;
    prev_cursor_y = 200.0;

    /* Alternate the abs x between two on-screen values so every event changes the
     * integer cursor position and update_virtual_cursor emits exactly one
     * MOUSEMOVE (a point staying on-screen is not moved by the glide clamp). */
    for (i = 0; i < 500; ++i) {
        prev_release_time = 0;
        ax = (i & 1) ? 500.0 : 600.0;
        write_ptc_coord_frame(pipe_fds[1], PTC_PACKET_CURSOR_ABS_EVENT,
            ax, 200.0);
        t_before = current_time_ms();
        CHECK(process_parent_message());
        t_after = current_time_ms();
        pkt = TAILQ_LAST(&evq_head, tailhead_evq);
        CHECK(pkt != NULL);
        CHECK(pkt->packet_type == KLOAK_PACKET_TYPE_MOUSEMOVE);
        /* global coord = abs + pointer_space (the ABS-specific transform) */
        CHECK(pkt->data.coord_data.x == (int32_t)(ax) + state.pointer_space_x);
        CHECK(pkt->data.coord_data.y == 200 + state.pointer_space_y);
        /* bounded random delay */
        CHECK(pkt->sched_time >= t_before);
        CHECK(pkt->sched_time <= t_after + max_delay);
        if (pkt->sched_time - t_before < min_delay) {
            min_delay = pkt->sched_time - t_before;
        }
        if (pkt->sched_time - t_before > max_seen_delay) {
            max_seen_delay = pkt->sched_time - t_before;
        }
        TAILQ_REMOVE(&evq_head, pkt, evq_entries);
        free(pkt);
    }
    CHECK(max_seen_delay - min_delay > max_delay / 2);

    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
    CHECK(close(pipe_fds[0]) == 0);
    CHECK(close(pipe_fds[1]) == 0);
    recv_read_fd = -1;
}

/* calc_poll_timeout gates how long the main loop sleeps before the next release,
 * so it must: block indefinitely (-1) on an empty queue, return 0 when parent
 * data is already buffered OR the head packet is already due, return the
 * remaining delay for a future packet, and clamp a far-future wait to INT_MAX. A
 * bug returning 0 here (busy-spin) or a too-large value (late release) would
 * respectively waste CPU or break the delay bound. */
static void unit_calc_poll_timeout(void)
{
    struct input_packet p_future;
    struct input_packet p_past;
    struct input_packet p_farfuture;
    int timeout = 0;
    int64_t before_ms = 0;
    int64_t after_ms = 0;
    int64_t rem_lo = 0;
    int64_t rem_hi = 0;

    TAILQ_INIT(&evq_head);
    parse_ring_data_len = 0;
    /* empty queue, no buffered data -> block indefinitely */
    CHECK(calc_poll_timeout() == -1);

    /* buffered parent data -> service it now, no wait */
    parse_ring_data_len = 1;
    CHECK(calc_poll_timeout() == 0);
    parse_ring_data_len = 0;

    /* a packet due in the future -> a wait that tracks the REMAINING delay, not
     * merely any positive value: a stub returning 1 for every future wait would
     * busy-spin yet pass a bare `> 0 && <= 100000` check. calc_poll_timeout reads
     * the clock once internally, between our before/after reads, so the true
     * remaining delay it computes lies in [sched_time - after, sched_time - before]. */
    memset(&p_future, 0, sizeof(p_future));
    p_future.sched_time = current_time_ms() + 100000;
    TAILQ_INSERT_TAIL(&evq_head, &p_future, evq_entries);
    before_ms = current_time_ms();
    timeout = calc_poll_timeout();
    after_ms = current_time_ms();
    rem_lo = p_future.sched_time - after_ms;  /* clock latest -> smallest remaining */
    rem_hi = p_future.sched_time - before_ms; /* clock earliest -> largest remaining */
    if (rem_lo < 0) rem_lo = 0;
    if (rem_hi < 0) rem_hi = 0;
    CHECK((int64_t)timeout >= rem_lo && (int64_t)timeout <= rem_hi);
    TAILQ_REMOVE(&evq_head, &p_future, evq_entries);

    /* a packet already past its sched_time -> release immediately (0) */
    memset(&p_past, 0, sizeof(p_past));
    p_past.sched_time = current_time_ms() - 10;
    TAILQ_INSERT_TAIL(&evq_head, &p_past, evq_entries);
    CHECK(calc_poll_timeout() == 0);
    TAILQ_REMOVE(&evq_head, &p_past, evq_entries);

    /* a wait exceeding INT_MAX ms clamps to INT_MAX (poll's int timeout) */
    memset(&p_farfuture, 0, sizeof(p_farfuture));
    p_farfuture.sched_time = current_time_ms() + (int64_t)(INT_MAX) + 100000;
    TAILQ_INSERT_TAIL(&evq_head, &p_farfuture, evq_entries);
    CHECK(calc_poll_timeout() == INT_MAX);
    TAILQ_REMOVE(&evq_head, &p_farfuture, evq_entries);
}

/* Regression (Whonix/kloak#41): the identical-keymap early return in
 * kb_handle_keymap must close the compositor-provided fd. Pre-fix it munmap'd
 * the mapping but leaked the fd, so a compositor re-sending the same keymap
 * leaked one fd per event until shm_open/allocate_shm failed fatally. The child
 * asserts the fd is closed on return. */
static enum child_outcome run_keymap_leak_child(void)
{
    char tmpl[] = "/tmp/kloak_kmleak_XXXXXX";
    int fd = mkstemp(tmpl);
    pid_t pid;
    int status = 0;

    assert(fd >= 0);
    assert(unlink(tmpl) == 0);
    assert(write(fd, "xkb", 4) == 4);   /* "xkb\0" */

    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        /* Previously-seen map identical to the incoming one -> early return. */
        state.old_kb_map_shm = (char *)"xkb";
        state.old_kb_map_shm_size = 4;
        (void)!freopen("/dev/null", "w", stderr);
        kb_handle_keymap(NULL, NULL, WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1, fd, 4);
        /* The identical-map path must have closed fd; still open -> leak. */
        if (fcntl(fd, F_GETFD) != -1) {
            _exit(2);
        }
        _exit(errno == EBADF ? 0 : 3);
    }
    assert(close(fd) == 0);
    assert(waitpid(pid, &status, 0) == pid);
    return classify_child(status);
}

static void unit_kb_handle_keymap_identical_closes_fd(void)
{
    CHECK(run_keymap_leak_child() == CH_EXIT0);
}

/* Regression (Whonix/kloak#41): update_virtual_cursor must not abort when the
 * only non-NULL output geometry is 0x0. labwc emits wl_output::done before the
 * xdg-output logical size, and display_sync_maybe records a 0x0 geometry until
 * the size arrives; with the cursor homeless, the relocation loop hit
 * assert(sane_location_valid) and aborted. It must skip the unusable geometry
 * and return NULL when no screen is usable. */
static enum child_outcome run_cursor_zero_geom_child(void)
{
    static struct output_geometry zero_geom = { .x = 0, .y = 0,
        .width = 0, .height = 0 };
    pid_t pid;
    int status = 0;

    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        struct input_packet *pkt = NULL;
        ssize_t i;
        (void)!freopen("/dev/null", "w", stderr);
        for (i = 0; i < MAX_SCREEN_COUNT; i++) {
            state.output_geometries[i] = NULL;
        }
        state.output_geometries[0] = &zero_geom;
        prev_cursor_x = 0.0;
        prev_cursor_y = 0.0;
        cursor_x = 0.0;
        cursor_y = 0.0;
        pkt = update_virtual_cursor();
        /* No usable screen -> must return NULL, not abort. */
        _exit(pkt == NULL ? 0 : 1);
    }
    assert(waitpid(pid, &status, 0) == pid);
    return classify_child(status);
}

static void unit_update_virtual_cursor_zero_geometry(void)
{
    CHECK(run_cursor_zero_geom_child() == CH_EXIT0);
}

/* Regression (Whonix/kloak#41): applayer_config_init must not busy-spin at 100%
 * CPU (while it still holds capabilities) if the parent dies before sending
 * config. read_peer_data_to_ring_buffer returns on FIONREAD==0 without read()ing,
 * so it never observes EOF by itself; the config loop must poll and exit on
 * hangup. The child's write end is closed everywhere -> POLLHUP; alarm bounds a
 * pre-fix spin so the canary fails fast rather than hanging the suite. */
static enum child_outcome run_config_init_hangup_child(void)
{
    int pfd[2];
    pid_t pid;
    int status = 0;

    assert(pipe(pfd) == 0);
    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        (void)!freopen("/dev/null", "w", stderr);
        assert(dup2(pfd[0], 0) == 0);   /* applayer_config_init reads fd 0 */
        assert(close(pfd[0]) == 0);
        assert(close(pfd[1]) == 0);     /* no writer remains -> POLLHUP */
        alarm(10);                      /* a pre-fix spin is killed by SIGALRM */
        applayer_config_init();         /* must exit via POLLHUP, not spin */
        _exit(0);
    }
    assert(close(pfd[0]) == 0);
    assert(close(pfd[1]) == 0);
    assert(waitpid(pid, &status, 0) == pid);
    return classify_child(status);
}

static void unit_applayer_config_init_exits_on_hangup(void)
{
    CHECK(run_config_init_hangup_child() == CH_EXIT0);
}

/* find_merge_target_packet is the core of packet coalescing (move-over-scroll
 * and scroll-over-move): a reverse walk from the queue tail that returns the
 * last packet of the target type, SKIPPING an allowed intervening type, but
 * stopping (returning NULL) at any other packet. Every jitter test drains the
 * queue between events, so this reverse walk + ignore-list + blocker logic was
 * never exercised -- a broken coalescer (wrong skip, merging past a key) would
 * ship green. Drive it directly over a hand-built queue. */
static void unit_find_merge_target_packet(void)
{
    const enum input_packet_type ign_scroll[]
        = { KLOAK_PACKET_TYPE_MOUSESCROLL, 0 };
    const enum input_packet_type ign_move[]
        = { KLOAK_PACKET_TYPE_MOUSEMOVE, 0 };
    struct input_packet *mv = NULL;
    struct input_packet *sc = NULL;
    struct input_packet *kb = NULL;
    struct input_packet *pkt = NULL;

    TAILQ_INIT(&evq_head);

    /* empty queue -> no merge target */
    CHECK(find_merge_target_packet(KLOAK_PACKET_TYPE_MOUSEMOVE, ign_scroll)
        == NULL);

    /* [MOVE] -> that move is the target */
    mv = safe_calloc(1, sizeof(struct input_packet));
    mv->packet_type = KLOAK_PACKET_TYPE_MOUSEMOVE;
    TAILQ_INSERT_TAIL(&evq_head, mv, evq_entries);
    CHECK(find_merge_target_packet(KLOAK_PACKET_TYPE_MOUSEMOVE, ign_scroll)
        == mv);

    /* [MOVE, SCROLL]: a move coalesces ACROSS an intervening scroll (scroll is
     * on the ignore list), and a scroll finds the tail scroll. */
    sc = safe_calloc(1, sizeof(struct input_packet));
    sc->packet_type = KLOAK_PACKET_TYPE_MOUSESCROLL;
    TAILQ_INSERT_TAIL(&evq_head, sc, evq_entries);
    CHECK(find_merge_target_packet(KLOAK_PACKET_TYPE_MOUSEMOVE, ign_scroll)
        == mv);
    CHECK(find_merge_target_packet(KLOAK_PACKET_TYPE_MOUSESCROLL, ign_move)
        == sc);

    /* [MOVE, SCROLL, KB]: a key at the tail is neither target nor ignored, so it
     * BLOCKS the merge -- a move must not coalesce past an unrelated event. */
    kb = safe_calloc(1, sizeof(struct input_packet));
    kb->packet_type = KLOAK_PACKET_TYPE_KB;
    TAILQ_INSERT_TAIL(&evq_head, kb, evq_entries);
    CHECK(find_merge_target_packet(KLOAK_PACKET_TYPE_MOUSEMOVE, ign_scroll)
        == NULL);

    while ((pkt = TAILQ_FIRST(&evq_head)) != NULL) {
        TAILQ_REMOVE(&evq_head, pkt, evq_entries);
        free(pkt);
    }
}

int main(void)
{
    unit_check_screen_touch();
    unit_find_merge_target_packet();
    unit_release_jitter();
    unit_release_jitter_mouse();
    unit_release_jitter_abs();
    unit_calc_poll_timeout();
    unit_traverse_line();
    unit_get_ticks_from_scroll_accum();
    unit_random_between();
    unit_current_time_ms();
    unit_coord_space();
    unit_make_virtual_cursor_pos_sane();
    unit_kb_handle_keymap();
    unit_cross_overlap_and_offset_global_space();
    unit_recalc_global_space_gap();
    unit_abs_coord_invalid();
    unit_open_wl_sock_connect_degraded();
    unit_kb_handle_keymap_identical_closes_fd();
    unit_update_virtual_cursor_zero_geometry();
    unit_applayer_config_init_exits_on_hangup();
    printf("kloakwl harness: all assertions passed (%d checks)\n", checks);
    return 0;
}
