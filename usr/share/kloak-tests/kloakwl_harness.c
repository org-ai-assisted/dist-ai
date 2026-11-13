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
and the short-backing-fd SIGBUS guard), and the now-fixed cross-overlap and
offset-global-space audit regressions.
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

/* make_virtual_cursor_pos_sane walks start->end avoiding voids. A move wholly
 * within one screen reaches its target unchanged. */
static void unit_make_virtual_cursor_pos_sane(void)
{
    struct output_geometry g0 = geom(0, 0, 1920, 1080);
    double cx = 200.0;
    double cy = 200.0;
    ssize_t i;

    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
    state.output_geometries[0] = &g0;

    make_virtual_cursor_pos_sane(100.0, 100.0, &cx, &cy);
    CHECK(cx == 200.0 && cy == 200.0);

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

/* open_wl_sock, when connect() to the compositor socket fails, is FATAL: it
 * err(1)-exits and sends the parent nothing. (Whether it should instead enter a
 * degraded mode -- report CTP_PACKET_WAYLAND_LOST and exit(0) so the parent
 * skips the grab and awaits the escape combo -- is tracked in Whonix/kloak#35;
 * it is not in the shipped source.) Run in a forked child so the fatal exit is
 * contained: it points send_write_fd at a pipe and calls open_wl_sock against a
 * WAYLAND_DISPLAY under an empty XDG_RUNTIME_DIR, so the socket cannot exist and
 * connect() fails with ENOENT deterministically. The parent asserts no packet
 * arrived and that open_wl_sock exited (did not return) with the err(1) code. */
static void unit_open_wl_sock_connect_fatal(void)
{
    char runtime_dir[] = "/tmp/kloak_wlsock_XXXXXX";
    int pipe_fds[2];
    pid_t pid;
    int status = 0;
    enum ctp_packet_type pkt = CTP_PACKET_INIT_ACK;
    ssize_t got;

    assert(mkdtemp(runtime_dir) != NULL);
    assert(pipe(pipe_fds) == 0);

    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        assert(close(pipe_fds[0]) == 0);
        send_write_fd = pipe_fds[1];
        assert(setenv("XDG_RUNTIME_DIR", runtime_dir, 1) == 0);
        assert(setenv("WAYLAND_DISPLAY", "kloak-nonexistent-wl", 1) == 0);
        /* The FATAL path writes to stderr; keep the test output clean. */
        (void)!freopen("/dev/null", "w", stderr);
        (void)open_wl_sock();
        /* open_wl_sock must NOT return on connect failure: it exits. A return
         * here lands as exit 2, which the CH_EXIT1 assert below rejects. */
        _exit(2);
    }
    assert(close(pipe_fds[1]) == 0);
    got = read(pipe_fds[0], &pkt, sizeof(pkt));
    assert(close(pipe_fds[0]) == 0);
    assert(waitpid(pid, &status, 0) == pid);
    assert(rmdir(runtime_dir) == 0);

    CHECK(got == 0);
    CHECK(classify_child(status) == CH_EXIT1);
}

int main(void)
{
    unit_check_screen_touch();
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
    unit_open_wl_sock_connect_fatal();
    printf("kloakwl harness: all assertions passed (%d checks)\n", checks);
    return 0;
}
