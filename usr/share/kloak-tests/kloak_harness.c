/*
SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted

Concrete unit tests + a light randomized fuzz for kloak's pure/testable
functions. Compiled and run by test_kloak_verification.py against the REAL
src/kloak.c (reusing kloak's KLOAK_FUZZING seam -- no kloak source change), then
linked with the wayland-scanner protocol code and the wayland/libinput/libevdev/
xkbcommon libraries exactly as kloak itself links. No compositor or input device
is needed: the pure logic is called directly, and the one Wayland handler
exercised (kb_handle_keymap, below) runs in a forked child over a plain fd, not
a live connection.

Also here:
  * unit_kb_handle_keymap -- regression for the compositor-controlled keymap-fd
    SIGBUS (Whonix/kloak#24): a forked child proves a short fd is rejected with a
    clean exit, not a fault.
  * characterize_open_bugs_24 -- executable documentation of the KNOWN-OPEN
    upstream bugs referred to the maintainer (cross-overlap screen touch, and the
    br_corner_x-as-width global-space bug): each pins the current behavior so a
    fix trips the test.

Complements kloak_cbmc.c: CBMC proves the invariants hold for ALL inputs in the
operating envelope; these assert the concrete, human-meaningful values and edges
(and catch a regression CBMC's envelope assumptions might mask).
*/
#define KLOAK_FUZZING
#include "kloak.c"

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>

static int checks = 0;
#define CHECK(cond) do { assert(cond); ++checks; } while (0)

static void unit_lookup_keycode(void)
{
    CHECK(lookup_keycode("KEY_ESC") == KEY_ESC);
    CHECK(lookup_keycode("KEY_A") == KEY_A);
    CHECK(lookup_keycode("KEY_RIGHTSHIFT") == KEY_RIGHTSHIFT);
    CHECK(lookup_keycode("KEY_UNKNOWN") == KEY_UNKNOWN);
    /* A name absent from the table maps to 0 (the documented miss value). */
    CHECK(lookup_keycode("KEY_DOES_NOT_EXIST") == 0);
    CHECK(lookup_keycode("") == 0);
}

static void unit_check_point_in_area(void)
{
    /* point strictly inside */
    CHECK(check_point_in_area(5, 5, 0, 0, 10, 10));
    /* top-left corner is inclusive */
    CHECK(check_point_in_area(0, 0, 0, 0, 10, 10));
    /* right/bottom edge is exclusive (x < rect_x + rect_width) */
    CHECK(!check_point_in_area(10, 5, 0, 0, 10, 10));
    CHECK(!check_point_in_area(5, 10, 0, 0, 10, 10));
    /* outside */
    CHECK(!check_point_in_area(20, 20, 0, 0, 10, 10));
    /* any negative coordinate -> false */
    CHECK(!check_point_in_area(-1, 5, 0, 0, 10, 10));
    CHECK(!check_point_in_area(5, 5, 0, 0, -10, 10));
    /* zero-size rectangle contains nothing */
    CHECK(!check_point_in_area(0, 0, 0, 0, 0, 0));
}

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
    /* a negative field -> false */
    CHECK(!check_screen_touch(geom(-1, 0, 100, 100), geom(100, 0, 100, 100)));
}

static void unit_traverse_line(void)
{
    struct coord a = { .x = 0, .y = 0 };
    struct coord out;

    /* pos 0 returns the start point unchanged */
    out = traverse_line(a, (struct coord){ .x = 10, .y = 10 }, 0);
    CHECK(out.x == 0 && out.y == 0);

    /* vertical line: x fixed, y advances by pos toward the end */
    out = traverse_line((struct coord){ 5, 0 }, (struct coord){ 5, 100 }, 7);
    CHECK(out.x == 5 && out.y == 7);
    out = traverse_line((struct coord){ 5, 100 }, (struct coord){ 5, 0 }, 7);
    CHECK(out.x == 5 && out.y == 93);

    /* shallow near-horizontal line: x advances by pos, y barely moves */
    out = traverse_line((struct coord){ 0, 0 }, (struct coord){ 100, 10 }, 10);
    CHECK(out.x == 10 && out.y == 1);

    /* 45-degree diagonal: equal advance in both axes */
    out = traverse_line((struct coord){ 0, 0 }, (struct coord){ 100, 100 }, 10);
    CHECK(out.x == 10 && out.y == 10);
}

static void unit_parse_uint31(void)
{
    int32_t v = -1;
    CHECK(parse_uint31_arg("0", 10, &v) && v == 0);
    CHECK(parse_uint31_arg("2147483647", 10, &v) && v == INT32_MAX);
    CHECK(parse_uint31_arg("ff", 16, &v) && v == 255);
    /* > INT32_MAX rejected */
    CHECK(!parse_uint31_arg("2147483648", 10, &v));
    /* empty, trailing junk, and a negative (strtoul wraps huge) all rejected */
    CHECK(!parse_uint31_arg("", 10, &v));
    CHECK(!parse_uint31_arg("12x", 10, &v));
    CHECK(!parse_uint31_arg("-1", 10, &v));
    /* A leading '-' that strtoul wraps to a SMALL in-range value must still be
     * rejected (bug: "-18446744073709551615" wraps to 1). */
    CHECK(!parse_uint31_arg("-18446744073709551615", 10, &v));
}

static void unit_parse_uint32(void)
{
    uint32_t v = 0;
    CHECK(parse_uint32_arg("0", 10, &v) && v == 0);
    CHECK(parse_uint32_arg("4294967295", 10, &v) && v == UINT32_MAX);
    /* > UINT32_MAX rejected */
    CHECK(!parse_uint32_arg("4294967296", 10, &v));
    CHECK(!parse_uint32_arg("", 10, &v));
    CHECK(!parse_uint32_arg("x", 10, &v));
    CHECK(!parse_uint32_arg("-18446744073709551615", 10, &v));
}

static void unit_get_ticks_from_scroll_accum(void)
{
    double accum;

    /* zero accumulator yields no ticks, left untouched */
    accum = 0.0;
    CHECK(get_ticks_from_scroll_accum(&accum) == 0 && accum == 0.0);

    /* below one tick (120 units): no tick, accumulator preserved */
    accum = 119.0;
    CHECK(get_ticks_from_scroll_accum(&accum) == 0 && accum == 119.0);

    /* exactly one tick: 1 returned, remainder drained to 0 */
    accum = 120.0;
    CHECK(get_ticks_from_scroll_accum(&accum) == 1 && accum == 0.0);

    /* two ticks plus remainder: 2 returned, remainder kept */
    accum = 250.0;
    CHECK(get_ticks_from_scroll_accum(&accum) == 2 && accum == 10.0);

    /* negative direction */
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
    applayer_random_init();
    for (i = 0; i < 100000; ++i) {
        int64_t r = random_between(1, 6);
        CHECK(r >= 1 && r <= 6);
    }
    /* a single-width interval after the lower>=upper guard */
    for (i = 0; i < 1000; ++i) {
        int64_t r = random_between(0, 1);
        CHECK(r == 0 || r == 1);
    }
}

static void unit_current_time_ms(void)
{
    int64_t first, second;
    start_time = 0;
    first = current_time_ms();   /* first call seeds start_time, returns 0 */
    CHECK(first == 0);
    second = current_time_ms();  /* subsequent calls are a non-negative delta */
    CHECK(second >= 0);
}

static void unit_coord_space(void)
{
    /* Two side-by-side 1920x1080 screens in the global compositor space. */
    struct output_geometry g0 = geom(0, 0, 1920, 1080);
    struct output_geometry g1 = geom(1920, 0, 1920, 1080);
    struct disp_state local = { 0 };
    struct screen_local_coord sl;
    struct coord ab;
    ssize_t i;

    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
    state.output_geometries[0] = &g0;
    state.output_geometries[1] = &g1;

    /* a point on the second screen maps to that screen, local-origin relative */
    sl = abs_coord_to_screen_local_coord(2000, 50);
    CHECK(sl.valid && sl.output_idx == 1 && sl.x == 80 && sl.y == 50);
    /* round-trip back to absolute */
    ab = screen_local_coord_to_abs_coord(sl.x, sl.y, sl.output_idx);
    CHECK(ab.x == 2000 && ab.y == 50);

    /* a point on the first screen */
    sl = abs_coord_to_screen_local_coord(10, 10);
    CHECK(sl.valid && sl.output_idx == 0 && sl.x == 10 && sl.y == 10);

    /* recalc_global_space spans both screens with no gap */
    local.output_geometries[0] = &g0;
    local.output_geometries[1] = &g1;
    recalc_global_space(&local);
    CHECK(local.global_space_width == 3840);
    CHECK(local.global_space_height == 1080);
    CHECK(local.pointer_space_x == 0 && local.pointer_space_y == 0);

    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
}

/* parse_esc_key_str parses one -k/--escape-keys value: a comma separates escape
 * combos, '|' separates the keys within a combo. The CLI rejects a repeated -k
 * (check_dup_arg_and_mark exits before a second call), so parse_esc_key_str is
 * invoked at most once; this tests that single-call contract across both
 * separators. */
static void unit_parse_esc_key_str(void)
{
    esc_key_list = NULL;
    esc_key_sublist_len = NULL;
    active_esc_key_list = NULL;
    esc_key_list_len = 0;

    /* two combos: "KEY_A" and the chord "KEY_RIGHTSHIFT|KEY_B" */
    parse_esc_key_str("KEY_A,KEY_RIGHTSHIFT|KEY_B");

    CHECK(esc_key_list_len == 2);
    CHECK(esc_key_sublist_len[0] == 1);
    CHECK(esc_key_list[0][0] == KEY_A);
    CHECK(esc_key_sublist_len[1] == 2);
    CHECK(esc_key_list[1][0] == KEY_RIGHTSHIFT);
    CHECK(esc_key_list[1][1] == KEY_B);
}

/* randname must fill the buffer with [A-Za-z] only. Bug: the lowercase branch
 * adds ASCII_LOWERCASE_START (97) without first subtracting ALPHABET_LEN, so a
 * reduced value in [26,51] becomes bytes 123..148 ({ | } ~ DEL and high bytes),
 * not a-z. Needs randfd (applayer_random_init). */
static void unit_randname(void)
{
    char buf[256];
    size_t n;

    applayer_random_init();
    randname(buf, (ssize_t)sizeof(buf));
    for (n = 0; n < sizeof(buf); ++n) {
        CHECK((buf[n] >= 'A' && buf[n] <= 'Z')
              || (buf[n] >= 'a' && buf[n] <= 'z'));
    }
}

/* How a kb_handle_keymap child process ended. */
enum km_outcome { KM_EXIT0, KM_EXIT1, KM_SIGNALED, KM_OTHER };

/* Run kb_handle_keymap in a forked child against a backing fd of `fd_len` bytes
 * (written from `content`, or truncated to that length when `content` is NULL)
 * but a compositor-declared `size`, with `old_map` as the previously-seen map.
 * Returns how the child terminated. A short fd (`size` > `fd_len`) makes the
 * mmap+memchr read pages past end-of-file; without the fstat guard that faults
 * with SIGBUS, with it the function exits(1) cleanly. */
static enum km_outcome run_keymap_child(const char *content, size_t fd_len,
                                        uint32_t size, const char *old_map)
{
    char tmpl[] = "/tmp/kloak_km_XXXXXX";
    int fd;
    pid_t pid;
    int status = 0;

    fd = mkstemp(tmpl);
    assert(fd >= 0);
    assert(unlink(tmpl) == 0);
    if (content != NULL) {
        assert(write(fd, content, fd_len) == (ssize_t)fd_len);
    } else {
        assert(ftruncate(fd, (off_t)fd_len) == 0);
    }

    pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        struct disp_state st = { 0 };
        st.old_kb_map_shm = (char *)old_map;
        /* The FATAL path writes to stderr; keep the test output clean. */
        (void)!freopen("/dev/null", "w", stderr);
        kb_handle_keymap(&st, NULL, WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1, fd, size);
        _exit(0);
    }
    assert(close(fd) == 0);
    assert(waitpid(pid, &status, 0) == pid);
    if (WIFSIGNALED(status)) {
        return KM_SIGNALED;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return KM_EXIT0;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 1) {
        return KM_EXIT1;
    }
    return KM_OTHER;
}

/* Regression for the keymap-fd SIGBUS bug (Whonix/kloak#24 third-pass item A):
 * `size` and `fd` both come from the compositor, so a `size` larger than the
 * backing fd must be rejected BEFORE mmap/memchr read past end-of-file. The
 * fstat guard turns the SIGBUS into a clean FATAL exit. */
static void unit_kb_handle_keymap(void)
{
    /* Zero-length fd, size 4096: every mapped page is past EOF. Guard present
     * -> clean exit(1); absent -> KM_SIGNALED (SIGBUS). */
    CHECK(run_keymap_child(NULL, 0, 4096, NULL) == KM_EXIT1);

    /* Adequate fd whose content equals the previous map: the function takes the
     * "same map" early return and completes without faulting. */
    CHECK(run_keymap_child("xkb", 4, 4, "xkb") == KM_EXIT0);

    /* Adequate fd with no NUL terminator in `size` bytes: the existing
     * malicious-keymap guard exits(1) (no SIGBUS). */
    CHECK(run_keymap_child("abcd", 4, 4, NULL) == KM_EXIT1);
}

/* CHARACTERIZATION of KNOWN-OPEN upstream bugs (Whonix/kloak#24 third pass),
 * referred to the maintainer as non-localized. Each CHECK pins the CURRENT
 * (incorrect) behavior: it catches a regression AND trips when the bug is fixed
 * (then flip to the commented correct assertion). These document the open
 * defect in executable form -- they do NOT endorse the behavior. */
static void characterize_open_bugs_24(void)
{
    struct output_geometry cross_a = geom(0, 400, 1920, 1080);
    struct output_geometry cross_b = geom(420, 0, 1080, 1920);
    struct output_geometry off_a = geom(100, 0, 1920, 1080);
    struct output_geometry off_b = geom(2020, 0, 1920, 1080);
    struct disp_state local = { 0 };

    /* Item D: check_screen_touch tests only corner-containment, so a cross/plus
     * overlap (these two overlap over x[420,1500) y[400,1480)) is wrongly seen
     * as non-touching. Correct when fixed:
     *   CHECK(check_screen_touch(cross_a, cross_b)); */
    CHECK(!check_screen_touch(cross_a, cross_b));

    /* Item F: recalc_global_space stores global_space_width = br_corner_x (the
     * right-edge coordinate), not the span br_corner_x - ul_corner_x. With the
     * leftmost output at x=100 the width is overstated by 100. Correct when
     * fixed: CHECK(local.global_space_width == 3840); */
    local.output_geometries[0] = &off_a;
    local.output_geometries[1] = &off_b;
    recalc_global_space(&local);
    CHECK(local.global_space_width == 3940);
    CHECK(local.pointer_space_x == 100);
}

/* Regression for the inotify/startup "event"-prefix loose match
 * (Whonix/kloak#41, CodeRabbit outside-diff): only canonical "event<N>" evdev
 * nodes (what udev creates) must be grabbed; a bare "event" or an
 * "event"-prefixed non-device name (e.g. "eventfoo") must be ignored. */
static void unit_is_event_device_name(void)
{
    /* canonical nodes attach */
    CHECK(is_event_device_name("event0"));
    CHECK(is_event_device_name("event1"));
    CHECK(is_event_device_name("event10"));
    CHECK(is_event_device_name("event2147483647"));
    /* "event"-prefixed non-devices are ignored */
    CHECK(!is_event_device_name("event"));     /* no numeric suffix */
    CHECK(!is_event_device_name("eventfoo"));  /* the reported case */
    CHECK(!is_event_device_name("event0a"));   /* trailing non-digit */
    CHECK(!is_event_device_name("event1.0"));
    /* unrelated and degenerate names */
    CHECK(!is_event_device_name("mouse0"));
    CHECK(!is_event_device_name("js0"));
    CHECK(!is_event_device_name("eve"));
    CHECK(!is_event_device_name(""));
}

/* Regression for the press-tracking double-list bug (the src/kloak.c FIXME):
 * on a key/button press kloak links the SAME input_packet onto two queues at
 * once -- the main event queue (evq_head, via `entries`) and the pressing
 * device's tracking queue (trackq_head, via `trackq_entries`). A single shared
 * TAILQ_ENTRY link cannot be on two lists at the same time, so the second
 * insert corrupted both: removing the packet from the tracking queue on release
 * mangled the event queue (the "silently failing TAILQ_REMOVE" -> assertion
 * failure / use-after-free on the second release). The fix gives the tracking
 * queue its own `trackq_entries` link. This reproduces the exact membership and
 * asserts that removing from one queue leaves the other intact; it also fails to
 * compile if `trackq_entries` is ever removed again. */
static void unit_trackq_separate_link(void)
{
    struct li_device_info dev = { 0 };
    struct input_packet *earlier = safe_calloc(1, sizeof(*earlier));
    struct input_packet *press = safe_calloc(1, sizeof(*press));
    struct input_packet *walk = NULL;
    int seen = 0;

    TAILQ_INIT(&evq_head);
    TAILQ_INIT(&dev.trackq_head);

    /* The event queue already holds an earlier event; the press then arrives on
     * both the event queue and the device tracking queue, exactly as kloak's
     * handler does. */
    TAILQ_INSERT_TAIL(&evq_head, earlier, entries);
    TAILQ_INSERT_TAIL(&evq_head, press, entries);
    TAILQ_INSERT_TAIL(&dev.trackq_head, press, trackq_entries);

    /* Release handling removes the matching press from the tracking queue. */
    TAILQ_REMOVE(&dev.trackq_head, press, trackq_entries);

    /* Tracking queue is now empty ... */
    CHECK(TAILQ_EMPTY(&dev.trackq_head));
    /* ... and the event queue is still well-formed: both events, in order, with
     * the chain intact. A shared link would have unlinked `press` from evq too
     * (or corrupted `earlier`'s next pointer) when it was removed above. */
    TAILQ_FOREACH(walk, &evq_head, entries) {
        if (seen == 0) {
            CHECK(walk == earlier);
        } else if (seen == 1) {
            CHECK(walk == press);
        }
        ++seen;
    }
    CHECK(seen == 2);

    TAILQ_INIT(&evq_head);
    free(earlier);
    free(press);
}

int main(void)
{
    unit_lookup_keycode();
    unit_check_point_in_area();
    unit_check_screen_touch();
    unit_traverse_line();
    unit_parse_uint31();
    unit_parse_uint32();
    unit_get_ticks_from_scroll_accum();
    unit_random_between();
    unit_current_time_ms();
    unit_coord_space();
    unit_parse_esc_key_str();
    unit_randname();
    unit_kb_handle_keymap();
    unit_is_event_device_name();
    unit_trackq_separate_link();
    characterize_open_bugs_24();
    printf("kloak harness: all assertions passed (%d checks)\n", checks);
    return 0;
}
