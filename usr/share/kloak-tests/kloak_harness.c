/*
SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted

Concrete unit tests + a light randomized fuzz for kloak's pure/testable
functions. Compiled and run by test_kloak_verification.py against the REAL
src/kloak.c (reusing kloak's KLOAK_FUZZING seam -- no kloak source change), then
linked with the wayland-scanner protocol code and the wayland/libinput/libevdev/
xkbcommon libraries exactly as kloak itself links. No compositor or input device
is needed: the pure logic is called directly, and the handlers exercised run in
a forked child over a plain fd, not a live connection.

Covers arraybolt3's testability seams (Whonix/kloak#24): calc_next_led_state
(num/caps-lock 4-state cycle), clamp_cursor (pointer-space clamp),
make_virtual_cursor_pos_sane (void-avoiding glide), and parse_inotify_events
(the assert-free, fuzzable record walk, incl. the zero-length IN_Q_OVERFLOW
skip). Also pins two now-FIXED audit bugs in
unit_cross_overlap_and_offset_global_space (cross/plus overlap seen as a gap;
global-space width stored as the right-edge coordinate).

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

    /* a step past the far end yields the end-of-line sentinel (-1, -1) */
    out = traverse_line((struct coord){ 0, 0 }, (struct coord){ 10, 10 }, 11);
    CHECK(out.x == -1 && out.y == -1);
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
    CHECK(recalc_global_space(&local));
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

/* Only canonical "event<N>" evdev nodes (what udev creates) are grabbed; the
 * startup scan and the inotify hotplug path both match with the compiled
 * evdev_reg regex. A bare "event" or an "event"-prefixed non-device name must
 * not match. */
static void unit_evdev_regex(void)
{
    applayer_regex_init();
    /* canonical nodes match */
    CHECK(regexec(&evdev_reg, "event0", 0, NULL, 0) == 0);
    CHECK(regexec(&evdev_reg, "event1", 0, NULL, 0) == 0);
    CHECK(regexec(&evdev_reg, "event10", 0, NULL, 0) == 0);
    CHECK(regexec(&evdev_reg, "event2147483647", 0, NULL, 0) == 0);
    /* "event"-prefixed non-devices do not match */
    CHECK(regexec(&evdev_reg, "event", 0, NULL, 0) != 0);
    CHECK(regexec(&evdev_reg, "eventfoo", 0, NULL, 0) != 0);
    CHECK(regexec(&evdev_reg, "event0a", 0, NULL, 0) != 0);
    CHECK(regexec(&evdev_reg, "event1.0", 0, NULL, 0) != 0);
    /* unrelated and degenerate names */
    CHECK(regexec(&evdev_reg, "mouse0", 0, NULL, 0) != 0);
    CHECK(regexec(&evdev_reg, "js0", 0, NULL, 0) != 0);
    CHECK(regexec(&evdev_reg, "", 0, NULL, 0) != 0);
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
 * (written from `content`, or truncated to that length when `content` is NULL)
 * but a compositor-declared `size`, with `old_map` as the previously-seen map.
 * Returns how the child terminated. */
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
    return classify_child(status);
}

/* kb_handle_keymap guards: a keymap with no NUL terminator in `size` bytes is a
 * malicious/garbage map and must exit(1), not be compiled; an adequate map that
 * matches the previously-seen one takes the early return without faulting. */
static void unit_kb_handle_keymap(void)
{
    /* Adequate fd whose content equals the previous map: the "same map" early
     * return completes cleanly. */
    CHECK(run_keymap_child("xkb", 4, 4, "xkb") == CH_EXIT0);

    /* Adequate fd with no NUL terminator in `size` bytes: the malicious-keymap
     * guard exits(1). */
    CHECK(run_keymap_child("abcd", 4, 4, NULL) == CH_EXIT1);
}

/* calc_next_led_state drives the global num/caps-lock 4-state counter and
 * returns the LED mask. Toggling a lock key press/release/press/release cycles
 * the LED on, on, on, off; a non-lock key leaves the state untouched. */
static void unit_calc_next_led_state(void)
{
    num_lock_state = 0;
    num_lock_held = false;
    caps_lock_state = 0;
    caps_lock_held = false;

    /* numlock: on after the first press, still on across the next three edges
     * until the fourth edge (second release) cycles it back off */
    CHECK(calc_next_led_state(KEY_NUMLOCK, LIBINPUT_KEY_STATE_PRESSED)
          & LIBINPUT_LED_NUM_LOCK);
    CHECK(calc_next_led_state(KEY_NUMLOCK, LIBINPUT_KEY_STATE_RELEASED)
          & LIBINPUT_LED_NUM_LOCK);
    CHECK(calc_next_led_state(KEY_NUMLOCK, LIBINPUT_KEY_STATE_PRESSED)
          & LIBINPUT_LED_NUM_LOCK);
    CHECK(!(calc_next_led_state(KEY_NUMLOCK, LIBINPUT_KEY_STATE_RELEASED)
            & LIBINPUT_LED_NUM_LOCK));

    /* capslock is independent; a non-lock key is a no-op on both states */
    CHECK(calc_next_led_state(KEY_CAPSLOCK, LIBINPUT_KEY_STATE_PRESSED)
          & LIBINPUT_LED_CAPS_LOCK);
    CHECK(calc_next_led_state(KEY_A, LIBINPUT_KEY_STATE_PRESSED)
          & LIBINPUT_LED_CAPS_LOCK);
    CHECK(!(calc_next_led_state(KEY_A, LIBINPUT_KEY_STATE_PRESSED)
            & LIBINPUT_LED_NUM_LOCK));
}

/* clamp_cursor pins the global cursor into [pointer_space_*, right/bottom_edge)
 * and reports whether it had to move it. */
static void unit_clamp_cursor(void)
{
    state.pointer_space_x = 0;
    state.pointer_space_y = 0;
    state.pointer_space_right_edge = 1920;
    state.pointer_space_bottom_edge = 1080;

    cursor_x = 100;
    cursor_y = 100;
    CHECK(!clamp_cursor());
    CHECK(cursor_x == 100 && cursor_y == 100);

    cursor_x = 5000;
    cursor_y = 5000;
    CHECK(clamp_cursor());
    CHECK(cursor_x == 1919 && cursor_y == 1079);

    cursor_x = -5;
    cursor_y = -5;
    CHECK(clamp_cursor());
    CHECK(cursor_x == 0 && cursor_y == 0);
}

/* make_virtual_cursor_pos_sane walks start->end avoiding voids. A move wholly
 * within one screen reaches its target unchanged. */
static void unit_make_virtual_cursor_pos_sane(void)
{
    struct output_geometry g0 = geom(0, 0, 1920, 1080);
    double cx = 0.0;
    double cy = 0.0;
    ssize_t i;

    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
    state.output_geometries[0] = &g0;

    cx = 200.0;
    cy = 200.0;
    make_virtual_cursor_pos_sane(100.0, 100.0, &cx, &cy);
    CHECK(cx == 200.0 && cy == 200.0);

    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
}

/* Append one inotify_event record (kernel-padded name) to buf, return the new
 * end offset. */
static ssize_t put_inotify(char *buf, ssize_t off, uint32_t mask,
                           const char *name)
{
    struct inotify_event *ie = (struct inotify_event *)(buf + off);
    uint32_t namelen = (uint32_t)(strlen(name) + 1U);

    namelen = (namelen + 7U) & ~7U; /* kernel aligns the name field */
    ie->wd = 1;
    ie->mask = mask;
    ie->cookie = 0;
    ie->len = namelen;
    memset(ie->name, 0, namelen);
    memcpy(ie->name, name, strlen(name));
    return off + (ssize_t)sizeof(struct inotify_event) + (ssize_t)namelen;
}

/* parse_inotify_events returns the next canonical event<N> node name in the
 * buffer, skips non-evdev and zero-length (IN_Q_OVERFLOW) records, and sets
 * do_attach from IN_CREATE. */
static void unit_parse_inotify_events(void)
{
    char buf[256];
    ssize_t len = 0;
    ssize_t pos = 0;
    bool do_attach = false;
    char *name = NULL;

    memset(buf, 0, sizeof(buf));
    applayer_regex_init();
    /* a genuine zero-length (IN_Q_OVERFLOW) record: no name field, must be
     * skipped with no over-read */
    ((struct inotify_event *)(buf))->mask = IN_Q_OVERFLOW;
    ((struct inotify_event *)(buf))->len = 0;
    len = (ssize_t)sizeof(struct inotify_event);
    len = put_inotify(buf, len, 0, "mouse0");         /* non-evdev: skipped */
    len = put_inotify(buf, len, IN_CREATE, "event5"); /* match */

    name = parse_inotify_events(buf, len, &pos, &do_attach);
    CHECK(name != NULL && strcmp(name, "event5") == 0 && do_attach);
    /* nothing left to match */
    name = parse_inotify_events(buf, len, &pos, &do_attach);
    CHECK(name == NULL);
}

/* Regression for two audit items that were OPEN at first report and are now
 * FIXED in arraybolt3/trixie (Whonix/kloak#24). Each pins the CORRECT value so
 * a revert of the fix trips the test.
 *   Item D: check_screen_touch must detect a cross/plus overlap where neither
 *     rectangle has a corner inside the other.
 *   Item F: recalc_global_space must store the SPAN (br_corner_x - ul_corner_x)
 *     as the width, with the origin tracked separately in pointer_space_x, when
 *     the leftmost output does not start at x=0. */
static void unit_cross_overlap_and_offset_global_space(void)
{
    struct output_geometry cross_a = geom(0, 400, 1920, 1080);
    struct output_geometry cross_b = geom(420, 0, 1080, 1920);
    struct output_geometry off_a = geom(100, 0, 1920, 1080);
    struct output_geometry off_b = geom(2020, 0, 1920, 1080);
    struct disp_state local = { 0 };

    /* Item D: these two overlap over x[420,1500) y[400,1480) with no shared
     * corner -- the AABB test must see them as touching. */
    CHECK(check_screen_touch(cross_a, cross_b));

    /* Item F: leftmost output at x=100; span is 3940-100 = 3840, origin 100. */
    local.output_geometries[0] = &off_a;
    local.output_geometries[1] = &off_b;
    CHECK(recalc_global_space(&local));
    CHECK(local.global_space_width == 3840);
    CHECK(local.pointer_space_x == 100);
}

/* recalc_global_space must REJECT (return false) a layout with a gap between
 * screens -- production turns that into the "gaps are present" fatal. Two
 * screens separated by a void do not connect. */
static void unit_recalc_global_space_gap(void)
{
    struct output_geometry g0 = geom(0, 0, 1920, 1080);
    struct output_geometry gapped = geom(3000, 0, 1920, 1080);
    struct disp_state local = { 0 };

    local.output_geometries[0] = &g0;
    local.output_geometries[1] = &gapped;
    CHECK(!recalc_global_space(&local));
}

/* A point covered by no screen (a void in global space) maps to an invalid
 * screen-local coordinate. */
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
    CHECK(!sl.valid);

    for (i = 0; i < MAX_SCREEN_COUNT; ++i) {
        state.output_geometries[i] = NULL;
    }
}

int main(void)
{
    unit_lookup_keycode();
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
    unit_evdev_regex();
    unit_kb_handle_keymap();
    unit_cross_overlap_and_offset_global_space();
    unit_recalc_global_space_gap();
    unit_abs_coord_invalid();
    unit_calc_next_led_state();
    unit_clamp_cursor();
    unit_make_virtual_cursor_pos_sane();
    unit_parse_inotify_events();
    printf("kloak harness: all assertions passed (%d checks)\n", checks);
    return 0;
}
