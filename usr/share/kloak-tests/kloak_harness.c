/*
SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted

Concrete unit tests + a light randomized fuzz for kloak's pure/testable
functions. Compiled and run by test_kloak_verification.py against the REAL
src/kloak.c (reusing kloak's KLOAK_FUZZING seam -- no kloak source change), then
linked with the wayland-scanner protocol code and the wayland/libinput/libevdev/
xkbcommon libraries exactly as kloak itself links. The Wayland/libinput code is
dead here (never called), so no compositor or input device is needed at runtime;
only the pure logic is exercised.

Complements kloak_cbmc.c: CBMC proves the invariants hold for ALL inputs in the
operating envelope; these assert the concrete, human-meaningful values and edges
(and catch a regression CBMC's envelope assumptions might mask).
*/
#define KLOAK_FUZZING
#include "kloak.c"

#include <assert.h>
#include <stdint.h>
#include <string.h>

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
    printf("kloak harness: all assertions passed (%d checks)\n", checks);
    return 0;
}
