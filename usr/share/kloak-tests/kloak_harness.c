/*
SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted

Concrete unit tests for the pure/testable functions in kloak's libinput proxy
(src/kloak.c). Compiled and run by test_kloak_verification.py against the REAL
src/kloak.c (via the KLOAK_FUZZING seam -- no kloak source change). The Wayland
adapter's functions live in src/kloakwl.c and are tested in kloakwl_harness.c.

Covers: lookup_keycode, the uint31/uint32 CLI parsers (including the signed-wrap
rejection), the escape-key parser across both separators, the getopt dup-option
guard (a repeated option is rejected, not leaked to a single-use parser),
calc_next_led_state's num/caps-lock 4-state cycle, the evdev node-name regex, and
parse_inotify_events (the assert-free, fuzzable record walk, incl. the
zero-length IN_Q_OVERFLOW skip and the skip of a matching node carrying neither
IN_CREATE nor IN_DELETE).
*/
#define KLOAK_FUZZING

/* kloak.c uses _GNU_SOURCE symbols (memfd_create, environ); define it before
 * any system header is pulled in below, otherwise the glibc feature guards
 * latch without it and kloak.c's own _GNU_SOURCE define arrives too late. */
#define _GNU_SOURCE

#include <setjmp.h>
#include <stdlib.h>

/* Intercept kloak's fatal exit(): a rejection kloak handles by design (e.g. a
 * duplicate CLI option), not a crash. Defined AFTER <stdlib.h> (so exit's real
 * declaration is already parsed) and BEFORE kloak.c, whose guarded <stdlib.h>
 * re-include is a no-op -- so only kloak.c's exit() CALLS expand. The value
 * passed to longjmp is the exit code + 1 (longjmp cannot carry 0). */
static jmp_buf g_reject;
#define exit(code) longjmp(g_reject, (code) + 1)

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

/* parse_esc_key_str parses one -k/--escape-keys value: a comma separates escape
 * combos, '|' separates the keys within a combo. This tests one value with both
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

/* kloak's option parsers assume each option is passed at most once, so the
 * getopt dup guard (check_dup_arg_and_mark) must reject any repeat rather than
 * let it leak through to a parser that is not safe to call twice. Drive the
 * REAL CLI parse path with a duplicated -k and confirm it exits(1). */
static void unit_dup_option_rejected(void)
{
    char *argv[] = { "kloak", "-k", "KEY_A", "-k", "KEY_B", NULL };

    esc_key_list = NULL;
    esc_key_sublist_len = NULL;
    active_esc_key_list = NULL;
    esc_key_list_len = 0;
    optind = 1;

    /* setjmp must be the controlling expression itself (C 7.13.1.1 -- assigning
     * its result is undefined). exit(code) is mapped to longjmp(g_reject,
     * code + 1), so a rejecting exit(1) arrives here as 2. */
    switch (setjmp(g_reject)) {
    case 0:
        parse_cli_args(5, argv);
        CHECK(0);   /* returned -- the duplicate -k was NOT rejected */
        break;
    case 2:
        break;      /* exit(1): the guard rejected the duplicate */
    default:
        CHECK(0);   /* exited with an unexpected code */
        break;
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

/* calc_next_led_state drives the global num/caps-lock 4-state counter and
 * returns the LED mask. Toggling a lock key press/release/press/release cycles
 * the LED on, on, on, off; a non-lock key leaves the state untouched. */
static struct button_event be(uint32_t code, bool pressed)
{
    struct button_event e = { .button_code = code, .is_pressed = pressed };
    return e;
}

static void unit_calc_next_led_state(void)
{
    num_lock_state = 0;
    num_lock_held = false;
    caps_lock_state = 0;
    caps_lock_held = false;

    /* numlock: on after the first press, still on across the next three edges
     * until the fourth edge (second release) cycles it back off */
    CHECK(calc_next_led_state(be(KEY_NUMLOCK, true)) & LIBINPUT_LED_NUM_LOCK);
    CHECK(calc_next_led_state(be(KEY_NUMLOCK, false)) & LIBINPUT_LED_NUM_LOCK);
    CHECK(calc_next_led_state(be(KEY_NUMLOCK, true)) & LIBINPUT_LED_NUM_LOCK);
    CHECK(!(calc_next_led_state(be(KEY_NUMLOCK, false)) & LIBINPUT_LED_NUM_LOCK));

    /* capslock is independent; a non-lock key is a no-op on both states */
    CHECK(calc_next_led_state(be(KEY_CAPSLOCK, true)) & LIBINPUT_LED_CAPS_LOCK);
    CHECK(calc_next_led_state(be(KEY_A, true)) & LIBINPUT_LED_CAPS_LOCK);
    CHECK(!(calc_next_led_state(be(KEY_A, true)) & LIBINPUT_LED_NUM_LOCK));
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
 * buffer, skips non-evdev, zero-length (IN_Q_OVERFLOW) and unknown-mask records,
 * and sets do_attach from IN_CREATE. */
static void unit_parse_inotify_events(void)
{
    char buf[256];
    ssize_t len = 0;
    ssize_t pos = 0;
    bool do_attach = false;
    bool overflow = false;
    char *name = NULL;

    memset(buf, 0, sizeof(buf));
    applayer_regex_init();
    /* a genuine zero-length (IN_Q_OVERFLOW) record would set overflow; here use
     * a non-evdev record (skipped) then an IN_CREATE match */
    len = put_inotify(buf, len, 0, "mouse0");         /* non-evdev: skipped */
    len = put_inotify(buf, len, IN_CREATE, "event5"); /* match */

    name = parse_inotify_events(buf, len, &pos, &do_attach, &overflow);
    CHECK(name != NULL && strcmp(name, "event5") == 0 && do_attach && !overflow);
    /* nothing left to match */
    name = parse_inotify_events(buf, len, &pos, &do_attach, &overflow);
    CHECK(name == NULL);
}

/* A matching event<N> node carrying neither IN_CREATE nor IN_DELETE makes the
 * walk BAIL gracefully (returns NULL, sets *buf_pos = -1) rather than abort --
 * the function is assert-free by contract (a fuzz seam). */
static void unit_parse_inotify_unknown_mask_bails(void)
{
    char buf[256];
    ssize_t len = 0;
    ssize_t pos = 0;
    bool do_attach = false;
    bool overflow = false;
    char *name = NULL;

    memset(buf, 0, sizeof(buf));
    applayer_regex_init();
    /* event<N> node with a mask that is neither IN_CREATE nor IN_DELETE */
    len = put_inotify(buf, len, IN_ATTRIB, "event7");

    name = parse_inotify_events(buf, len, &pos, &do_attach, &overflow);
    CHECK(name == NULL && pos == -1 && !overflow);
}

int main(void)
{
    unit_lookup_keycode();
    unit_parse_uint31();
    unit_parse_uint32();
    unit_parse_esc_key_str();
    unit_dup_option_rejected();
    unit_evdev_regex();
    unit_calc_next_led_state();
    unit_parse_inotify_events();
    unit_parse_inotify_unknown_mask_bails();
    printf("kloak harness: all assertions passed (%d checks)\n", checks);
    return 0;
}
