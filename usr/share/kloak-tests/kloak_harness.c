/*
SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted

Concrete unit tests for the pure/testable functions in kloak's libinput proxy
(src/kloak.c). Compiled and run by test_kloak_verification.py against the REAL
src/kloak.c (via the KLOAK_FUZZING seam -- no kloak source change). The Wayland
adapter's functions live in src/kloakwl.c and are tested in kloakwl_harness.c.

Covers: lookup_keycode, the uint31/uint32 CLI parsers (signed-wrap AND strtoul
ERANGE rejection), the escape-key parser across both separators and its malformed
-value rejections, register_esc_combo_event (the teardown trigger: combo
activation, the underflow clamp, and the all-combos-held exit), the getopt
dup-option guard (a repeated option is rejected, not leaked to a single-use
parser), calc_next_led_state's num/caps-lock 4-state cycle, fill_with_rand_alphabetic's
[A-Za-z] invariant, the evdev node-name regex, and parse_inotify_events (the
assert-free, fuzzable record walk: the IN_CREATE/IN_DELETE attach flag, the
IN_Q_OVERFLOW signal, and the bail on a matching node carrying neither).
*/
#define KLOAK_FUZZING

/* kloak.c uses _GNU_SOURCE symbols (memfd_create, environ); define it before
 * any system header is pulled in below, otherwise the glibc feature guards
 * latch without it and kloak.c's own _GNU_SOURCE define arrives too late. */
#define _GNU_SOURCE

#include <setjmp.h>
#include <stdlib.h>
#include <err.h>

/* Intercept kloak's fatal exits: a rejection kloak handles by design (e.g. a
 * duplicate CLI option), not a crash. kloak routes fatals both through exit()
 * and through <err.h> (err()/errx()), whose libc exit() would otherwise escape
 * an exit()-only macro -- so intercept all three. Defined AFTER the real
 * declarations are parsed (<stdlib.h>, <err.h>) and BEFORE kloak.c, whose
 * guarded re-includes are a no-op, so only kloak.c's CALLS expand. The value
 * passed to longjmp is the exit code + 1 (longjmp cannot carry 0). warn()/
 * warnx() are non-fatal and deliberately left alone. */
static jmp_buf g_reject;
#define exit(code) longjmp(g_reject, (code) + 1)
#define err(code, ...) longjmp(g_reject, (code) + 1)
#define errx(code, ...) longjmp(g_reject, (code) + 1)

#include "kloak.c"

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

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

/* parse_uint_arg caps at an explicit max_val and writes a uint32_t. The suite
 * covers both envelopes kloak uses it in: INT32_MAX (max_delay, startup delay)
 * and UINT32_MAX (cursor color). */
static void unit_parse_uint31(void)
{
    uint32_t v = 0;
    CHECK(parse_uint_arg("0", 10, INT32_MAX, &v) && v == 0);
    CHECK(parse_uint_arg("2147483647", 10, INT32_MAX, &v)
          && v == (uint32_t)INT32_MAX);
    CHECK(parse_uint_arg("ff", 16, INT32_MAX, &v) && v == 255);
    /* > max_val rejected */
    CHECK(!parse_uint_arg("2147483648", 10, INT32_MAX, &v));
    /* empty, trailing junk, and a negative all rejected */
    CHECK(!parse_uint_arg("", 10, INT32_MAX, &v));
    CHECK(!parse_uint_arg("12x", 10, INT32_MAX, &v));
    CHECK(!parse_uint_arg("-1", 10, INT32_MAX, &v));
    /* A leading '-' that strtoul would wrap to a SMALL in-range value must still
     * be rejected (the explicit '-' guard, not the range check). */
    CHECK(!parse_uint_arg("-18446744073709551615", 10, INT32_MAX, &v));
    /* A positive value exceeding ULONG_MAX makes strtoul set ERANGE; the
     * errno==ERANGE guard (AGENTS.md) must reject it on its own, reached before
     * any max_val range check. */
    CHECK(!parse_uint_arg("99999999999999999999999999", 10, INT32_MAX, &v));
}

static void unit_parse_uint32(void)
{
    uint32_t v = 0;
    CHECK(parse_uint_arg("0", 10, UINT32_MAX, &v) && v == 0);
    CHECK(parse_uint_arg("4294967295", 10, UINT32_MAX, &v) && v == UINT32_MAX);
    /* > max_val rejected */
    CHECK(!parse_uint_arg("4294967296", 10, UINT32_MAX, &v));
    CHECK(!parse_uint_arg("", 10, UINT32_MAX, &v));
    CHECK(!parse_uint_arg("x", 10, UINT32_MAX, &v));
    CHECK(!parse_uint_arg("-18446744073709551615", 10, UINT32_MAX, &v));
    /* strtoul ERANGE (value > ULONG_MAX) rejected even at the widest cap. */
    CHECK(!parse_uint_arg("99999999999999999999999999", 10, UINT32_MAX, &v));
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

/* Each malformed -k/--escape-keys value must be rejected by errx(1) (arriving
 * here as g_reject code 2), not silently accepted: an empty combo, an empty key
 * within a combo, and an unrecognized key name. */
static void expect_esc_reject(const char *spec)
{
    esc_key_list = NULL;
    esc_key_sublist_len = NULL;
    active_esc_key_list = NULL;
    esc_key_list_len = 0;

    switch (setjmp(g_reject)) {
    case 0:
        parse_esc_key_str(spec);
        CHECK(0);   /* accepted a malformed spec */
        break;
    case 2:
        break;      /* errx(1) -> code 2: rejected as expected */
    default:
        CHECK(0);   /* rejected with an unexpected code */
        break;
    }
}

static void unit_parse_esc_key_str_errors(void)
{
    expect_esc_reject("");                 /* empty root token */
    expect_esc_reject("KEY_A,");           /* trailing empty root token */
    expect_esc_reject("KEY_RIGHTSHIFT|");  /* empty sub-token within a combo */
    expect_esc_reject("KEY_BOGUS");        /* unrecognized key name */
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

/* register_esc_combo_event is kloak's teardown trigger: it counts how many keys
 * of each escape combo are currently held and exits(0) once EVERY combo has at
 * least one key down. A release with no matching press must clamp the per-combo
 * count to 0 (warn, not go negative), and a key in no combo is ignored. */
static void unit_register_esc_combo(void)
{
    esc_key_list = NULL;
    esc_key_sublist_len = NULL;
    active_esc_key_list = NULL;
    esc_key_list_len = 0;
    /* combo 0 = [KEY_A]; combo 1 = chord [KEY_RIGHTSHIFT | KEY_B]. */
    parse_esc_key_str("KEY_A,KEY_RIGHTSHIFT|KEY_B");

    /* a lone combo-0 press activates only combo 0 -- not every combo, no exit */
    register_esc_combo_event(be(KEY_A, true));
    CHECK(active_esc_key_list[0] == 1);
    CHECK(active_esc_key_list[1] == 0);

    /* release clears combo 0 ... */
    register_esc_combo_event(be(KEY_A, false));
    CHECK(active_esc_key_list[0] == 0);
    /* ... and an extra (unmatched) release clamps to 0, never negative */
    register_esc_combo_event(be(KEY_A, false));
    CHECK(active_esc_key_list[0] == 0);

    /* a key belonging to no combo is ignored */
    register_esc_combo_event(be(KEY_C, true));
    CHECK(active_esc_key_list[0] == 0 && active_esc_key_list[1] == 0);

    /* with combo 0 held, activating combo 1 makes EVERY combo active ->
     * errx(0) -> g_reject code 1 (the escape-combo teardown). */
    register_esc_combo_event(be(KEY_A, true));
    switch (setjmp(g_reject)) {
    case 0:
        register_esc_combo_event(be(KEY_RIGHTSHIFT, true));
        CHECK(0);   /* did not exit with every combo held down */
        break;
    case 1:
        break;      /* errx(0) -> code 1: escape combo fired */
    default:
        CHECK(0);   /* exited with an unexpected code */
        break;
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

/* An IN_Q_OVERFLOW record (the kernel dropped events) must set *overflow and
 * stop the walk with NULL so the caller can rescan /dev/input from scratch. */
static void unit_parse_inotify_overflow(void)
{
    char buf[256];
    ssize_t len = 0;
    ssize_t pos = 0;
    bool do_attach = false;
    bool overflow = false;
    char *name = NULL;

    memset(buf, 0, sizeof(buf));
    applayer_regex_init();
    len = put_inotify(buf, len, IN_Q_OVERFLOW, "");

    name = parse_inotify_events(buf, len, &pos, &do_attach, &overflow);
    CHECK(name == NULL && overflow);
}

/* A canonical event<N> node that was REMOVED (IN_DELETE) returns its name with
 * do_attach cleared, so the caller detaches the grab rather than re-grabbing. */
static void unit_parse_inotify_delete(void)
{
    char buf[256];
    ssize_t len = 0;
    ssize_t pos = 0;
    bool do_attach = true;    /* start true so the clear to false is observable */
    bool overflow = false;
    char *name = NULL;

    memset(buf, 0, sizeof(buf));
    applayer_regex_init();
    len = put_inotify(buf, len, IN_DELETE, "event6");

    name = parse_inotify_events(buf, len, &pos, &do_attach, &overflow);
    CHECK(name != NULL && strcmp(name, "event6") == 0 && !do_attach
          && !overflow);
}

/* fill_with_rand_alphabetic's modulo-bias normalization (subtle signed-char
 * arithmetic, see kloak-shared.h) must only ever emit ASCII letters. Drive the
 * REAL /dev/urandom path and assert every byte is [A-Za-z]. */
static void unit_fill_with_rand_alphabetic(void)
{
    char buf[64];
    ssize_t i = 0;
    unsigned char c = 0;

    init_fd_urandom();
    memset(buf, 0, sizeof(buf));
    fill_with_rand_alphabetic(buf, (ssize_t)(sizeof(buf)));
    for (i = 0; i < (ssize_t)(sizeof(buf)); i++) {
        c = (unsigned char)(buf[i]);
        CHECK((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
    }
}

/* Regression for Whonix/kloak#34 (the busy-loop coupled to the #35 degraded
 * path). applayer_poll_init must stop watching the child pipe (ev_fds[2]) when
 * the Wayland connect failed: in degraded mode the child has already exited, so
 * its pipe only ever reports POLLHUP, and the main loop services ev_fds[2] only
 * under `if (wl_connect_success)` -- so a watched dead pipe returns instantly
 * every iteration and spins at 100% CPU. A negative fd makes poll ignore it.
 * Old code set ev_fds[2].fd = recv_read_fd unconditionally. Needs a real
 * (device-less) libinput context, since applayer_poll_init reads
 * libinput_get_fd(li). */
static void unit_degraded_poll_skips_dead_pipe(void)
{
    li = libinput_path_create_context(&li_interface, NULL);
    assert(li != NULL);
    inotify_fd = -1;    /* stored into ev_fds[1].fd; value is otherwise unused */
    recv_read_fd = 42;  /* the fd a non-degraded run would watch */

    wl_connect_success = true;
    applayer_poll_init();
    CHECK(ev_fds[2].fd == recv_read_fd);
    free(ev_fds);
    ev_fds = NULL;

    wl_connect_success = false;
    applayer_poll_init();
    CHECK(ev_fds[2].fd == -1);
    free(ev_fds);
    ev_fds = NULL;

    libinput_unref(li);
    li = NULL;
}

/* Regression (Whonix/kloak#41): li_open_restricted must honor libinput's
 * open_restricted contract -- return -errno on a device it cannot open, not
 * fatally exit. A device vanishing between inotify IN_CREATE and
 * attach_input_device would otherwise tear kloak down and release every device
 * grab, de-anonymizing input. The pre-fix fatal safe_open arrives here as a
 * reject (exit code + 1 via the g_reject longjmp). */
static void unit_li_open_restricted_missing_returns_errno(void)
{
    int r = 0;
    switch (setjmp(g_reject)) {
    case 0:
        wl_connect_success = false;
        r = li_open_restricted("/nonexistent/kloak/device", O_RDONLY, NULL);
        CHECK(r == -ENOENT);   /* returned the contract error, did not exit */
        break;
    default:
        CHECK(0);              /* fatally exited on a missing device -- the bug */
        break;
    }
}

/* The parent->child PTC wire protocol was tested only from the CHILD side, by
 * frames the kloakwl harness BUILDS BY HAND -- nothing ran the REAL parent
 * serializer send_msg_to_peer and checked its bytes, so a drift in the
 * serializer (field order/width, the uint8 pressed encoding) would break
 * production while the hand-built frame and the child's parser stayed mutually
 * consistent (silent green). Run the REAL serializer and pin its output bytes to
 * the documented layout. (The reverse direction -- the parent decoding the
 * untrusted child's CTP packets -- is covered by fuzz_kloak_child_msg.) */
static void unit_wire_byte_contract(void)
{
    int spipe[2];
    unsigned char buf[64];
    size_t pos = 0;
    ssize_t n = 0;
    enum ptc_packet_type ptype = 0;
    uint32_t code = 0;
    uint8_t pressed = 0;
    double gx = 0.0;
    double gy = 0.0;
    struct button_event ev = be(272u, true);
    struct double_coord dc = { .x = 3.0, .y = -4.0 };

    CHECK(pipe(spipe) == 0);
    send_write_fd = spipe[1];

    /* Click/key layout: [enum ptc_packet_type][uint32 code][uint8 pressed]. */
    send_msg_to_peer(PTC_PACKET_CLICK_EVENT, 1, &ev);
    n = read(spipe[0], buf, sizeof(buf));
    CHECK(n == (ssize_t)(sizeof(enum ptc_packet_type) + sizeof(uint32_t)
        + sizeof(uint8_t)));
    pos = 0;
    memcpy(&ptype, buf + pos, sizeof(ptype));
    pos += sizeof(ptype);
    memcpy(&code, buf + pos, sizeof(code));
    pos += sizeof(code);
    pressed = buf[pos];
    CHECK(ptype == PTC_PACKET_CLICK_EVENT);
    CHECK(code == 272u);
    CHECK(pressed == 1);

    /* Cursor/scroll layout: [enum ptc_packet_type][double x][double y]. */
    send_msg_to_peer(PTC_PACKET_CURSOR_REL_EVENT, 1, &dc);
    n = read(spipe[0], buf, sizeof(buf));
    CHECK(n == (ssize_t)(sizeof(enum ptc_packet_type) + sizeof(double) * 2));
    pos = 0;
    memcpy(&ptype, buf + pos, sizeof(ptype));
    pos += sizeof(ptype);
    memcpy(&gx, buf + pos, sizeof(gx));
    pos += sizeof(gx);
    memcpy(&gy, buf + pos, sizeof(gy));
    CHECK(ptype == PTC_PACKET_CURSOR_REL_EVENT);
    CHECK(gx == 3.0 && gy == -4.0);

    CHECK(close(spipe[0]) == 0);
    CHECK(close(spipe[1]) == 0);
    send_write_fd = -1;
}

int main(void)
{
    unit_lookup_keycode();
    unit_wire_byte_contract();
    unit_parse_uint31();
    unit_parse_uint32();
    unit_parse_esc_key_str();
    unit_parse_esc_key_str_errors();
    unit_register_esc_combo();
    unit_dup_option_rejected();
    unit_evdev_regex();
    unit_calc_next_led_state();
    unit_parse_inotify_events();
    unit_parse_inotify_unknown_mask_bails();
    unit_parse_inotify_overflow();
    unit_parse_inotify_delete();
    unit_fill_with_rand_alphabetic();
    unit_degraded_poll_skips_dead_pipe();
    unit_li_open_restricted_missing_returns_errno();
    printf("kloak harness: all assertions passed (%d checks)\n", checks);
    return 0;
}
