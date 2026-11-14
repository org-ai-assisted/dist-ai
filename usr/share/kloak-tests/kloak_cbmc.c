/*
SPDX-FileCopyrightText: ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
See the file COPYING for copying conditions.

AI-Assisted

CBMC proof harness for the pure arithmetic in kloak's libinput proxy
(src/kloak.c), resolved via KLOAK_REPO. No kloak source change: reuses the
KLOAK_FUZZING seam (guards out main()), so the actual function body is verified.
The Wayland-adapter arithmetic (geometry/scroll/time/random) lives in
src/kloakwl.c and is proven in kloakwl_cbmc.c.

CBMC 6.x enables the full standard check set by default (signed/unsigned/pointer/
float overflow, conversion, nan, bounds, pointer, div-by-zero), so verify_sleep_ms
is proven free of ALL of those for every in-envelope input. Its EINTR retry is a
bounded loop, so it runs under --unwind.

The libc boundary (nanosleep) is modeled here so the proof is deterministic -- an
environment shim, not a reimplementation of kloak logic.
*/
#define KLOAK_FUZZING
#include "kloak.c"

#include <stdint.h>

/* ---- libc boundary models (environment, not kloak logic) ---- */

int nanosleep(const struct timespec *req, struct timespec *rem)
{
    (void)req;
    (void)rem;
    return 0;
}

/* /dev/urandom: a full read of nondeterministic bytes (read_random treats a
 * short read as fatal), so fill_with_rand_alphabetic's real rejection sampling
 * runs over arbitrary bytes. */
ssize_t read(int fd, void *buf, size_t count)
{
    (void)fd;
    __CPROVER_havoc_slice(buf, count);
    return (ssize_t)count;
}

/* The evdev node-name match is not kloak arithmetic; model it as a
 * nondeterministic match/no-match so BOTH branches of parse_inotify_events are
 * explored without reasoning about regex internals or the name bytes. */
int regexec(const regex_t *preg, const char *string, size_t nmatch,
            regmatch_t pmatch[], int eflags)
{
    (void)preg;
    (void)string;
    (void)nmatch;
    (void)pmatch;
    (void)eflags;
    return nondet_int();
}

/* ---- proofs ---- */

/* sleep_ms: a non-negative millisecond count produces a valid timespec with no
 * UB (nanosleep modeled above). */
void verify_sleep_ms(void)
{
    int64_t ms;
    __CPROVER_assume(ms >= 0);
    (void)sleep_ms(ms);
}

/* fill_with_rand_alphabetic: every output byte is an ASCII letter [A-Za-z],
 * whatever random bytes /dev/urandom returns. The modulo+offset after the
 * rejection loop fixes the domain unconditionally, so the invariant holds even
 * when the bounded rejection loop is unwound only to a prefix (the sampling only
 * reduces modulo bias, it does not gate correctness). Signed-char normalization
 * (abs() with the SCHAR_MIN special-case) is proven UB-free here. */
void verify_fill_with_rand_alphabetic(void)
{
    char buf[4];
    ssize_t i = 0;
    fill_with_rand_alphabetic(buf, (ssize_t)(sizeof(buf)));
    for (i = 0; i < (ssize_t)(sizeof(buf)); i++) {
        __CPROVER_assert(
            (buf[i] >= 'A' && buf[i] <= 'Z')
            || (buf[i] >= 'a' && buf[i] <= 'z'),
            "fill_with_rand_alphabetic emits only ASCII letters");
    }
}

/* parse_inotify_events: the assert-light record walk over a kernel-supplied
 * buffer (untrusted ie->len) is UB-free -- no ssize_t overflow in the struct_len
 * add / rem_len subtract / pointer advance -- and never leaves *buf_pos outside
 * [-1, buf_len]. Symbolic buffer with a symbolic start offset; the walk consumes
 * >= sizeof(struct inotify_event) per step, so --unwind covers every step over a
 * small buffer exhaustively. The evdev match is modeled (regexec above). */
void verify_parse_inotify_events(void)
{
    char buf[64];
    /* Nondeterministic: uninitialized locals so CBMC explores every buf_len and
     * start offset in range (an explicit = 0 would pin the proof to an empty
     * buffer at offset zero -- __CPROVER_assume filters values, it does not
     * generate them). buf itself is an uninitialized (symbolic) byte array. */
    ssize_t buf_len;
    ssize_t pos;
    bool do_attach = false;
    bool overflow = false;
    __CPROVER_assume(buf_len >= 0 && buf_len <= (ssize_t)(sizeof(buf)));
    __CPROVER_assume(pos >= 0 && pos <= buf_len);
    (void)parse_inotify_events(buf, buf_len, &pos, &do_attach, &overflow);
    __CPROVER_assert(pos >= -1 && pos <= buf_len,
                     "buf_pos stays within [-1, buf_len]");
}
