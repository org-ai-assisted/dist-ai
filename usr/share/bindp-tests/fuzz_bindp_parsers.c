/*
   Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions.

   AI-Assisted

   libFuzzer harness for bindp's untrusted-input parsers (NOT a copy of the
   subject). #includes the REAL usr/src/bindp/bindp.c (resolved by the entrypoint
   via -I <BINDP_REPO>/usr/src/bindp) and drives its parsers with coverage-guided
   mutated bytes under ASAN + UBSAN:

     parse_int_flag      -- arbitrary NUL-terminated string -> must be 0 or 1
     get_address_family  -- arbitrary >=2-byte sockaddr prefix (2-byte read)
     _init BIND_ADDR / BIND_PORT / REUSE_* / IP_TRANSPARENT -- the env the shim
       trusts from its launching process: inet_aton, strtol -> in_port_t, and the
       flag parse. The reuse/transparent flags must stay in {0,1}.

   The CBMC proofs (bindp_cbmc.c) verify these functions exhaustively against
   MODELLED libc; this lane runs the REAL compiled code against the real libc
   (inet_aton / strtol), so ASAN/UBSAN catch any memory or undefined-behaviour
   issue a model cannot. bindp.c ships an unguarded main() and names its
   LD_PRELOAD constructor _init -- both reserved here -- so they are renamed
   around the include.
*/
#define _GNU_SOURCE

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Host LLVMFuzzerTestOneInput so the subject's reserved symbols do not collide. */
#define main bindp_subject_main
#define _init bindp_subject_init
#include "bindp.c"
#undef main
#undef _init

static void reset_state(void)
{
    bind_addr_saddr = 0;
    bind_port_saddr = 0;
    reuse_addr = 0;
    reuse_port = 0;
    ip_transparent = 0;
    unsetenv("BIND_ADDR");
    unsetenv("BIND_PORT");
    unsetenv("REUSE_ADDR");
    unsetenv("REUSE_PORT");
    unsetenv("IP_TRANSPARENT");
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* NUL-terminated copy for the string parsers (an embedded NUL just truncates
       the string, which is a valid input to exercise). */
    char *str = malloc(size + 1);
    if (str == NULL) {
        return 0;
    }
    memcpy(str, data, size);
    str[size] = '\0';

    int flag = parse_int_flag(str, "FUZZ");
    assert(flag == 0 || flag == 1);

    /* get_address_family reads the first 2 bytes as sa_family. */
    if (size >= sizeof(struct sockaddr)) {
        (void)get_address_family((const struct sockaddr *)data);
    }

    /* Drive _init's env parsing with the same fuzzed string in every slot. */
    reset_state();
    setenv("BIND_ADDR", str, 1);
    setenv("BIND_PORT", str, 1);
    setenv("REUSE_ADDR", str, 1);
    setenv("REUSE_PORT", str, 1);
    setenv("IP_TRANSPARENT", str, 1);
    bindp_subject_init();
    /* The flags are parse_int_flag outputs: must stay boolean. */
    assert(reuse_addr == 0 || reuse_addr == 1);
    assert(reuse_port == 0 || reuse_port == 1);
    assert(ip_transparent == 0 || ip_transparent == 1);
    reset_state();

    free(str);
    return 0;
}
