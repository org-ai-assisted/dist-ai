/*
   Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions.

   AI-Assisted

   Per-function unit harness for bindp (NOT a copy of the subject). #includes the
   REAL usr/src/bindp/bindp.c (resolved by the test via -I <BINDP_REPO>/usr/src/
   bindp) and calls its functions DIRECTLY, so each parser/helper gets exhaustive
   input coverage without LD_PRELOAD or a live socket:

     parse_int_flag   -- 0/1 accepted, everything else -> 0
     get_address_family -- reads the 2-byte sa_family field
     _init BIND_PORT  -- strtol -> in_port_t, in-range applied, out-of-range dropped
     _init BIND_ADDR  -- inet_aton, valid applied, invalid left untouched
     _init REUSE_ADDR, REUSE_PORT, IP_TRANSPARENT -- parsed like parse_int_flag

   The shipped libindp.so is linked -Wl,-z,nodlopen (LD_PRELOAD only), so ctypes/
   dlopen cannot load it; including the source is how the functions are reached.
   bindp.c ships an unguarded main() and names its LD_PRELOAD constructor _init --
   both reserved in a linked executable -- so they are renamed around the include.

   Usage: bindp_unit <category>
     parse_flag | family | init_port | init_addr | init_flags
   Prints one "FAIL: ..." line per failed assertion and a final
   "cases=<n> failures=<m>" tally; exit 0 iff failures==0 (2 = bad usage).
*/
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

/* Host main()/_init so the subject's reserved symbols do not collide. */
#define main bindp_subject_main
#define _init bindp_subject_init
#include "bindp.c"
#undef main
#undef _init

static int g_cases;
static int g_failures;

static void check_int(const char *what, long got, long want)
{
    g_cases++;
    if (got != want) {
        g_failures++;
        printf("FAIL: %s -> got %ld want %ld\n", what, got, want);
    }
}

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

static void run_parse_flag(void)
{
    static const char *invalid[] = {
        "2", "", "01", "00", " 1", "1 ", "true", "yes", "10", "-1", "+1",
        "x", "1x", "11", NULL };
    check_int("parse_int_flag(\"0\")", parse_int_flag("0", "FLAG"), 0);
    check_int("parse_int_flag(\"1\")", parse_int_flag("1", "FLAG"), 1);
    for (int i = 0; invalid[i] != NULL; i++) {
        char what[64];
        snprintf(what, sizeof(what), "parse_int_flag(\"%s\")", invalid[i]);
        check_int(what, parse_int_flag(invalid[i], "FLAG"), 0);
    }
}

static void run_family(void)
{
    static const unsigned short fams[] = {
        AF_INET, AF_UNIX, AF_INET6, AF_UNSPEC, 0x1234, 0xFFFF };
    for (size_t i = 0; i < sizeof(fams) / sizeof(fams[0]); i++) {
        unsigned char buf[16];
        memset(buf, 0, sizeof(buf));
        memcpy(buf, &fams[i], sizeof(fams[i]));
        char what[48];
        snprintf(what, sizeof(what), "get_address_family(0x%x)", fams[i]);
        check_int(what, get_address_family((const struct sockaddr *)buf),
                  fams[i]);
    }
}

static void init_port(const char *value, long want)
{
    reset_state();
    setenv("BIND_PORT", value, 1);
    bindp_subject_init();
    char what[48];
    snprintf(what, sizeof(what), "BIND_PORT=%s", value);
    check_int(what, bind_port_saddr, want);
}

static void run_init_port(void)
{
    init_port("1", 1);
    init_port("80", 80);
    init_port("443", 443);
    init_port("1024", 1024);
    init_port("49888", 49888);
    init_port("65535", 65535);
    /* Out of range -> left at the reset 0 (not applied). */
    init_port("65536", 0);
    init_port("70000", 0);
    init_port("-1", 0);
    init_port("99999", 0);
    init_port("2147483648", 0);
    init_port("4294967296", 0);
}

static void init_addr_valid(const char *value)
{
    reset_state();
    setenv("BIND_ADDR", value, 1);
    bindp_subject_init();
    struct in_addr expected;
    inet_aton(value, &expected);
    char what[48];
    snprintf(what, sizeof(what), "BIND_ADDR=%s", value);
    check_int(what, bind_addr_saddr, expected.s_addr);
}

static void init_addr_invalid(const char *value)
{
    reset_state();
    setenv("BIND_ADDR", value, 1);
    bindp_subject_init();
    char what[48];
    snprintf(what, sizeof(what), "BIND_ADDR=%s (invalid)", value);
    /* Invalid -> the else branch never assigns bind_addr_saddr: stays 0. */
    check_int(what, bind_addr_saddr, 0);
}

static void run_init_addr(void)
{
    init_addr_valid("127.0.0.1");
    init_addr_valid("10.0.0.5");
    init_addr_valid("192.168.1.1");
    init_addr_valid("8.8.8.8");
    /*
       inet_aton accepts the short forms (a, a.b, a.b.c), so those are NOT
       invalid; only an out-of-range octet or non-numeric garbage is.
    */
    init_addr_invalid("256.1.1.1");
    init_addr_invalid("garbage");
    init_addr_invalid("");
    init_addr_invalid("999.999.999.999");
    init_addr_invalid("1.2.3.4.5");
}

static void init_flag(const char *env_key, const char *value, int *global,
                      long want)
{
    reset_state();
    setenv(env_key, value, 1);
    bindp_subject_init();
    char what[48];
    snprintf(what, sizeof(what), "%s=%s", env_key, value);
    check_int(what, *global, want);
}

static void run_init_flags(void)
{
    struct {
        const char *key;
        int *global;
    } flags[] = {
        { "REUSE_ADDR", &reuse_addr },
        { "REUSE_PORT", &reuse_port },
        { "IP_TRANSPARENT", &ip_transparent },
    };
    static const char *bad[] = { "2", "", "yes", "-1", NULL };
    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        init_flag(flags[i].key, "1", flags[i].global, 1);
        init_flag(flags[i].key, "0", flags[i].global, 0);
        for (int j = 0; bad[j] != NULL; j++) {
            init_flag(flags[i].key, bad[j], flags[i].global, 0);
        }
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <category>\n", argv[0]);
        return 2;
    }
    const char *category = argv[1];
    if (strcmp(category, "parse_flag") == 0) {
        run_parse_flag();
    } else if (strcmp(category, "family") == 0) {
        run_family();
    } else if (strcmp(category, "init_port") == 0) {
        run_init_port();
    } else if (strcmp(category, "init_addr") == 0) {
        run_init_addr();
    } else if (strcmp(category, "init_flags") == 0) {
        run_init_flags();
    } else {
        fprintf(stderr, "unknown category '%s'\n", category);
        return 2;
    }
    printf("cases=%d failures=%d\n", g_cases, g_failures);
    return g_failures == 0 ? 0 : 1;
}
