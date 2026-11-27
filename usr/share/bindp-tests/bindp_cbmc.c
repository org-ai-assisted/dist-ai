/*
   Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions.

   AI-Assisted

   CBMC formal-verification harness for bindp (usr/src/bindp/bindp.c).

   #includes the REAL source (its directory is supplied by the driver via
   `cbmc -I <src_dir>`, so only the bare filename is hard-coded here -- never a
   copy) and proves, one verify_* entry per `cbmc --function`, memory safety and
   arithmetic correctness of the interposed bind()/connect() paths, the env
   parsing, and the SO_DOMAIN family gate. bindp is loop-free interposer
   arithmetic, so each proof is EXHAUSTIVE (no --unwind needed).

   The definitions below MODEL libc/syscalls CBMC cannot execute (environment,
   not bindp logic): getenv, inet_aton, __isoc23_strtol, dlsym/dlerror,
   getsockopt (reports a controllable socket domain), setsockopt (counts
   invocations so the option gate can be proved), and the real_bind/real_connect
   pass-throughs.
*/
#define _GNU_SOURCE

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

/* ---- nondet generators (undefined -> CBMC returns a fresh symbolic value) ---- */
int nondet_int(void);
unsigned int nondet_uint(void);
long nondet_long(void);
unsigned short nondet_ushort(void);
char nondet_char(void);

/*
   Controllable environment state, set by each proof before it calls into bindp.
   g_sock_domain / g_getsockopt_rc steer the modeled SO_DOMAIN query so a proof
   can pin the socket's real family and exercise both the query-ok and
   query-failed (fall back to caller family) paths. g_setsockopt_calls counts
   IP-option applications; g_set_reuseaddr / g_set_reuseport / g_set_iptransparent
   record WHICH specific option was requested, so a proof asserts each one was
   applied (not merely that some setsockopt happened).
*/
int g_sock_domain = 0;
int g_getsockopt_rc = 0;
int g_setsockopt_calls = 0;
int g_set_reuseaddr = 0;
int g_set_reuseport = 0;
int g_set_iptransparent = 0;

/* ---- libc / syscall models (environment, not bindp logic) ---- */

char *getenv(const char *name) {
    (void)name;
    if (nondet_int()) {
        return (char *)0;               /* variable unset */
    }
    /* A bounded, always NUL-terminated symbolic string: any value bindp may
       read, without an unbounded/over-read. _init uses each returned pointer
       immediately, so one reused buffer is sound. */
    static char buf[8];
    for (int i = 0; i < 7; i++) {
        buf[i] = nondet_char();
    }
    buf[7] = '\0';
    return buf;
}

int inet_aton(const char *cp, struct in_addr *inp) {
    (void)cp;
    inp->s_addr = (in_addr_t)nondet_uint();  /* value is irrelevant to safety */
    return nondet_int() ? 1 : 0;             /* explore parse-ok and parse-fail */
}

/*
   glibc redirects strtol() to __isoc23_strtol under C23, which CBMC has no
   body for. Model the contract bindp relies on: a nondet result with errno
   either clear or ERANGE, so both the in-range and rejected BIND_PORT paths
   are explored.
*/
long __isoc23_strtol(const char *nptr, char **endptr, int base) {
    (void)nptr;
    (void)endptr;
    (void)base;
    errno = nondet_int() ? 0 : ERANGE;
    return nondet_long();
}

void *dlsym(void *handle, const char *symbol) {
    (void)handle;
    (void)symbol;
    static int anchor;
    return &anchor;                         /* non-NULL; real_* set directly below */
}

char *dlerror(void) {
    return (char *)0;                       /* no loader error */
}

int getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen) {
    (void)fd;
    (void)optlen;
    /* The family gate is only sound if bindp asks for the socket DOMAIN. Assert
       the exact query so a proof cannot pass on a wrong level/optname (e.g. a
       SO_TYPE query the model would otherwise answer with g_sock_domain). */
    __CPROVER_assert(level == SOL_SOCKET && optname == SO_DOMAIN,
        "bindp queries the socket family via SOL_SOCKET/SO_DOMAIN");
    if (g_getsockopt_rc == 0) {
        *(int *)optval = g_sock_domain;
        return 0;
    }
    return -1;
}

int setsockopt(int fd, int level, int optname, const void *optval,
    socklen_t optlen) {
    (void)fd;
    (void)optval;
    (void)optlen;
    g_setsockopt_calls++;
    /* Record the SPECIFIC option so a proof asserts each configured option was
       requested, not merely that one setsockopt call happened. */
    if (level == SOL_SOCKET && optname == SO_REUSEADDR) {
        g_set_reuseaddr = 1;
    }
    if (level == SOL_SOCKET && optname == SO_REUSEPORT) {
        g_set_reuseport = 1;
    }
    if (level == SOL_IP && optname == IP_TRANSPARENT) {
        g_set_iptransparent = 1;
    }
    return nondet_int();
}

static int model_real_bind(int fd, const struct sockaddr *sk, socklen_t sl) {
    (void)fd;
    (void)sk;
    (void)sl;
    return nondet_int();
}

static int model_real_connect(int fd, const struct sockaddr *sk, socklen_t sl) {
    (void)fd;
    (void)sk;
    (void)sl;
    return nondet_int();
}

#include "bindp.c"

/* Reset the mutable bindp globals to a known base before each proof. */
static void reset_bindp_state(void) {
    real_bind = model_real_bind;
    real_connect = model_real_connect;
    bind_addr_saddr = 0;
    bind_port_saddr = 0;
    reuse_addr = 0;
    reuse_port = 0;
    ip_transparent = 0;
    g_setsockopt_calls = 0;
    g_set_reuseaddr = 0;
    g_set_reuseport = 0;
    g_set_iptransparent = 0;
}

/* parse_int_flag maps any NUL-terminated string to exactly 0 or 1. */
void verify_parse_int_flag(void) {
    char s[8];
    for (int i = 0; i < 7; i++) {
        s[i] = nondet_char();
    }
    s[7] = '\0';
    int32_t rv = parse_int_flag(s, "FLAG");
    __CPROVER_assert(rv == 0 || rv == 1,
        "parse_int_flag returns only 0 or 1");
}

/*
   _init over arbitrary environment: memory-safe (default checks), the parsed
   reuse flags stay in {0,1}, and -- via --conversion-check -- the
   strtol -> (in_port_t) BIND_PORT cast never truncates an in-range value.

   SCOPE: the modeled getenv returns an up-to-SEVEN-character symbolic string
   (an 8-byte NUL-terminated buffer), and __isoc23_strtol is modeled by its
   CONTRACT (nondet result, errno clear or ERANGE). So this proves the numeric
   CONVERSION path over every strtol outcome, NOT the textual parsing of
   unbounded BIND_PORT strings (e.g. "000000008080" is outside the 7-char model).
*/
void verify_init_env_parsing(void) {
    reset_bindp_state();
    _init();
    __CPROVER_assert(reuse_addr == 0 || reuse_addr == 1,
        "reuse_addr parsed into {0,1}");
    __CPROVER_assert(reuse_port == 0 || reuse_port == 1,
        "reuse_port parsed into {0,1}");
    __CPROVER_assert(ip_transparent == 0 || ip_transparent == 1,
        "ip_transparent parsed into {0,1}");
}

/*
   get_address_family reads exactly the sa_family field and nothing past it.
   Back it with an object that ENDS at the family field (not a full sockaddr_in)
   so --bounds-check makes any read beyond those two bytes FAIL the proof.
*/
void verify_get_address_family(void) {
    unsigned short fam = nondet_ushort();
    unsigned short f = get_address_family((struct sockaddr *)&fam);
    __CPROVER_assert(f == fam,
        "get_address_family reads the sockaddr family field, in bounds");
}

/*
   bind() over a well-formed AF_INET sockaddr with both SO_DOMAIN outcomes and
   an arbitrary reported domain: memory safe (no OOB write to the caller
   sockaddr, no bad pointer/overflow), whatever the rewrite globals hold.
*/
void verify_bind_inet_memory_safety(void) {
    reset_bindp_state();
    bind_addr_saddr = (in_addr_t)nondet_uint();
    bind_port_saddr = nondet_ushort();
    reuse_addr = nondet_int() ? 1 : 0;
    reuse_port = nondet_int() ? 1 : 0;
    ip_transparent = nondet_int() ? 1 : 0;
    g_getsockopt_rc = nondet_int() ? 0 : -1;
    g_sock_domain = nondet_int();

    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = (in_addr_t)nondet_uint();
    sa.sin_port = nondet_ushort();
    int rv = bind(nondet_int(), (struct sockaddr *)&sa, sizeof(sa));
    (void)rv;
}

/* An IP socket (real family AF_INET) with options requested gets them applied. */
void verify_bind_ip_applies_options(void) {
    reset_bindp_state();
    reuse_addr = 1;
    reuse_port = 1;
    ip_transparent = 1;
    g_getsockopt_rc = 0;
    g_sock_domain = AF_INET;

    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = (in_addr_t)nondet_uint();
    sa.sin_port = nondet_ushort();
    bind(nondet_int(), (struct sockaddr *)&sa, sizeof(sa));
    __CPROVER_assert(g_set_reuseaddr == 1,
        "SO_REUSEADDR requested on an IP socket");
    __CPROVER_assert(g_set_reuseport == 1,
        "SO_REUSEPORT requested on an IP socket");
    __CPROVER_assert(g_set_iptransparent == 1,
        "IP_TRANSPARENT requested on an IP socket");
}

/*
   The regression property: a caller passing sa_family AF_UNSPEC on a socket
   whose REAL domain is AF_INET (the Linux IPv4 wildcard-bind case) must still
   get the reuse options -- the gate keys on SO_DOMAIN, not the caller family.
*/
void verify_bind_af_unspec_caller_still_applies_options(void) {
    reset_bindp_state();
    reuse_addr = 1;
    reuse_port = 1;
    g_getsockopt_rc = 0;
    g_sock_domain = AF_INET;            /* real socket is IPv4 */

    struct sockaddr_in sa;
    sa.sin_family = AF_UNSPEC;          /* caller's sa_family */
    sa.sin_addr.s_addr = (in_addr_t)nondet_uint();
    sa.sin_port = nondet_ushort();
    bind(nondet_int(), (struct sockaddr *)&sa, sizeof(sa));
    __CPROVER_assert(g_set_reuseaddr == 1,
        "AF_UNSPEC caller on an AF_INET socket still gets SO_REUSEADDR");
    __CPROVER_assert(g_set_reuseport == 1,
        "AF_UNSPEC caller on an AF_INET socket still gets SO_REUSEPORT");
}

/* A non-IP socket (real family AF_UNIX) never gets the IP socket options. */
void verify_bind_non_ip_skips_options(void) {
    reset_bindp_state();
    reuse_addr = 1;
    reuse_port = 1;
    ip_transparent = 1;
    g_getsockopt_rc = 0;
    g_sock_domain = AF_UNIX;

    struct sockaddr_un sa;
    sa.sun_family = AF_UNIX;
    sa.sun_path[0] = '\0';
    bind(nondet_int(), (struct sockaddr *)&sa, sizeof(sa));
    __CPROVER_assert(g_setsockopt_calls == 0,
        "no setsockopt at all on a non-IP socket");
    __CPROVER_assert(g_set_reuseaddr == 0 && g_set_reuseport == 0
        && g_set_iptransparent == 0,
        "no IP socket option requested on a non-IP socket");
}

/*
   connect() on an AF_INET caller with a rewrite configured binds the source via
   the internal local_sockaddr_in; prove that whole path is memory-safe.
*/
void verify_connect_memory_safety(void) {
    reset_bindp_state();
    bind_addr_saddr = (in_addr_t)nondet_uint();
    bind_port_saddr = nondet_ushort();
    local_sockaddr_in->sin_family = AF_INET;
    local_sockaddr_in->sin_addr.s_addr = bind_addr_saddr;
    local_sockaddr_in->sin_port = nondet_ushort();
    g_getsockopt_rc = 0;
    g_sock_domain = AF_INET;

    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = (in_addr_t)nondet_uint();
    sa.sin_port = nondet_ushort();
    int rv = connect(nondet_int(), (struct sockaddr *)&sa, sizeof(sa));
    (void)rv;
}
