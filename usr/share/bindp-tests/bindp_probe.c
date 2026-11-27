/*
   Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
   See the file COPYING for copying conditions.

   AI-Assisted

   Test fixture for the bindp-tests suite (NOT a copy of the subject). Drives the
   REAL libindp.so (LD_PRELOAD by the test) through its bind()/connect() paths and
   reports observable results as `key=value` lines on stdout, so the Python test
   can assert on bindp's behaviour end to end:

     - address / port rewrite from BIND_ADDR / BIND_PORT,
     - SO_REUSEADDR / SO_REUSEPORT application, gated to IP sockets,
     - the AF_UNSPEC-wildcard regression (reuse options still applied),
     - AF_UNIX binds left untouched,
     - connect() binding the source address.

   Usage: bindp_probe <mode> [arg]
     bind-inet          AF_INET UDP bind to INADDR_ANY:0 (sa_family AF_INET)
     bind-unspec        same, but the sockaddr's sa_family is AF_UNSPEC
     bind-unix <path>   AF_UNIX bind to <path>
     dual-unspec        two AF_INET UDP sockets, both bound AF_UNSPEC to one port
     connect-src        TCP client connect to a local listener; report its source

   Printed keys (per mode): bind_rc, addr, port, reuseaddr, reuseport,
   second_bind_rc, src_addr. Exit 0 = ran to completion (read the keys); exit 2 =
   setup failure (socket/listener), not an assertion.
*/
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

static int getopt_int(int fd, int opt) {
    int val = -1;
    socklen_t len = (socklen_t)sizeof(val);
    if (getsockopt(fd, SOL_SOCKET, opt, &val, &len) != 0) {
        return -1;
    }
    return val;
}

static void report_inet(int fd) {
    struct sockaddr_in got;
    socklen_t got_len = (socklen_t)sizeof(got);
    char ip[INET_ADDRSTRLEN] = "";
    if (getsockname(fd, (struct sockaddr *)&got, &got_len) != 0) {
        fprintf(stderr, "getsockname: %s\n", strerror(errno));
        exit(2);
    }
    inet_ntop(AF_INET, &got.sin_addr, ip, sizeof(ip));
    printf("addr=%s\n", ip);
    printf("port=%d\n", ntohs(got.sin_port));
    printf("reuseaddr=%d\n", getopt_int(fd, SO_REUSEADDR));
    printf("reuseport=%d\n", getopt_int(fd, SO_REUSEPORT));
}

static void fill_in(struct sockaddr_in *sa, unsigned short family, in_port_t port) {
    memset(sa, 0, sizeof(*sa));
    sa->sin_family = family;
    sa->sin_addr.s_addr = htonl(INADDR_ANY);
    sa->sin_port = port;
}

static int mode_bind_inet(unsigned short family) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return 2;
    }
    struct sockaddr_in sa;
    fill_in(&sa, family, 0);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        printf("bind_rc=%d\n", errno);
        return 0;
    }
    printf("bind_rc=0\n");
    report_inet(fd);
    return 0;
}

static int mode_bind_unix(const char *path) {
    if (path == NULL) {
        fprintf(stderr, "bind-unix needs a path argument\n");
        return 2;
    }
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return 2;
    }
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(sa.sun_path)) {
        fprintf(stderr, "path too long\n");
        return 2;
    }
    strncpy(sa.sun_path, path, sizeof(sa.sun_path) - 1);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        printf("bind_rc=%d\n", errno);
        return 0;
    }
    printf("bind_rc=0\n");
    printf("reuseaddr=%d\n", getopt_int(fd, SO_REUSEADDR));
    return 0;
}

static int mode_dual_unspec(void) {
    int s1 = socket(AF_INET, SOCK_DGRAM, 0);
    int s2 = socket(AF_INET, SOCK_DGRAM, 0);
    if (s1 < 0 || s2 < 0) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return 2;
    }
    struct sockaddr_in first;
    fill_in(&first, AF_UNSPEC, 0);
    if (bind(s1, (struct sockaddr *)&first, sizeof(first)) != 0) {
        fprintf(stderr, "first bind: %s\n", strerror(errno));
        return 2;
    }
    struct sockaddr_in got;
    socklen_t got_len = (socklen_t)sizeof(got);
    if (getsockname(s1, (struct sockaddr *)&got, &got_len) != 0) {
        fprintf(stderr, "getsockname: %s\n", strerror(errno));
        return 2;
    }
    struct sockaddr_in second;
    fill_in(&second, AF_UNSPEC, got.sin_port);
    if (bind(s2, (struct sockaddr *)&second, sizeof(second)) != 0) {
        printf("second_bind_rc=%d\n", errno);
        return 0;
    }
    printf("second_bind_rc=0\n");
    return 0;
}

static int mode_connect_src(void) {
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        fprintf(stderr, "server socket: %s\n", strerror(errno));
        return 2;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) != 0
        || listen(srv, 1) != 0) {
        fprintf(stderr, "server setup: %s\n", strerror(errno));
        return 2;
    }
    socklen_t sa_len = (socklen_t)sizeof(sa);
    if (getsockname(srv, (struct sockaddr *)&sa, &sa_len) != 0) {
        fprintf(stderr, "server getsockname: %s\n", strerror(errno));
        return 2;
    }

    int cli = socket(AF_INET, SOCK_STREAM, 0);
    if (cli < 0) {
        fprintf(stderr, "client socket: %s\n", strerror(errno));
        return 2;
    }
    /*
       Dial the server's ACTUAL bound address, not a hardcoded 127.0.0.1: when
       BIND_ADDR is set, bindp rewrites every bind() in this process -- including
       the server's -- so the listener may sit on that address. The test asserts
       on the client's source address, which is what connect() binds.
    */
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr = sa.sin_addr;
    dst.sin_port = sa.sin_port;
    if (connect(cli, (struct sockaddr *)&dst, sizeof(dst)) != 0) {
        printf("connect_rc=%d\n", errno);
        return 0;
    }
    printf("connect_rc=0\n");

    struct sockaddr_in src;
    socklen_t src_len = (socklen_t)sizeof(src);
    char ip[INET_ADDRSTRLEN] = "";
    if (getsockname(cli, (struct sockaddr *)&src, &src_len) != 0) {
        fprintf(stderr, "client getsockname: %s\n", strerror(errno));
        return 2;
    }
    inet_ntop(AF_INET, &src.sin_addr, ip, sizeof(ip));
    printf("src_addr=%s\n", ip);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <mode> [arg]\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    if (strcmp(mode, "bind-inet") == 0) {
        return mode_bind_inet(AF_INET);
    }
    if (strcmp(mode, "bind-unspec") == 0) {
        return mode_bind_inet(AF_UNSPEC);
    }
    if (strcmp(mode, "bind-unix") == 0) {
        return mode_bind_unix(argc >= 3 ? argv[2] : NULL);
    }
    if (strcmp(mode, "dual-unspec") == 0) {
        return mode_dual_unspec();
    }
    if (strcmp(mode, "connect-src") == 0) {
        return mode_connect_src();
    }
    fprintf(stderr, "unknown mode '%s'\n", mode);
    return 2;
}
