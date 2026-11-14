// Experiment A (docs/send-admission-design.md, section 3; results in
// docs/journal/2026-11-abort-close.md): which way of
// closing a connection now releases what a zero-copy send to a peer that
// does not read holds, while other connections have requests pending.
//
//   abort-close-probe <arm> <idle>
//
// One process is one round. Like ringline, every accepted socket is installed
// in the io_uring fixed-file table, its raw fd is closed, and each connection
// has a POLL_ADD(POLLRDHUP) pending (ringline's hangup poll). `idle`
// connections are opened first, so their polls are earlier requests than
// anything on the target. Then the target: its client sets a 4 KiB receive
// buffer and never reads, its hangup poll is armed, and a 512 KiB SEND_ZC is
// submitted with MSG_DONTWAIT. The kernel accepts what fits in the socket
// buffer (176,128 bytes on 6.8 and 6.12, all of it on 7.2), and since the peer
// does not read, that data stays queued and the notification (CQE_F_NOTIF)
// does not land. After 300 ms the round checks the notification is still out
// and applies the arm:
//
//   plain          IORING_OP_CLOSE of the slot (control).
//   linger         SO_LINGER {1, 0} through URING_CMD setsockopt, then CLOSE.
//   cancel_linger  ASYNC_CANCEL of every request on the slot, then the
//                  setsockopt, then CLOSE (candidate 1).
//   unspec         IORING_OP_CONNECT with an AF_UNSPEC address, then CLOSE
//                  (candidate 2: tcp_disconnect resets and purges the write
//                  queue whatever holds the file).
//   cancel_unspec  ASYNC_CANCEL, then CONNECT AF_UNSPEC, then CLOSE.
//   batch          cancel, setsockopt and CLOSE on every connection, idle ones
//                  included, submitted together: a shutdown that resets every
//                  remaining connection at once.
//
// It reports whether the notification landed within 5 s of the arm and when,
// how the target's client read ended (ECONNRESET for an RST, eof for a FIN,
// EAGAIN for a connection still open), and, for batch, how many idle clients
// saw an RST. If the notification has not landed after 5 s and there are idle
// connections, it closes every idle client, which completes their polls, and
// reports whether and when the notification landed after that.
//
// Raw syscalls and a local SQE layout, so it builds against old headers and
// without liburing.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/io_uring.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define OP_POLL_ADD 6
#define OP_ASYNC_CANCEL 14
#define OP_CONNECT 16
#define OP_CLOSE 19
#define OP_URING_CMD 46
#define OP_SEND_ZC 47
#define SQE_FIXED_FILE 1u
#define SQE_IO_HARDLINK (1u << 3)
#define CQE_F_NOTIF (1u << 3)
#define SOCKET_OP_SETSOCKOPT 3
#define CANCEL_ALL (1u << 0)
#define CANCEL_FD (1u << 1)
#define CANCEL_FD_FIXED (1u << 3)
#define REG_FILES 2
#define REG_FILES_UPDATE 6

#define UD_SEND 1
#define UD_CANCEL 2
#define UD_ACT 3
#define UD_CLOSE 4
#define UD_POLL 1000
#define UD_BATCH 100000

struct sqe64 {
    uint8_t opcode, flags;
    uint16_t ioprio;
    int32_t fd;
    union { uint64_t off; uint64_t addr2; struct { uint32_t cmd_op, pad1; }; };
    union { uint64_t addr; struct { uint32_t level, optname; }; };
    uint32_t len;
    uint32_t op_flags;
    uint64_t user_data;
    uint16_t buf_index, personality;
    union { int32_t splice_fd_in; uint32_t file_index; uint32_t optlen; };
    uint64_t optval;
    uint64_t pad2;
};
_Static_assert(sizeof(struct sqe64) == 64, "sqe layout");

struct cqe16 { uint64_t user_data; int32_t res; uint32_t flags; };

static int ring_fd;
static unsigned *sq_tail, *sq_mask, *sq_array, *cq_head, *cq_tail, *cq_mask;
static struct sqe64 *sqes;
static struct cqe16 *cqes;
static unsigned pending_submit;

static void die(const char *what) { fprintf(stderr, "%s: %s\n", what, strerror(errno)); exit(2); }

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void ring_init(unsigned entries) {
    struct io_uring_params p;
    memset(&p, 0, sizeof p);
    p.flags = IORING_SETUP_CQSIZE;
    p.cq_entries = entries * 4;
    ring_fd = syscall(__NR_io_uring_setup, entries, &p);
    if (ring_fd < 0) die("io_uring_setup");
    size_t sq_len = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    size_t cq_len = p.cq_off.cqes + p.cq_entries * sizeof(struct cqe16);
    size_t len = sq_len > cq_len ? sq_len : cq_len;
    char *sq = mmap(0, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_SQ_RING);
    if (sq == MAP_FAILED) die("mmap sq");
    sqes = mmap(0, p.sq_entries * sizeof(struct sqe64), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_SQES);
    if (sqes == MAP_FAILED) die("mmap sqes");
    sq_tail = (unsigned *)(sq + p.sq_off.tail);
    sq_mask = (unsigned *)(sq + p.sq_off.ring_mask);
    sq_array = (unsigned *)(sq + p.sq_off.array);
    cq_head = (unsigned *)(sq + p.cq_off.head);
    cq_tail = (unsigned *)(sq + p.cq_off.tail);
    cq_mask = (unsigned *)(sq + p.cq_off.ring_mask);
    cqes = (struct cqe16 *)(sq + p.cq_off.cqes);
}

static struct sqe64 *get_sqe(void) {
    unsigned tail = *sq_tail, idx = tail & *sq_mask;
    struct sqe64 *s = &sqes[idx];
    memset(s, 0, sizeof *s);
    sq_array[idx] = idx;
    __atomic_store_n(sq_tail, tail + 1, __ATOMIC_RELEASE);
    pending_submit++;
    return s;
}

static void submit(void) {
    while (pending_submit) {
        int n = syscall(__NR_io_uring_enter, ring_fd, pending_submit, 0, 0, NULL, 0);
        if (n < 0) die("io_uring_enter");
        pending_submit -= n;
    }
}

// Every CQE goes through here. The send's notification and the results of
// the requests the round waits for are recorded as they pass.
static int notif_seen;
static double notif_at;
static int results[8];
static int have[8];
static int batch_closed;

static void reap(void) {
    unsigned head = *cq_head;
    while (head != __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE)) {
        struct cqe16 *c = &cqes[head & *cq_mask];
        if (c->user_data == UD_SEND && (c->flags & CQE_F_NOTIF)) {
            if (!notif_seen) notif_at = now();
            notif_seen = 1;
        } else if (c->user_data < 8) {
            results[c->user_data] = c->res;
            have[c->user_data] = 1;
        } else if (c->user_data >= UD_BATCH) {
            batch_closed++;
        }
        head++;
        __atomic_store_n(cq_head, head, __ATOMIC_RELEASE);
    }
}

static void spin(double secs, int (*done)(void)) {
    double end = now() + secs;
    for (;;) {
        reap();
        if (done && done()) return;
        if (now() > end) return;
        syscall(__NR_io_uring_enter, ring_fd, 0, 0, 0, NULL, 0);
        struct timespec ts = {0, 200000};
        nanosleep(&ts, NULL);
    }
}

static int got_notif(void) { return notif_seen; }
static int have_send(void) { return have[UD_SEND]; }
static int have_close(void) { return have[UD_CLOSE]; }

static void install(int slot, int fd) {
    struct { uint32_t offset, resv; uint64_t fds; } upd = {(uint32_t)slot, 0, (uint64_t)(uintptr_t)&fd};
    if (syscall(__NR_io_uring_register, ring_fd, REG_FILES_UPDATE, &upd, 1) != 1) die("files update");
    close(fd);
}

static void poll_rdhup(int slot, uint64_t ud) {
    struct sqe64 *s = get_sqe();
    s->opcode = OP_POLL_ADD; s->flags = SQE_FIXED_FILE; s->fd = slot;
    s->op_flags = POLLRDHUP; s->user_data = ud;
}

static void cancel_all(int slot, uint64_t ud, uint8_t link) {
    struct sqe64 *s = get_sqe();
    s->opcode = OP_ASYNC_CANCEL; s->fd = slot; s->flags = link;
    s->op_flags = CANCEL_ALL | CANCEL_FD | CANCEL_FD_FIXED; s->user_data = ud;
}

static struct linger lg = {1, 0};
static void set_linger(int slot, uint64_t ud, uint8_t link) {
    struct sqe64 *s = get_sqe();
    s->opcode = OP_URING_CMD; s->flags = SQE_FIXED_FILE | link; s->fd = slot;
    s->cmd_op = SOCKET_OP_SETSOCKOPT; s->level = SOL_SOCKET; s->optname = SO_LINGER;
    s->optval = (uint64_t)(uintptr_t)&lg; s->optlen = sizeof lg; s->user_data = ud;
}

static struct sockaddr unspec_addr = {.sa_family = AF_UNSPEC};
static void connect_unspec(int slot, uint64_t ud, uint8_t link) {
    struct sqe64 *s = get_sqe();
    s->opcode = OP_CONNECT; s->flags = SQE_FIXED_FILE | link; s->fd = slot;
    s->addr = (uint64_t)(uintptr_t)&unspec_addr; s->addr2 = sizeof unspec_addr; s->user_data = ud;
}

static void close_slot(int slot, uint64_t ud) {
    struct sqe64 *s = get_sqe();
    s->opcode = OP_CLOSE; s->file_index = (uint32_t)slot + 1; s->user_data = ud;
}

// The client socket's TCP state, read without consuming anything: reading
// would ACK the queued data and free the zero-copy pages, which lands the
// notification whatever the server side did. 1 established, 7 closed (an RST
// arrived), 8 close-wait (a FIN arrived).
static int client_state(int cfd) {
    struct tcp_info ti;
    socklen_t len = sizeof ti;
    if (getsockopt(cfd, IPPROTO_TCP, TCP_INFO, &ti, &len)) return -1;
    return ti.tcpi_state;
}

// How a client's read of what it can get ends.
static const char *client_end(int cfd, long *bytes) {
    char sink[65536];
    *bytes = 0;
    for (;;) {
        ssize_t rr = recv(cfd, sink, sizeof sink, MSG_DONTWAIT);
        if (rr > 0) { *bytes += rr; continue; }
        if (rr == 0) return "eof";
        return strerrorname_np(errno);
    }
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: abort-close-probe <arm> <idle>\n"); return 2; }
    const char *arm = argv[1];
    int idle = atoi(argv[2]);
    int nslots = idle + 1;
    struct rlimit rl = {65536, 65536};
    setrlimit(RLIMIT_NOFILE, &rl);
    ring_init(4096);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t alen = sizeof a;
    if (bind(lfd, (void *)&a, sizeof a) || listen(lfd, 4096) || getsockname(lfd, (void *)&a, &alen)) die("listen");

    int *slots = malloc(sizeof(int) * nslots);
    for (int i = 0; i < nslots; i++) slots[i] = -1;
    if (syscall(__NR_io_uring_register, ring_fd, REG_FILES, slots, nslots) < 0) die("register files");

    // Idle connections in slots 1..idle, each with its hangup poll pending,
    // opened before the target so their polls are the earlier requests.
    int *idle_cfd = malloc(sizeof(int) * (idle + 1));
    for (int i = 1; i <= idle; i++) {
        int cfd = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(cfd, (void *)&a, sizeof a)) die("connect idle");
        int sfd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
        if (sfd < 0) die("accept idle");
        install(i, sfd);
        poll_rdhup(i, UD_POLL + i);
        idle_cfd[i] = cfd;
        if (pending_submit >= 64) submit();
    }
    submit();

    // The target in slot 0.
    int cfd = socket(AF_INET, SOCK_STREAM, 0);
    int small = 4096;
    setsockopt(cfd, SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
    if (connect(cfd, (void *)&a, sizeof a)) die("connect");
    int sfd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
    if (sfd < 0) die("accept");
    int big = 4 << 20;
    if (setsockopt(sfd, SOL_SOCKET, SO_SNDBUFFORCE, &big, sizeof big))
        setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &big, sizeof big);
    install(0, sfd);
    poll_rdhup(0, UD_POLL);

    size_t send_len = 512 * 1024;
    char *payload = mmap(0, send_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(payload, 'x', send_len);
    struct sqe64 *s = get_sqe();
    s->opcode = OP_SEND_ZC; s->flags = SQE_FIXED_FILE; s->fd = 0;
    s->addr = (uint64_t)(uintptr_t)payload; s->len = send_len; s->op_flags = MSG_DONTWAIT; s->user_data = UD_SEND;
    submit();
    spin(2.0, have_send);
    if (!have[UD_SEND]) { printf("arm=%s idle=%d error=no-send-cqe\n", arm, idle); return 1; }
    spin(0.3, NULL);
    int before = notif_seen;

    double t0 = now();
    if (strcmp(arm, "plain") == 0) {
        close_slot(0, UD_CLOSE);
    } else if (strcmp(arm, "linger") == 0) {
        set_linger(0, UD_ACT, SQE_IO_HARDLINK);
        close_slot(0, UD_CLOSE);
    } else if (strcmp(arm, "cancel_linger") == 0) {
        cancel_all(0, UD_CANCEL, SQE_IO_HARDLINK);
        set_linger(0, UD_ACT, SQE_IO_HARDLINK);
        close_slot(0, UD_CLOSE);
    } else if (strcmp(arm, "unspec") == 0) {
        connect_unspec(0, UD_ACT, SQE_IO_HARDLINK);
        close_slot(0, UD_CLOSE);
    } else if (strcmp(arm, "cancel_unspec") == 0) {
        cancel_all(0, UD_CANCEL, SQE_IO_HARDLINK);
        connect_unspec(0, UD_ACT, SQE_IO_HARDLINK);
        close_slot(0, UD_CLOSE);
    } else if (strcmp(arm, "batch") == 0) {
        for (int i = 0; i < nslots; i++) {
            cancel_all(i, i == 0 ? UD_CANCEL : UD_BATCH + 3 * i, SQE_IO_HARDLINK);
            set_linger(i, i == 0 ? UD_ACT : UD_BATCH + 3 * i + 1, SQE_IO_HARDLINK);
            close_slot(i, i == 0 ? UD_CLOSE : UD_BATCH + 3 * i + 2);
            if (pending_submit >= 60) submit();
        }
    } else {
        fprintf(stderr, "unknown arm %s\n", arm);
        return 2;
    }
    submit();
    spin(2.0, have_close);
    double close_ms = have[UD_CLOSE] ? (now() - t0) * 1000 : -1;
    spin(5.0, got_notif);
    int notif5 = notif_seen && !before;
    double notif_ms = notif5 ? (notif_at - t0) * 1000 : -1;
    int state5 = client_state(cfd);

    int idle_reset = 0;
    if (strcmp(arm, "batch") == 0) {
        for (int i = 1; i <= idle; i++) {
            long b;
            const char *e = client_end(idle_cfd[i], &b);
            if (strcmp(e, "ECONNRESET") == 0) idle_reset++;
        }
    }

    // Not released within 5 s: end the idle connections' polls and look again.
    int notif_after_idle = -1;
    double after_idle_ms = -1;
    int state_after = -1;
    if (!notif5 && !before && idle > 0 && strcmp(arm, "batch") != 0) {
        double t1 = now();
        for (int i = 1; i <= idle; i++) close(idle_cfd[i]);
        spin(5.0, got_notif);
        notif_after_idle = notif_seen;
        if (notif_seen) after_idle_ms = (notif_at - t1) * 1000;
        state_after = client_state(cfd);
    }
    long bytes = 0;
    const char *end = client_end(cfd, &bytes);

    printf("arm=%s idle=%d sent=%d notif_before=%d cancel=%d act=%d close=%d close_ms=%.2f "
           "notif_5s=%d notif_ms=%.2f client_read=%ld client_end=%s idle_reset=%d "
           "notif_after_idle_close=%d after_idle_ms=%.2f client_state_5s=%d client_state_after=%d\n",
           arm, idle, results[UD_SEND], before,
           have[UD_CANCEL] ? results[UD_CANCEL] : 0, have[UD_ACT] ? results[UD_ACT] : 0,
           have[UD_CLOSE] ? results[UD_CLOSE] : -9999, close_ms, notif5, notif_ms, bytes, end,
           idle_reset, notif_after_idle, after_idle_ms, state5, state_after);
    return 0;
}
