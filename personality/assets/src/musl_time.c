/* musl_time — emulated time: clock_gettime(CLOCK_MONOTONIC),
 * nanosleep, clock_gettime(CLOCK_REALTIME) and arch_prctl(ARCH_GET_FS).
 *
 * Prints, in order:
 *   "mono: t0=<ns> slept=<ns> real=<sec>.<nsec>"
 *   "tls: fs=<base> ok"
 *   "cwd:<root>" then "exe:/linrun" (kept from the musl_cwd demo)
 *   "helios-musl-time: ALL OK"
 * Exits 1 (with "tls-fail" / "mono-fail" / "sleep-short") if the emulator
 * answers something Linux would not: a base of 0 for ARCH_GET_FS (musl's
 * startup sets TLS through ARCH_SET_FS), or a nanosleep that came back
 * before its own deadline.
 *
 * Build (see ../build.sh):
 *   zig cc -target x86_64-linux-musl -static -Os -s -o musl_time musl_time.c
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

/* ARCH_GET_FS (0x1003): the base ARCH_SET_FS set. */
static long arch_prctl_get_fs(unsigned long *out) {
    return syscall(SYS_arch_prctl, 0x1003, out);
}

int main(void) {
    struct timespec t0, t1;
    if (clock_gettime(CLOCK_MONOTONIC, &t0) != 0) {
        write(1, "mono-fail\n", 10);
        return 1;
    }
    /* A real sleep: the emulator waits on its monotonic clock, so the
     * measured span must cover the requested 20 ms. */
    struct timespec req = {0, 20 * 1000 * 1000};
    nanosleep(&req, 0);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long long dt =
        (t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec);

    /* ARCH_GET_FS must answer the base libc startup set through
     * ARCH_SET_FS, not 0. */
    unsigned long fs = 0;
    if (arch_prctl_get_fs(&fs) != 0 || fs == 0) {
        write(1, "tls-fail\n", 9);
        return 1;
    }

    /* CLOCK_REALTIME: the system has no wall-clock source, so Linux guests
     * see the epoch here (Linux itself would report a date). */
    struct timespec real;
    clock_gettime(CLOCK_REALTIME, &real);

    printf("mono: t0=%lld slept=%lld real=%lld.%09ld\n",
           (long long)t0.tv_sec * 1000000000LL + t0.tv_nsec, dt,
           (long long)real.tv_sec, real.tv_nsec);
    printf("tls: fs=%lx ok\n", fs);

    char buf[256];
    if (getcwd(buf, 256) != 0) {
        unsigned long n = strlen(buf);
        write(1, "cwd:", 4);
        write(1, buf, n);
        write(1, "\n", 1);
    }
    char p[128];
    int n = readlink("/proc/self/exe", p, 128);
    if (n > 0) {
        write(1, "exe:", 4);
        write(1, p, n);
        write(1, "\n", 1);
    }
    if (dt < 20 * 1000 * 1000) {
        write(1, "sleep-short\n", 12);
        return 1;
    }
    write(1, "helios-musl-time: ALL OK\n", 24);
    return 0;
}