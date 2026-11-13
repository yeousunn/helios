/* musl_cwd — emulated getcwd(2) and readlink(2).
 *
 * Prints "cwd:<root>" then "exe:/linrun" (the emulator reports its own
 * /proc/self/exe). On failure prints "getcwd-fail" / "readlink-fail".
 *
 * Build (see ../build.sh):
 *   zig cc -target x86_64-linux-musl -static -Os -s -o musl_cwd musl_cwd.c
 */
#include <unistd.h>
#include <string.h>

int main(void) {
    char buf[256];
    if (getcwd(buf, 256) == 0) {
        write(1, "getcwd-fail\n", 12);
    } else {
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
    } else {
        write(1, "readlink-fail\n", 14);
    }
    return 0;
}
