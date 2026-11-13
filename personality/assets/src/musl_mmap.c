/* musl_mmap — emulated mmap(2) (MAP_ANONYMOUS) over a carved+mapped frame.
 *
 * Maps 8 KiB anonymous RW memory, writes "ok\n" into it, then prints
 * "helios-mmap:ok". On failure prints "helios-mmap-fail" (exit 1).
 *
 * Build (see ../build.sh):
 *   zig cc -target x86_64-linux-musl -static -Os -s -o musl_mmap musl_mmap.c
 */
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    char *p = mmap(0, 0x2000, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        write(1, "helios-mmap-fail\n", 17);
        return 1;
    }
    p[0] = 'o';
    p[1] = 'k';
    p[2] = '\n';
    write(1, "helios-mmap:", 12);
    write(1, p, 3);
    return 0;
}
