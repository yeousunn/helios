/* musl_open — emulated open(2)/read(2)/close(2) reach real VFS files.
 *
 * Opens "hello", reads it, and prints "helios-open-ok:" followed by the file
 * contents; prints "helios-open-fail" (and exits 1) on any failure.
 * Output in the smoke: "helios-open-ok:helios-vfs-ok".
 *
 * Build (see ../build.sh):
 *   zig cc -target x86_64-linux-musl -static -Os -s -o musl_open musl_open.c
 */
#include <fcntl.h>
#include <unistd.h>

int main(void) {
    int fd = open("hello", O_RDONLY);
    if (fd < 0) {
        write(1, "helios-open-fail\n", 17);
        return 1;
    }
    char buf[64];
    int n = read(fd, buf, 64);
    write(1, "helios-open-ok:", 15);
    if (n > 0)
        write(1, buf, n);
    write(1, "\n", 1);
    close(fd);
    return 0;
}
