/* musl_all — one run that exercises the whole emulated surface:
 * printf (stdio) + open/read/close + stat + opendir/readdir + mmap.
 *
 * Prints, in order: "helios-musl: printf ok", "read: " + file contents,
 * "stat: size=<n>", "readdir: <n> entries", "mmap: ok",
 * "helios-musl: ALL OK". Exits 1 (with "open FAIL") if any file call fails.
 *
 * Build (see ../build.sh):
 *   zig cc -target x86_64-linux-musl -static -Os -s -o musl_all musl_all.c
 */
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    printf("helios-musl: printf ok");
    int fd = open("hello", O_RDONLY);
    if (fd < 0) {
        write(1, "open FAIL\n", 10);
        return 1;
    }
    char buf[64];
    int n = read(fd, buf, 64);
    if (n > 0) {
        write(1, "read: ", 6);
        write(1, buf, n);
    }
    close(fd);

    struct stat st;
    if (stat("hello", &st) == 0)
        printf("stat: size=%ld\n", (long)st.st_size);

    DIR *d = opendir("/");
    int count = 0;
    if (d) {
        count = -1;
        while (readdir(d))
            count++;
        closedir(d);
    }
    printf("readdir: %d entries\n", count);

    if (mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
             -1, 0) != MAP_FAILED)
        write(1, "mmap: ok\n", 9);
    printf("helios-musl: ALL OK");
    return 0;
}
