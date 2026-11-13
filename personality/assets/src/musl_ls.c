/* musl_ls — emulated opendir(3)/readdir(3) through the VFS (getdents64).
 *
 * Lists the root directory (name + newline per entry, capped at 31 entries),
 * then prints "helios-ls-done:" and the entry count on the next line.
 * On failure prints "helios-opendir-fail" (exit 1).
 *
 * Build (see ../build.sh):
 *   zig cc -target x86_64-linux-musl -static -Os -s -o musl_ls musl_ls.c
 */
#include <dirent.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    DIR *d = opendir("/");
    if (!d) {
        write(1, "helios-opendir-fail\n", 20);
        return 1;
    }
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        int len = strlen(e->d_name);
        write(1, e->d_name, len);
        write(1, "\n", 1);
        if (++n == 31)
            break;
    }
    closedir(d);
    write(1, "helios-ls-done:", 15);
    char b[3];
    b[0] = (char)(0x30 + n % 10);
    b[1] = 0x0a;
    b[2] = 0;
    write(1, b, 2);
    return 0;
}
