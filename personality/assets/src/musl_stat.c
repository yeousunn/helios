/* musl_stat — emulated stat(2) over the VFS.
 *
 * Prints "size=<n> mode=<octal>\n" for "hello" (in the smoke: "size=13
 * mode=644"); on failure prints "helios-stat-fail" (exit 1). Uses a hand
 * rolled integer-to-string helper so no printf machinery is linked.
 *
 * Build (see ../build.sh):
 *   zig cc -target x86_64-linux-musl -static -Os -s -o musl_stat musl_stat.c
 */
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    struct stat st;
    if (stat("hello", &st) < 0) {
        write(1, "helios-stat-fail\n", 17);
        return 1;
    }
    char buf[64];
    int n = 0;
    buf[n++] = 's';
    buf[n++] = 'i';
    buf[n++] = 'z';
    buf[n++] = 'e';
    buf[n++] = '=';
    unsigned long v = st.st_size;
    char tmp[24];
    int k = 0;
    if (v == 0)
        tmp[k++] = '0';
    while (v) {
        tmp[k++] = (char)('0' + v % 10);
        v /= 10;
    }
    while (k)
        buf[n++] = tmp[--k];
    buf[n++] = ' ';
    buf[n++] = 'm';
    buf[n++] = 'o';
    buf[n++] = 'd';
    buf[n++] = 'e';
    buf[n++] = '=';
    unsigned m = st.st_mode;
    char o[3];
    for (int i = 0; i < 3; i++) {
        o[i] = (char)('0' + (m & 7));
        m >>= 3;
    }
    for (int i = 2; i >= 0; i--)
        buf[n++] = o[i];
    buf[n++] = '\n';
    write(1, buf, n);
    return 0;
}
