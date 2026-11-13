/* musl_hello — first program to go through real musl stdio (printf), which
 * makes musl issue ioctl(TCGETS) + writev before the write.
 *
 * Build (see ../build.sh):
 *   zig cc -target x86_64-linux-musl -static -Os -s -o musl_hello musl_hello.c
 */
#include <stdio.h>

int main(void) {
    printf("helios-musl-hello\n");
    return 0;
}
