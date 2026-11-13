/* musl_write — a bare write(2) with no stdio, so the emulator's reply->rax
 * path is exercised without musl's stdio buffering.
 *
 * Build (see ../build.sh):
 *   zig cc -target x86_64-linux-musl -static -Os -s -o musl_write musl_write.c
 */
#include <unistd.h>

int main(void) {
    write(1, "helios-musl-write\n", 18);
    return 0;
}
