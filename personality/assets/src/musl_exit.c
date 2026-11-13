/* musl_exit — write a line, then _exit(2) directly (bypassing the stdio
 * flush in exit(3)), to prove the emulator handles an explicit exit_group.
 *
 * Build (see ../build.sh):
 *   zig cc -target x86_64-linux-musl -static -Os -s -o musl_exit musl_exit.c
 */
#include <unistd.h>
#include <stdlib.h>

int main(void) {
    write(1, "helios-musl-write\n", 18);
    _exit(0);
}
