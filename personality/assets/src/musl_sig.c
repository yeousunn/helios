/* musl_sig — emulated signal self-delivery: raise(SIGTERM) terminates.
 *
 * Prints "helios-before-raise", raises SIGTERM (which the emulator treats as
 * a terminating self-directed signal), and should never reach
 * "helios-after-raise". Exit status is 128 + 15 = 143.
 *
 * Build (see ../build.sh):
 *   zig cc -target x86_64-linux-musl -static -Os -s -o musl_sig musl_sig.c
 */
#include <signal.h>
#include <unistd.h>

int main(void) {
    write(1, "helios-before-raise\n", 20);
    raise(SIGTERM);
    write(1, "helios-after-raise\n", 19);
    return 0;
}
