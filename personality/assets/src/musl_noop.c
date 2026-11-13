/* musl_noop — the smallest static musl program: prove startup + exit work.
 *
 * Build (see ../build.sh):
 *   zig cc -target x86_64-linux-musl -static -Os -s -o musl_noop musl_noop.c
 */
int main(void) {
    return 0;
}
