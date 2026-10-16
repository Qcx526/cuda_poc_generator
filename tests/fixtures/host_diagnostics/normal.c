/* Fixed CPU diagnostic fixture. No file, network, child process or GPU access.
 * Compile/run only after separate operator approval and enforced limits. */
#include <stdlib.h>
int main(void) {
    unsigned char *p = malloc(8);
    if (p == NULL) return 2;
    p[0] = 7;
    int result = p[0] == 7 ? 0 : 3;
    free(p);
    return result;
}
