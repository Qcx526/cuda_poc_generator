/* Fixed controlled CPU diagnostic anomaly; never a CVE reproduction.
 * Do not compile/run without operator approval and a bounded isolated runner. */
#include <stdlib.h>
int main(void) {
    unsigned char *p = malloc(8);
    if (p == NULL) return 2;
    p[0] = 1;
    free(p);
    volatile unsigned char observed = p[0];
    (void)observed;
    return 0;
}
