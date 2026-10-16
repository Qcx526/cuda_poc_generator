/* Fixed controlled CPU diagnostic anomaly; never a CVE reproduction.
 * Do not compile/run without operator approval and a bounded isolated runner. */
#include <stdlib.h>
int main(void) {
    unsigned char *p = calloc(8, 1);
    if (p == NULL) return 2;
    volatile unsigned int index = 8;
    p[index] = 1;
    free(p);
    return 0;
}
