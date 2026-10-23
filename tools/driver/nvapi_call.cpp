/* Call one NVAPI id with the right number of arguments.
 *
 *   nvapi_call <id> <argc> [buffer bytes]
 *
 * Every argument is a pointer to a zeroed buffer whose first dword carries
 * size|version, which is what most NVAPI structures expect. Scalars are passed
 * as the buffer address too: passing 0 for an unknown scalar is how a caller
 * accidentally sends a null pointer where an integer was meant.
 *
 * The C caller exists because ctypes turns an access violation into an
 * exception and hides it from a debugger; here the fault is unhandled.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef void *(*QIFN)(unsigned int);
typedef int (*INITPROC)(void);

int main(int argc, char **argv) {
    if (argc < 3) { printf("usage: %s <id hex> <argc> [bytes]\n", argv[0]); return 2; }
    unsigned int id = (unsigned int)strtoul(argv[1], NULL, 0);
    int nargs = atoi(argv[2]);
    size_t size = argc > 3 ? (size_t)strtoul(argv[3], NULL, 0) : 4096;

    HMODULE dll = LoadLibraryA("nvapi64.dll");
    if (!dll) { printf("no nvapi64\n"); return 3; }
    QIFN qi = (QIFN)(void *)GetProcAddress(dll, "nvapi_QueryInterface");
    if (!qi) { printf("no nvapi_QueryInterface\n"); return 3; }

    INITPROC init = (INITPROC)qi(0x0150E828);
    if (init) { int rc0 = init(); if (rc0) printf("init=%d\n", rc0); }

    void *fn = qi(id);
    if (!fn) { printf("id=0x%08x no such id\n", id); return 1; }

    unsigned char *buf = (unsigned char *)calloc(1, size);
    *(unsigned int *)buf = (unsigned int)(size & 0xFFFF) | (1u << 16);

    /* Up to six arguments are supported, which covers every NVAPI entry. */
    void *a[6] = {buf, buf, buf, buf, buf, buf};
    int status = 0;
    switch (nargs) {
        case 0: status = ((int (*)(void))fn)(); break;
        case 1: status = ((int (*)(void *))fn)(a[0]); break;
        case 2: status = ((int (*)(void *, void *))fn)(a[0], a[1]); break;
        case 3: status = ((int (*)(void *, void *, void *))fn)(a[0], a[1], a[2]); break;
        case 4: status = ((int (*)(void *, void *, void *, void *))fn)(a[0], a[1], a[2], a[3]); break;
        case 5: status = ((int (*)(void *, void *, void *, void *, void *))fn)(a[0], a[1], a[2], a[3], a[4]); break;
        default: status = ((int (*)(void *, void *, void *, void *, void *, void *))fn)
                     (a[0], a[1], a[2], a[3], a[4], a[5]); break;
    }
    printf("id=0x%08x argc=%d status=%d\n", id, nargs, status);
    free(buf);
    return 0;
}
