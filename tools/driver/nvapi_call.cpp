/* Call one NVAPI id with a well-formed buffer.
 *
 *   nvapi_call <id> [buffer bytes]
 *
 * A C caller is used instead of Python because ctypes turns the access
 * violation into an exception, which hides the fault from a debugger; here the
 * fault is unhandled and the module that caused it becomes visible.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef void *(*QIFN)(unsigned int);
typedef int (*INITPROC)(void);
typedef int (*APIPROC)(void *);

int main(int argc, char **argv) {
    if (argc < 2) { printf("usage: %s <id hex> [size]\n", argv[0]); return 2; }
    unsigned int id = (unsigned int)strtoul(argv[1], NULL, 0);
    size_t size = argc > 2 ? (size_t)strtoul(argv[2], NULL, 0) : 1024;

    HMODULE dll = LoadLibraryA("nvapi64.dll");
    if (!dll) { printf("cannot load nvapi64\n"); return 3; }
    QIFN qi = (QIFN)(void *)GetProcAddress(dll, "nvapi_QueryInterface");
    if (!qi) { printf("no nvapi_QueryInterface\n"); return 3; }

    INITPROC init = (INITPROC)qi(0x0150E828);
    if (init) { int rc0 = init(); printf("init=%d\n", rc0); }

    APIPROC fn = (APIPROC)qi(id);
    printf("id=0x%08x\n", id);
    if (!fn) { printf("no such id\n"); return 1; }

    unsigned char *buf = (unsigned char *)calloc(1, size);
    *(unsigned int *)buf = (unsigned int)(size & 0xFFFF) | (1u << 16);
    int status = fn(buf);
    printf("status=%d\n", status);
    free(buf);
    return 0;
}
