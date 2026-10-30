/* Reach the kernel driver through a real DRS session.
 *
 *   drs_probe <fn id hex> <offset> <value hex> [bytes]
 *
 * The earlier caller passed one buffer for every argument. That reaches the
 * entry points but not the code behind them: a session and a profile handle are
 * checked before anything is parsed, so a placeholder is rejected long before
 * the driver sees a struct. This builds the handle chain first - initialize,
 * create session, load settings, take the base profile - and only then calls the
 * target with a struct we control.
 *
 * offset < 0 leaves the struct untouched: that is the baseline. If the baseline
 * does not return zero, the mutation that follows says nothing, because the call
 * never got as far as the field being changed.
 *
 * Exists in C rather than ctypes for the same reason as before: a fault must
 * stay a fault, not become a Python exception nobody can attribute.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void *(*QIFN)(unsigned int);
typedef int (*INITPROC)(void);
typedef int (*CREATESESSION)(void **);
typedef int (*ONESESSION)(void *);
typedef int (*GETPROFILE)(void *, void **);
typedef int (*THREE)(void *, void *, void *);

static void *lookup(QIFN qi, unsigned int id, const char *what) {
    void *fn = qi(id);
    if (!fn) printf("[!] %s (0x%08x) not exported by this driver\n", what, id);
    return fn;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <fn id> <offset> <value> [bytes]\n", argv[0]);
        return 2;
    }
    unsigned int id = (unsigned int)strtoul(argv[1], NULL, 0);
    long offset = argc > 2 ? strtol(argv[2], NULL, 0) : -1;
    unsigned int value = argc > 3 ? (unsigned int)strtoul(argv[3], NULL, 0) : 0;
    size_t bytes = argc > 4 ? (size_t)strtoul(argv[4], NULL, 0) : 4096;

    HMODULE dll = LoadLibraryA("nvapi64.dll");
    if (!dll) { printf("no nvapi64\n"); return 3; }
    QIFN qi = (QIFN)(void *)GetProcAddress(dll, "nvapi_QueryInterface");
    if (!qi) { printf("no nvapi_QueryInterface\n"); return 3; }

    INITPROC init = (INITPROC)lookup(qi, 0x0150E828, "Initialize");
    int rc_init = init ? init() : -1;

    CREATESESSION create = (CREATESESSION)lookup(qi, 0x0694D52E, "DRS_CreateSession");
    void *session = NULL;
    int rc_session = create ? create(&session) : -1;

    ONESESSION load = (ONESESSION)lookup(qi, 0x375DBD6B, "DRS_LoadSettings");
    int rc_load = (load && session) ? load(session) : -1;

    GETPROFILE base = (GETPROFILE)lookup(qi, 0xDA8466A0, "DRS_GetBaseProfile");
    void *profile = NULL;
    int rc_profile = (base && session) ? base(session, &profile) : -1;
    if (rc_profile != 0) {
        GETPROFILE current = (GETPROFILE)lookup(qi, 0x617BFF9F, "DRS_GetCurrentGlobalProfile");
        if (current && session) rc_profile = current(session, &profile);
    }

    unsigned char *buf = (unsigned char *)calloc(1, bytes);
    if (!buf) { printf("no memory\n"); return 3; }
    /* Most NVAPI structs open with a packed size|version dword. */
    *(unsigned int *)buf = (unsigned int)(bytes & 0xFFFF) | (1u << 16);
    if (offset >= 0 && (size_t)offset + 4 <= bytes)
        *(unsigned int *)(buf + offset) = value;

    THREE fn = (THREE)lookup(qi, id, "target");
    int rc_call = 0x7FFFFFFF;
    if (fn && session && profile) {
        rc_call = fn(session, profile, buf);
    } else {
        printf("[!] handle chain incomplete: session=%p profile=%p\n", session, profile);
    }

    printf("probe fn=0x%08x offset=%ld value=0x%08x bytes=%zu "
           "init=%d session=%d load=%d profile=%d call=%d\n",
           id, offset, value, bytes, rc_init, rc_session, rc_load, rc_profile, rc_call);
    free(buf);
    return 0;
}
