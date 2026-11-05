/* Native twin of the Python mock: same contract, same two planted flaws.
 *
 * Why a DLL at all: the benchmark needs to be a real binary so Binary Facts can be
 * extracted from *the same artefact the candidate runs against*. Facts about a
 * different build would be fiction.
 *
 * Deliberately no real memory unsafety: the "OOB read" is modelled by accepting a
 * one-byte-over declaration and recording it, not by reading past a buffer.
 */

#include <windows.h>
#include <stdint.h>
#include <string.h>

#define MOCK_OK 0
#define MOCK_INVALID_PARAMETER ((int)0xC000000D)
#define MOCK_ACCESS_DENIED ((int)0xC0000022)

#define MAX_SLOTS 64
#define MAX_TRIGGERS 16

typedef struct {
    int handle;
    int in_use;
    int kind;          /* 1 adapter, 2 device, 3 context */
    int parent;
} Slot;

static Slot g_slots[MAX_SLOTS];
static int g_next = 0x2000;
static int g_triggers[MAX_TRIGGERS];
static int g_trigger_count = 0;

static void record_trigger(int kind)
{
    if (g_trigger_count < MAX_TRIGGERS) {
        g_triggers[g_trigger_count++] = kind;
    }
}

static Slot *find(int handle)
{
    int i;
    for (i = 0; i < MAX_SLOTS; i++) {
        if (g_slots[i].in_use && g_slots[i].handle == handle) {
            return &g_slots[i];
        }
    }
    return NULL;
}

static int alloc_slot(int kind, int parent)
{
    int i;
    for (i = 0; i < MAX_SLOTS; i++) {
        if (!g_slots[i].in_use) {
            g_slots[i].in_use = 1;
            g_slots[i].kind = kind;
            g_slots[i].parent = parent;
            g_slots[i].handle = g_next;
            g_next += 0x40;
            return g_slots[i].handle;
        }
    }
    return 0;
}

__declspec(dllexport) void MockReset(void)
{
    memset(g_slots, 0, sizeof(g_slots));
    g_next = 0x2000;
    g_trigger_count = 0;
}

__declspec(dllexport) int MockOpenAdapter(int *out)
{
    int handle = alloc_slot(1, 0);
    if (!handle) return MOCK_INVALID_PARAMETER;
    if (out) *out = handle;
    return MOCK_OK;
}

__declspec(dllexport) int MockCreateDevice(int adapter, int *out)
{
    Slot *parent = find(adapter);
    int handle;
    if (!parent || parent->kind != 1) return MOCK_INVALID_PARAMETER;
    handle = alloc_slot(2, adapter);
    if (!handle) return MOCK_INVALID_PARAMETER;
    if (out) *out = handle;
    return MOCK_OK;
}

__declspec(dllexport) int MockCreateContext(int device, int node, int *out)
{
    Slot *parent = find(device);
    int handle;
    (void)node;
    if (!parent || parent->kind != 2) return MOCK_INVALID_PARAMETER;
    handle = alloc_slot(3, device);
    if (!handle) return MOCK_INVALID_PARAMETER;
    if (out) *out = handle;
    return MOCK_OK;
}

__declspec(dllexport) int MockEscape(int adapter, int device, int context, int type,
                                     int flags, const unsigned char *payload, int length)
{
    Slot *a = find(adapter);
    Slot *d = find(device);
    Slot *c = find(context);
    int declared;
    int privileged;

    if (!a || a->kind != 1) return MOCK_INVALID_PARAMETER;
    if (!d || d->kind != 2) return MOCK_INVALID_PARAMETER;
    if (!c || c->kind != 3) return MOCK_INVALID_PARAMETER;
    if (type < 0 || type > 7) return MOCK_INVALID_PARAMETER;
    if (length < 0 || length > 1024) return MOCK_INVALID_PARAMETER;

    privileged = (flags & 0x2) != 0;

    /* Flaw 1: the ownership check is skipped when PRIVILEGED is claimed. */
    if (c->parent != device && !privileged) {
        return MOCK_ACCESS_DENIED;
    }
    /* Flaw 1 is recorded only if the call ultimately succeeds: a request that is
     * later rejected for a bad payload did not bypass anything, and counting it
     * would let a rejected call masquerade as a trigger. */

    /* Flaw 2: exactly one byte of over-declaration is accepted. */
    if (length >= 4) {
        declared = (int)(payload[0] | (payload[1] << 8) | (payload[2] << 16)
                         | ((unsigned)payload[3] << 24));
        if (declared > 0) {
            if (declared > length - 4 + 1) return MOCK_INVALID_PARAMETER;
            if (declared == length - 4 + 1) record_trigger(2);
        }
    }

    if (c->parent != device && privileged) {
        record_trigger(1);
    }
    return MOCK_OK;
}

static int release(int handle, int kind)
{
    Slot *slot = find(handle);
    if (!slot || slot->kind != kind) return MOCK_INVALID_PARAMETER;
    slot->in_use = 0;
    return MOCK_OK;
}

__declspec(dllexport) int MockDestroyContext(int context) { return release(context, 3); }
__declspec(dllexport) int MockDestroyDevice(int device) { return release(device, 2); }
__declspec(dllexport) int MockCloseAdapter(int adapter) { return release(adapter, 1); }

__declspec(dllexport) int MockTriggerCount(void) { return g_trigger_count; }
__declspec(dllexport) int MockTriggerAt(int index)
{
    if (index < 0 || index >= g_trigger_count) return 0;
    return g_triggers[index];
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
