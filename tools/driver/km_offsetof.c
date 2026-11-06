/* Ask the WDK headers where DxgkDdiEscape actually sits.
 *
 * The 0x110 used in the F9 report was derived by walking fields by hand. This makes
 * it a compiler answer instead of an arithmetic claim.
 */

#include <ntddk.h>
#include <dispmprt.h>

ULONG CpgOffsetDxgkDdiEscape(void)
{
    return (ULONG)FIELD_OFFSET(DRIVER_INITIALIZATION_DATA, DxgkDdiEscape);
}

ULONG CpgSizeDriverInit(void)
{
    return (ULONG)sizeof(DRIVER_INITIALIZATION_DATA);
}

ULONG CpgOffsetVersion(void)
{
    return (ULONG)FIELD_OFFSET(DRIVER_INITIALIZATION_DATA, Version);
}

/* The number, made readable in the object file: the array's size is the offset. */
char cpg_offset_symbol[FIELD_OFFSET(DRIVER_INITIALIZATION_DATA, DxgkDdiEscape)];
char cpg_size_symbol[sizeof(DRIVER_INITIALIZATION_DATA)];

/* A wrong guess must fail to compile, which proves the assert is live. */
#if defined(CPG_NEGATIVE_CONTROL)
static_assert(FIELD_OFFSET(DRIVER_INITIALIZATION_DATA, DxgkDdiEscape) == 0x111,
              "negative control: this must not compile");
#else
static_assert(FIELD_OFFSET(DRIVER_INITIALIZATION_DATA, DxgkDdiEscape) == 0x110,
              "DxgkDdiEscape is expected at 0x110");
#endif
