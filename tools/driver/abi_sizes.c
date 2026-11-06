/* Print the sizes and offsets the D3DKMT ABI actually has, as compiled by MSVC.
 *
 * Guessing these from memory is how the earlier probe ended up reading the wrong
 * bytes. The compiler knows; ask it.
 */

#include <windows.h>
#include <d3dkmthk.h>
#include <stdio.h>

int main(void)
{
    printf("D3DKMT_HANDLE %zu\n", sizeof(D3DKMT_HANDLE));
    printf("CREATEDEVICE size=%zu flags=%zu hDevice=%zu\n",
           sizeof(D3DKMT_CREATEDEVICE),
           offsetof(D3DKMT_CREATEDEVICE, Flags),
           offsetof(D3DKMT_CREATEDEVICE, hDevice));
    printf("GETDEVICESTATE size=%zu stateType=%zu\n",
           sizeof(D3DKMT_GETDEVICESTATE),
           offsetof(D3DKMT_GETDEVICESTATE, StateType));
    printf("  ExecutionState=%zu PresentState=%zu ResetState=%zu\n",
           sizeof(D3DKMT_DEVICEEXECUTION_STATE),
           sizeof(D3DKMT_DEVICEPRESENT_STATE),
           sizeof(D3DKMT_DEVICERESET_STATE));
    printf("  PresentStateDWM=%zu PageFault=%zu\n",
           sizeof(D3DKMT_DEVICEPRESENT_STATE_DWM),
           sizeof(D3DKMT_DEVICEPAGEFAULT_STATE));
    printf("QUERYADAPTERINFO size=%zu type=%zu data=%zu size_field=%zu\n",
           sizeof(D3DKMT_QUERYADAPTERINFO),
           offsetof(D3DKMT_QUERYADAPTERINFO, Type),
           offsetof(D3DKMT_QUERYADAPTERINFO, pPrivateDriverData),
           offsetof(D3DKMT_QUERYADAPTERINFO, PrivateDriverDataSize));
    printf("DRIVERVERSION requires a UINT out (%zu bytes)\n", sizeof(UINT));
    return 0;
}
