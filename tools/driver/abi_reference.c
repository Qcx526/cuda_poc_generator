/* ABI reference: ask the real compiler for the layout, instead of trusting a
 * hand-derived model or Python ctypes (which is the thing under test).
 *
 * Build (MSVC x64), from a shell that has the VS + SDK environment:
 *     cl /nologo /W3 /DUNICODE /D_UNICODE abi_reference.c
 * The include order matters: the SDK's shared/ must be searched before ucrt.
 */

#include <windows.h>
#include <d3dkmthk.h>
#include <stdio.h>

#define SHOW(type, field) \
    printf("{\"struct\":\"%s\",\"field\":\"%s\",\"offset\":%u}\n", #type, #field, (unsigned)offsetof(type, field))
#define SIZE(type) \
    printf("{\"struct\":\"%s\",\"sizeof\":%u,\"alignof\":%u}\n", #type, (unsigned)sizeof(type), (unsigned)__alignof(type))

int main(void)
{
    SIZE(D3DKMT_ESCAPE);
    SHOW(D3DKMT_ESCAPE, hAdapter);
    SHOW(D3DKMT_ESCAPE, hDevice);
    SHOW(D3DKMT_ESCAPE, Type);
    SHOW(D3DKMT_ESCAPE, Flags);
    SHOW(D3DKMT_ESCAPE, pPrivateDriverData);
    SHOW(D3DKMT_ESCAPE, PrivateDriverDataSize);
    SHOW(D3DKMT_ESCAPE, hContext);

    SIZE(D3DKMT_OPENADAPTERFROMHDC);
    SHOW(D3DKMT_OPENADAPTERFROMHDC, hDc);
    SHOW(D3DKMT_OPENADAPTERFROMHDC, hAdapter);
    SHOW(D3DKMT_OPENADAPTERFROMHDC, AdapterLuid);
    SHOW(D3DKMT_OPENADAPTERFROMHDC, VidPnSourceId);

    SIZE(D3DKMT_OPENADAPTERFROMLUID);
    SHOW(D3DKMT_OPENADAPTERFROMLUID, AdapterLuid);
    SHOW(D3DKMT_OPENADAPTERFROMLUID, hAdapter);

    SIZE(D3DKMT_CREATEDEVICE);
    SHOW(D3DKMT_CREATEDEVICE, hAdapter);
    SHOW(D3DKMT_CREATEDEVICE, Flags);
    SHOW(D3DKMT_CREATEDEVICE, hDevice);
    SHOW(D3DKMT_CREATEDEVICE, pCommandBuffer);
    SHOW(D3DKMT_CREATEDEVICE, CommandBufferSize);

    SIZE(D3DKMT_CREATECONTEXT);
    SHOW(D3DKMT_CREATECONTEXT, hDevice);
    SHOW(D3DKMT_CREATECONTEXT, NodeOrdinal);
    SHOW(D3DKMT_CREATECONTEXT, EngineAffinity);
    SHOW(D3DKMT_CREATECONTEXT, Flags);
    SHOW(D3DKMT_CREATECONTEXT, pPrivateDriverData);
    SHOW(D3DKMT_CREATECONTEXT, PrivateDriverDataSize);
    SHOW(D3DKMT_CREATECONTEXT, ClientHint);
    SHOW(D3DKMT_CREATECONTEXT, hContext);

    SIZE(D3DKMT_DESTROYCONTEXT);
    SHOW(D3DKMT_DESTROYCONTEXT, hContext);

    printf("{\"scalar\":\"D3DKMT_HANDLE\",\"sizeof\":%u}\n", (unsigned)sizeof(D3DKMT_HANDLE));
    printf("{\"scalar\":\"HANDLE\",\"sizeof\":%u}\n", (unsigned)sizeof(HANDLE));
    printf("{\"scalar\":\"LUID\",\"sizeof\":%u}\n", (unsigned)sizeof(LUID));
    return 0;
}
