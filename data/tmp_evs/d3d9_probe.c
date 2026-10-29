/* Baseline: create a D3D9 device and a ps_3_0 shader that carries SINCOS. */
#include <windows.h>
#include <d3d9.h>
#include <d3dcompiler.h>
#include <stdio.h>

static HWND make_window(void) {
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "CpgWnd";
    RegisterClassA(&wc);
    return CreateWindowExA(0, "CpgWnd", "cpg", WS_OVERLAPPEDWINDOW,
                           0, 0, 64, 64, NULL, NULL, wc.hInstance, NULL);
}

int main(void) {
    const char *src =
        "float4 main(float2 uv : TEXCOORD0) : COLOR {"
        " float s,c; sincos(uv.x,s,c); return float4(s,c,0,1); }";
    ID3DBlob *code = NULL, *err = NULL;
    HRESULT hr = D3DCompile(src, strlen(src), "s.hlsl", NULL, NULL, "main", "ps_3_0",
                            0, 0, &code, &err);
    printf("D3DCompile hr=0x%08lx size=%zu\n", (unsigned long)hr,
           code ? code->GetBufferSize() : (size_t)0);
    if (FAILED(hr)) {
        if (err) printf("compile error: %s\n", (char *)err->GetBufferPointer());
        return 1;
    }

    HWND hwnd = make_window();
    printf("hwnd=%p\n", (void *)hwnd);
    IDirect3D9 *d3d = Direct3DCreate9(D3D_SDK_VERSION);
    if (!d3d) { printf("no IDirect3D9\n"); return 2; }

    D3DPRESENT_PARAMETERS pp = {0};
    pp.Windowed = TRUE;
    pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    pp.BackBufferFormat = D3DFMT_X8R8G8B8;
    pp.BackBufferWidth = 64;
    pp.BackBufferHeight = 64;
    pp.hDeviceWindow = hwnd;
    pp.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;

    IDirect3DDevice9 *dev = NULL;
    hr = d3d->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd,
                           D3DCREATE_HARDWARE_VERTEXPROCESSING | D3DCREATE_FPU_PRESERVE,
                           &pp, &dev);
    printf("CreateDevice hr=0x%08lx dev=%p\n", (unsigned long)hr, (void *)dev);
    if (FAILED(hr)) return 3;

    IDirect3DPixelShader9 *sh = NULL;
    hr = dev->CreatePixelShader((const DWORD *)code->GetBufferPointer(), &sh);
    printf("CreatePixelShader hr=0x%08lx shader=%p\n", (unsigned long)hr, (void *)sh);
    printf("RESULT: %s\n", SUCCEEDED(hr) ? "PATH WORKS" : "rejected");
    if (sh) sh->Release();
    dev->Release(); d3d->Release();
    return 0;
}
