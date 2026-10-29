/* Semantic mutation: rewrite the SINCOS source token (regtype / index / srcmod). */
#include <windows.h>
#include <d3d9.h>
#include <d3dcompiler.h>
#include <stdio.h>
#include <stdlib.h>

static HWND make_window(void) {
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "CpgWnd";
    RegisterClassA(&wc);
    return CreateWindowExA(0, "CpgWnd", "cpg", WS_OVERLAPPEDWINDOW,
                           0, 0, 64, 64, NULL, NULL, wc.hInstance, NULL);
}

int main(int argc, char **argv) {
    int regtype = atoi(argv[1]), index = atoi(argv[2]), srcmod = atoi(argv[3]);
    const char *src =
        "float4 main(float2 uv : TEXCOORD0) : COLOR {"
        " float s,c; sincos(uv.x,s,c); return float4(s,c,0,1); }";
    ID3DBlob *code = NULL, *err = NULL;
    HRESULT hr = D3DCompile(src, strlen(src), "s.hlsl", NULL, NULL, "main", "ps_3_0",
                            0, 0, &code, &err);
    if (FAILED(hr)) { printf("compile failed\n"); return 1; }

    DWORD *words = (DWORD *)code->GetBufferPointer();
    size_t count = code->GetBufferSize() / 4, sincos = (size_t)-1;
    for (size_t i = 0; i < count; i++)
        if ((words[i] & 0xFFFF) == 0x25) { sincos = i; break; }
    if (sincos == (size_t)-1) { printf("no SINCOS\n"); return 2; }

    DWORD t = words[sincos + 1];
    t &= ~0x7FFu;                       /* register number */
    t |= (DWORD)(index & 0x7FF);
    t &= ~(0x7u << 28);                 /* register type */
    t |= ((DWORD)(regtype & 0x7) << 28);
    t &= ~(0xFu << 24);                 /* source modifier */
    t |= ((DWORD)(srcmod & 0xF) << 24);
    words[sincos + 1] = t;
    printf("mutate regtype=%d index=%d srcmod=%d -> 0x%08lx\n",
           regtype, index, srcmod, (unsigned long)t);

    HWND hwnd = make_window();
    IDirect3D9 *d3d = Direct3DCreate9(D3D_SDK_VERSION);
    D3DPRESENT_PARAMETERS pp = {0};
    pp.Windowed = TRUE; pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    pp.BackBufferFormat = D3DFMT_X8R8G8B8;
    pp.BackBufferWidth = 64; pp.BackBufferHeight = 64; pp.hDeviceWindow = hwnd;
    IDirect3DDevice9 *dev = NULL;
    hr = d3d->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd,
                           D3DCREATE_HARDWARE_VERTEXPROCESSING | D3DCREATE_FPU_PRESERVE,
                           &pp, &dev);
    if (FAILED(hr)) { printf("device failed\n"); return 4; }
    IDirect3DPixelShader9 *sh = NULL;
    hr = dev->CreatePixelShader(words, &sh);
    printf("hr=0x%08lx\n", (unsigned long)hr);
    if (sh) sh->Release();
    dev->Release(); d3d->Release();
    return 0;
}
