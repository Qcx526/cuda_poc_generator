/* One mutation per process: flip bit N of the SINCOS instruction, then create the shader. */
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
    int bit = argc > 1 ? atoi(argv[1]) : -1;
    const char *src =
        "float4 main(float2 uv : TEXCOORD0) : COLOR {"
        " float s,c; sincos(uv.x,s,c); return float4(s,c,0,1); }";
    ID3DBlob *code = NULL, *err = NULL;
    HRESULT hr = D3DCompile(src, strlen(src), "s.hlsl", NULL, NULL, "main", "ps_3_0",
                            0, 0, &code, &err);
    if (FAILED(hr)) { printf("compile failed 0x%lx\n", (unsigned long)hr); return 1; }

    DWORD *words = (DWORD *)code->GetBufferPointer();
    size_t count = code->GetBufferSize() / 4;
    size_t sincos = (size_t)-1;
    for (size_t i = 0; i < count; i++) {
        if ((words[i] & 0xFFFF) == 0x25) { sincos = i; break; }   /* D3DSIO_SINCOS */
    }
    if (sincos == (size_t)-1) { printf("no SINCOS\n"); return 2; }

    if (bit >= 0 && bit < 64) {
        size_t word = sincos + (bit / 32);
        size_t b = bit % 32;
        if (word >= count) { printf("bit out of range\n"); return 3; }
        words[word] ^= (1u << b);
        printf("flip bit %d (dword %zu, bit %zu): 0x%08lx\n", bit, word, b,
               (unsigned long)words[word]);
    } else {
        printf("baseline (no flip) sincos at dword %zu: 0x%08lx 0x%08lx\n",
               sincos, (unsigned long)words[sincos], (unsigned long)words[sincos+1]);
    }

    HWND hwnd = make_window();
    IDirect3D9 *d3d = Direct3DCreate9(D3D_SDK_VERSION);
    D3DPRESENT_PARAMETERS pp = {0};
    pp.Windowed = TRUE;
    pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    pp.BackBufferFormat = D3DFMT_X8R8G8B8;
    pp.BackBufferWidth = 64; pp.BackBufferHeight = 64;
    pp.hDeviceWindow = hwnd;
    IDirect3DDevice9 *dev = NULL;
    hr = d3d->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd,
                           D3DCREATE_HARDWARE_VERTEXPROCESSING | D3DCREATE_FPU_PRESERVE,
                           &pp, &dev);
    if (FAILED(hr)) { printf("device failed 0x%lx\n", (unsigned long)hr); return 4; }

    IDirect3DPixelShader9 *sh = NULL;
    hr = dev->CreatePixelShader(words, &sh);
    printf("CreatePixelShader hr=0x%08lx\n", (unsigned long)hr);
    if (sh) sh->Release();
    dev->Release(); d3d->Release();
    return 0;
}
