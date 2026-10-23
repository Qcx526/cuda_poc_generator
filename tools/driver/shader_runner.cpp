/* shader_runner: one job - get a ps_3_0 shader in front of the driver compiler.
 *
 *   shader_runner compile <out.bin>            compile HLSL, dump bytecode
 *   shader_runner assemble <in.asm> <out.bin>  assemble shader-model 3 text, dump bytecode
 *   shader_runner bytecode <in.bin>            create a pixel shader from raw bytecode
 *   shader_runner assemble <in.asm> <out.bin> vs   ... same, but vertex shader
 *
 * Exit code: 0 = accepted, 1 = rejected, anything else = the process faulted
 * (which is exactly what a reproducing input looks like).
 */
#include <windows.h>
#include <d3d9.h>
#include <d3dcompiler.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static HWND make_window(void) {
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "CpgWnd";
    RegisterClassA(&wc);
    return CreateWindowExA(0, "CpgWnd", "cpg", WS_OVERLAPPEDWINDOW,
                           0, 0, 64, 64, NULL, NULL, wc.hInstance, NULL);
}

typedef HRESULT (WINAPI *D3DAssemble_t)(LPCVOID, SIZE_T, LPCSTR, const void *, void *,
                                        UINT, ID3DBlob **, ID3DBlob **, HRESULT *);

static IDirect3DDevice9 *make_device(void) {
    HWND hwnd = make_window();
    IDirect3D9 *d3d = Direct3DCreate9(D3D_SDK_VERSION);
    if (!d3d) return NULL;
    D3DPRESENT_PARAMETERS pp = {0};
    pp.Windowed = TRUE;
    pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    pp.BackBufferFormat = D3DFMT_X8R8G8B8;
    pp.BackBufferWidth = 64; pp.BackBufferHeight = 64;
    pp.hDeviceWindow = hwnd;
    IDirect3DDevice9 *dev = NULL;
    HRESULT hr = d3d->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd,
                                   D3DCREATE_HARDWARE_VERTEXPROCESSING | D3DCREATE_FPU_PRESERVE,
                                   &pp, &dev);
    d3d->Release();
    return SUCCEEDED(hr) ? dev : NULL;
}

int main(int argc, char **argv) {
    if (argc < 3) { printf("usage: %s compile|bytecode <path>\n", argv[0]); return 2; }
    const char *mode = argv[1], *path = argv[2];
    static DWORD words[4096];
    size_t count = 0;

    if (strcmp(mode, "compile") == 0) {
        const char *src =
            "float4 main(float2 uv : TEXCOORD0) : COLOR {"
            " float s,c; sincos(uv.x,s,c); return float4(s,c,0,1); }";
        ID3DBlob *code = NULL, *err = NULL;
        HRESULT hr = D3DCompile(src, strlen(src), "s.hlsl", NULL, NULL, "main", "ps_3_0",
                                0, 0, &code, &err);
        if (FAILED(hr)) { printf("compile failed 0x%lx\n", (unsigned long)hr); return 1; }
        count = code->GetBufferSize() / 4;
        memcpy(words, code->GetBufferPointer(), code->GetBufferSize());
        FILE *f = fopen(path, "wb");
        if (!f) { printf("cannot write %s\n", path); return 1; }
        fwrite(words, 4, count, f);
        fclose(f);
        printf("compiled %zu dwords -> %s\n", count, path);
        code->Release();
    } else if (strcmp(mode, "assemble") == 0) {
        if (argc < 4) { printf("usage: %s assemble <in.asm> <out.bin>\n", argv[0]); return 2; }
        FILE *in = fopen(path, "rb");
        if (!in) { printf("cannot read %s\n", path); return 1; }
        static char text[65536];
        size_t n = fread(text, 1, sizeof(text) - 1, in);
        text[n] = 0;
        fclose(in);
        HMODULE lib = LoadLibraryA("d3dcompiler_47.dll");
        D3DAssemble_t assemble = (D3DAssemble_t)GetProcAddress(lib, "D3DAssemble");
        if (!assemble) { printf("no D3DAssemble\n"); return 1; }
        ID3DBlob *code = NULL, *err = NULL;
        HRESULT hra = assemble(text, n, path, NULL, NULL, 0, &code, &err, NULL);
        if (FAILED(hra)) {
            printf("assemble failed 0x%lx: %s\n", (unsigned long)hra,
                   err ? (char *)err->GetBufferPointer() : "");
            return 1;
        }
        count = code->GetBufferSize() / 4;
        memcpy(words, code->GetBufferPointer(), code->GetBufferSize());
        FILE *f = fopen(argv[3], "wb");
        fwrite(words, 4, count, f);
        fclose(f);
        printf("assembled %zu dwords -> %s\n", count, argv[3]);
        code->Release();
        path = argv[3];
    } else if (strcmp(mode, "bytecode") == 0) {
        FILE *f = fopen(path, "rb");
        if (!f) { printf("cannot read %s\n", path); return 1; }
        count = fread(words, 4, 4096, f);
        fclose(f);
        printf("loaded %zu dwords from %s\n", count, path);
    } else {
        printf("unknown mode %s\n", mode);
        return 2;
    }

    IDirect3DDevice9 *dev = make_device();
    if (!dev) { printf("no device\n"); return 1; }
    int is_vertex = (argc > 4 && strcmp(argv[4], "vs") == 0);
    HRESULT hr;
    if (is_vertex) {
        IDirect3DVertexShader9 *vs = NULL;
        hr = dev->CreateVertexShader(words, &vs);
        printf("CreateVertexShader hr=0x%08lx\n", (unsigned long)hr);
        if (vs) vs->Release();
    } else {
        IDirect3DPixelShader9 *sh = NULL;
        hr = dev->CreatePixelShader(words, &sh);
        printf("CreatePixelShader hr=0x%08lx\n", (unsigned long)hr);
        if (sh) sh->Release();
    }
    dev->Release();
    return SUCCEEDED(hr) ? 0 : 1;
}
