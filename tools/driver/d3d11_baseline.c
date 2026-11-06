/* Minimal normal D3D11/DXGI workload, used as the "legal operation" baseline.
 *
 * It does exactly what a user application does: pick the NVIDIA adapter by LUID,
 * create a hardware device, clear and present one frame, then release everything.
 * No private escape is constructed here.
 */

#define COBJMACROS
#include <windows.h>
#include <dxgi1_2.h>
#include <d3d11.h>
#include <stdio.h>

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    return DefWindowProcW(h, m, w, l);
}

static HWND make_hidden_window(void)
{
    WNDCLASSW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"cpg_baseline_wnd";
    RegisterClassW(&wc);
    return CreateWindowExW(0, wc.lpszClassName, L"cpg", WS_OVERLAPPEDWINDOW,
                           0, 0, 64, 64, NULL, NULL, wc.hInstance, NULL);
}

int main(void)
{
    HRESULT hr;
    IDXGIFactory1 *factory = NULL;
    IDXGIAdapter1 *chosen = NULL;
    DXGI_ADAPTER_DESC1 desc;
    ID3D11Device *device = NULL;
    ID3D11DeviceContext *context = NULL;
    IDXGISwapChain *swap = NULL;
    ID3D11RenderTargetView *rtv = NULL;
    IDXGIDevice *dxgi_device = NULL;
    IDXGIAdapter *device_adapter = NULL;
    DXGI_ADAPTER_DESC device_desc;
    LUID chosen_luid;
    ZeroMemory(&chosen_luid, sizeof(chosen_luid));
    D3D_FEATURE_LEVEL level = 0;
    HWND hwnd;
    UINT i;

    hr = CreateDXGIFactory1(&IID_IDXGIFactory1, (void **)&factory);
    printf("DXGI_FACTORY hr=0x%08lx\n", (unsigned long)hr);
    if (FAILED(hr)) return 1;

    for (i = 0; ; i++) {
        IDXGIAdapter1 *adapter = NULL;
        hr = IDXGIFactory1_EnumAdapters1(factory, i, &adapter);
        if (hr == DXGI_ERROR_NOT_FOUND) break;
        if (FAILED(hr)) break;
        if (SUCCEEDED(IDXGIAdapter1_GetDesc1(adapter, &desc))) {
            printf("ADAPTER index=%u vendor=0x%04x device=0x%04x luid=%08lx:%08lx vram=%llu name=%ls\n",
                   i, desc.VendorId, desc.DeviceId,
                   (unsigned long)desc.AdapterLuid.HighPart,
                   (unsigned long)desc.AdapterLuid.LowPart,
                   (unsigned long long)desc.DedicatedVideoMemory, desc.Description);
            if (!chosen && desc.VendorId == 0x10DE) {
                chosen = adapter;
                chosen_luid = desc.AdapterLuid;   /* desc is reused per adapter */
                continue;   /* keep the reference */
            }
        }
        IDXGIAdapter1_Release(adapter);
    }
    printf("CHOSEN vendor=%s\n", chosen ? "nvidia" : "none");
    if (!chosen) return 2;

    hwnd = make_hidden_window();
    printf("WINDOW hwnd=%p\n", (void *)hwnd);

    {
        D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1 };
        hr = D3D11CreateDevice((IDXGIAdapter *)chosen, D3D_DRIVER_TYPE_UNKNOWN, NULL,
                               D3D11_CREATE_DEVICE_BGRA_SUPPORT, levels, 2,
                               D3D11_SDK_VERSION, &device, &level, &context);
    }
    printf("D3D11_DEVICE hr=0x%08lx feature_level=0x%x\n", (unsigned long)hr, (unsigned)level);
    if (FAILED(hr)) return 3;

    /* Device -> adapter association, the link between D3D11 and D3DKMT identities. */
    if (SUCCEEDED(ID3D11Device_QueryInterface(device, &IID_IDXGIDevice, (void **)&dxgi_device))) {
        if (SUCCEEDED(IDXGIDevice_GetAdapter(dxgi_device, &device_adapter))) {
            if (SUCCEEDED(IDXGIAdapter_GetDesc(device_adapter, &device_desc))) {
                printf("DEVICE_ADAPTER luid=%08lx:%08lx matches_chosen=%s\n",
                       (unsigned long)device_desc.AdapterLuid.HighPart,
                       (unsigned long)device_desc.AdapterLuid.LowPart,
                       (device_desc.AdapterLuid.LowPart == chosen_luid.LowPart &&
                        device_desc.AdapterLuid.HighPart == chosen_luid.HighPart) ? "yes" : "no");
            }
        }
    }

    {
        DXGI_SWAP_CHAIN_DESC sd;
        ZeroMemory(&sd, sizeof(sd));
        sd.BufferCount = 1;
        sd.BufferDesc.Width = 64;
        sd.BufferDesc.Height = 64;
        sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        sd.OutputWindow = hwnd;
        sd.SampleDesc.Count = 1;
        sd.Windowed = TRUE;
        sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
        hr = IDXGIFactory1_CreateSwapChain(factory, (IUnknown *)device, &sd, &swap);
    }
    printf("SWAPCHAIN hr=0x%08lx\n", (unsigned long)hr);

    if (SUCCEEDED(hr)) {
        ID3D11Texture2D *back = NULL;
        hr = IDXGISwapChain_GetBuffer(swap, 0, &IID_ID3D11Texture2D, (void **)&back);
        if (SUCCEEDED(hr)) {
            hr = ID3D11Device_CreateRenderTargetView(device, (ID3D11Resource *)back, NULL, &rtv);
            ID3D11Texture2D_Release(back);
        }
        printf("RTV hr=0x%08lx\n", (unsigned long)hr);

        if (SUCCEEDED(hr)) {
            FLOAT colour[4] = { 0.1f, 0.2f, 0.3f, 1.0f };
            ID3D11DeviceContext_ClearRenderTargetView(context, rtv, colour);
            printf("RENDER clear=ok\n");
            hr = IDXGISwapChain_Present(swap, 0, 0);
            printf("PRESENT hr=0x%08lx\n", (unsigned long)hr);
        }
    }

    printf("DEVICE_REMOVED reason=0x%08lx\n",
           (unsigned long)(device ? ID3D11Device_GetDeviceRemovedReason(device) : 0));

    if (rtv) ID3D11RenderTargetView_Release(rtv);
    if (swap) IDXGISwapChain_Release(swap);
    if (device_adapter) IDXGIAdapter_Release(device_adapter);
    if (dxgi_device) IDXGIDevice_Release(dxgi_device);
    if (context) ID3D11DeviceContext_Release(context);
    if (device) ID3D11Device_Release(device);
    if (chosen) IDXGIAdapter1_Release(chosen);
    if (factory) IDXGIFactory1_Release(factory);
    if (hwnd) DestroyWindow(hwnd);

    printf("RELEASED all\n");
    return 0;
}
