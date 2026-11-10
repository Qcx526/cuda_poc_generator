// nvJPEG probe: decode one file with one named DLL, reporting every stage.
//
// Contract notes that earlier versions of this file got wrong:
//   * NVJPEG_OUTPUT_RGBI is three bytes per pixel regardless of source component count,
//     so the buffer is width*3*height. Sizing it at width*components under-allocates a
//     grayscale image by 3x and the library writes past the end without any error.
//   * The single-image nvjpegDecodePhaseOne/Two/Three entry points were removed in
//     CUDA 11.0. Only the batched forms exist, and they are a different contract, so
//     this probe uses the one supported single-image call.
//   * A decode that returns SUCCESS but cannot be synchronised or copied back has not
//     produced pixels. Stage 7 therefore participates in the verdict.
//   * The DLL is an argument, so the identity in the record is the identity that ran.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <windows.h>
#include <cuda.h>
#include <nvjpeg.h>

typedef nvjpegStatus_t (NVJPEGAPI *fn_get_property)(libraryPropertyType, int *);
typedef nvjpegStatus_t (NVJPEGAPI *fn_create)(nvjpegHandle_t *);
typedef nvjpegStatus_t (NVJPEGAPI *fn_state_create)(nvjpegHandle_t, nvjpegJpegState_t *);
typedef nvjpegStatus_t (NVJPEGAPI *fn_state_destroy)(nvjpegJpegState_t);
typedef nvjpegStatus_t (NVJPEGAPI *fn_destroy)(nvjpegHandle_t);
typedef nvjpegStatus_t (NVJPEGAPI *fn_image_info)(nvjpegHandle_t, const unsigned char *,
                                                 size_t, int *, nvjpegChromaSubsampling_t *,
                                                 int *, int *);
typedef nvjpegStatus_t (NVJPEGAPI *fn_decode)(nvjpegHandle_t, nvjpegJpegState_t,
                                              const unsigned char *, size_t,
                                              nvjpegOutputFormat_t, nvjpegImage_t *,
                                              cudaStream_t);

static const char *st(nvjpegStatus_t s) {
    switch (s) {
        case NVJPEG_STATUS_SUCCESS: return "SUCCESS";
        case NVJPEG_STATUS_NOT_INITIALIZED: return "NOT_INITIALIZED";
        case NVJPEG_STATUS_INVALID_PARAMETER: return "INVALID_PARAMETER";
        case NVJPEG_STATUS_BAD_JPEG: return "BAD_JPEG";
        case NVJPEG_STATUS_JPEG_NOT_SUPPORTED: return "JPEG_NOT_SUPPORTED";
        case NVJPEG_STATUS_ALLOCATOR_FAILURE: return "ALLOCATOR_FAILURE";
        case NVJPEG_STATUS_EXECUTION_FAILED: return "EXECUTION_FAILED";
        case NVJPEG_STATUS_ARCH_MISMATCH: return "ARCH_MISMATCH";
        case NVJPEG_STATUS_IMPLEMENTATION_NOT_SUPPORTED: return "IMPL_NOT_SUPPORTED";
        default: return "OTHER";
    }
}

int main(int argc, char **argv) {
    std::string dll, path;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--dll" && i + 1 < argc) dll = argv[++i];
        else if (a == "--file" && i + 1 < argc) path = argv[++i];
    }
    if (dll.empty() || path.empty()) {
        printf("usage: %s --dll <nvjpeg.dll> --file <file.jpg>\n", argv[0]);
        return 2;
    }

    HMODULE mod = LoadLibraryA(dll.c_str());
    printf("STAGE1 load_dll=%s\n", mod ? "OK" : "FAILED");
    if (!mod) return 2;

    fn_get_property get_property = (fn_get_property)GetProcAddress(mod, "nvjpegGetProperty");
    fn_create create = (fn_create)GetProcAddress(mod, "nvjpegCreateSimple");
    fn_state_create state_create = (fn_state_create)GetProcAddress(mod, "nvjpegJpegStateCreate");
    fn_state_destroy state_destroy = (fn_state_destroy)GetProcAddress(mod, "nvjpegJpegStateDestroy");
    fn_destroy destroy = (fn_destroy)GetProcAddress(mod, "nvjpegDestroy");
    fn_image_info image_info = (fn_image_info)GetProcAddress(mod, "nvjpegGetImageInfo");
    fn_decode decode = (fn_decode)GetProcAddress(mod, "nvjpegDecode");
    if (!get_property || !create || !state_create || !image_info || !decode) {
        printf("STAGE1 symbols=MISSING\n");
        return 2;
    }
    int major = 0, minor = 0, patch = 0;
    get_property(MAJOR_VERSION, &major);
    get_property(MINOR_VERSION, &minor);
    get_property(PATCH_LEVEL, &patch);
    printf("LIB version=%d.%d.%d\n", major, minor, patch);
    printf("LIB dll_path=%s\n", dll.c_str());

    FILE *f = fopen(path.c_str(), "rb");
    printf("STAGE2 file_open=%s\n", f ? "OK" : "FAILED");
    if (!f) return 2;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::vector<unsigned char> data((size_t)(size > 0 ? size : 0));
    bool read_ok = size > 0 && fread(data.data(), 1, (size_t)size, f) == (size_t)size;
    fclose(f);
    printf("STAGE2 file_read=%s bytes=%ld\n", read_ok ? "OK" : "FAILED", size);
    if (!read_ok) return 2;

    CUresult cu = cuInit(0);
    CUcontext ctx = nullptr;
    if (cu == CUDA_SUCCESS) {
        CUdevice dev = 0;
        CUdeviceGet(&dev, 0);
        cuDevicePrimaryCtxRetain(&ctx, dev);
        cuCtxSetCurrent(ctx);
    }
    printf("STAGE3 cuInit=%d\n", (int)cu);
    if (cu != CUDA_SUCCESS) return 2;

    nvjpegHandle_t handle = nullptr;
    nvjpegStatus_t rc = create(&handle);
    printf("STAGE3 nvjpegCreateSimple=%s\n", st(rc));
    if (rc != NVJPEG_STATUS_SUCCESS) return 1;

    nvjpegJpegState_t state = nullptr;
    rc = state_create(handle, &state);
    printf("STAGE3 nvjpegJpegStateCreate=%s\n", st(rc));
    if (rc != NVJPEG_STATUS_SUCCESS) { destroy(handle); return 1; }

    int components = 0, widths[NVJPEG_MAX_COMPONENT] = {0}, heights[NVJPEG_MAX_COMPONENT] = {0};
    nvjpegChromaSubsampling_t subsampling;
    rc = image_info(handle, data.data(), (size_t)size, &components, &subsampling, widths, heights);
    printf("STAGE4 nvjpegGetImageInfo=%s components=%d %dx%d subsampling=%d\n",
           st(rc), components, widths[0], heights[0], (int)subsampling);
    if (rc != NVJPEG_STATUS_SUCCESS) {
        state_destroy(state);
        destroy(handle);
        return 1;
    }

    // RGBI is three bytes per pixel whatever the source component count.
    size_t pitch = (size_t)widths[0] * 3;
    size_t bytes = pitch * (size_t)heights[0];
    nvjpegImage_t out;
    memset(&out, 0, sizeof(out));
    CUdeviceptr dev = 0;
    CUresult al = cuMemAlloc(&dev, bytes);
    printf("STAGE5 cuMemAlloc=%d pitch=%zu bytes=%zu\n", (int)al, pitch, bytes);
    if (al != CUDA_SUCCESS) {
        state_destroy(state);
        destroy(handle);
        return 1;
    }
    out.channel[0] = (unsigned char *)dev;
    out.pitch[0] = pitch;

    rc = decode(handle, state, data.data(), (size_t)size, NVJPEG_OUTPUT_RGBI, &out, nullptr);
    printf("STAGE6 nvjpegDecode=%s\n", st(rc));

    bool stage7_ok = false;
    if (rc == NVJPEG_STATUS_SUCCESS) {
        CUresult sync = cuCtxSynchronize();
        printf("STAGE7 cuCtxSynchronize=%d\n", (int)sync);
        std::vector<unsigned char> host(bytes);
        CUresult cp = (sync == CUDA_SUCCESS)
                          ? cuMemcpyDtoH(host.data(), dev, bytes)
                          : CUDA_ERROR_UNKNOWN;
        printf("STAGE7 cuMemcpyDtoH=%d\n", (int)cp);
        stage7_ok = (sync == CUDA_SUCCESS && cp == CUDA_SUCCESS);
        if (stage7_ok) {
            unsigned long sum = 0;
            for (size_t i = 0; i < bytes; ++i) sum = (sum * 131 + host[i]) & 0xffffffffUL;
            printf("PIXELS=%zu CHECKSUM=%lu\n", bytes, sum);
        }
    }

    cuMemFree(dev);
    state_destroy(state);
    destroy(handle);

    const char *stage = (rc != NVJPEG_STATUS_SUCCESS) ? "6_decode"
                        : stage7_ok ? "7_output" : "7_failed";
    printf("VERDICT last_success_stage=%s\n", stage);
    if (rc != NVJPEG_STATUS_SUCCESS) return 1;
    return stage7_ok ? 0 : 3;
}
