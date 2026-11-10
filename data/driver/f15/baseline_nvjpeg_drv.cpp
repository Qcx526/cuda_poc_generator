// nvJPEG decoder that talks to the driver API directly.
//
// The 13.x library must not be mixed with the 11.2 runtime, so allocation goes through
// cuda.h instead of cudart: the driver ABI is stable across these versions and the
// driver on this machine is new enough for both.
#include <cstdio>
#include <cstring>
#include <vector>
#include <nvjpeg.h>
#include <cuda.h>

static const char *st(nvjpegStatus_t s) {
    switch (s) {
        case NVJPEG_STATUS_SUCCESS: return "SUCCESS";
        case NVJPEG_STATUS_NOT_INITIALIZED: return "NOT_INITIALIZED";
        case NVJPEG_STATUS_INVALID_PARAMETER: return "INVALID_PARAMETER";
        case NVJPEG_STATUS_BAD_JPEG: return "BAD_JPEG";
        case NVJPEG_STATUS_JPEG_NOT_SUPPORTED: return "JPEG_NOT_SUPPORTED";
        case NVJPEG_STATUS_ALLOCATOR_FAILURE: return "ALLOCATOR_FAILURE";
        case NVJPEG_STATUS_EXECUTION_FAILED: return "EXECUTION_FAILED";
        default: return "OTHER";
    }
}

int main(int argc, char **argv) {
    if (argc < 2) { printf("usage: %s <file.jpg>\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { printf("OPEN_FAILED\n"); return 2; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::vector<unsigned char> data((size_t)size);
    if (fread(data.data(), 1, (size_t)size, f) != (size_t)size) { printf("READ_FAILED\n"); return 2; }
    fclose(f);

    CUresult cu = cuInit(0);
    printf("cuInit=%d\n", (int)cu);
    CUcontext ctx = nullptr;
    if (cu == CUDA_SUCCESS) {
        CUdevice dev;
        cuDeviceGet(&dev, 0);
        cuCtxCreate(&ctx, 0, dev);
    }

    nvjpegHandle_t handle = nullptr;
    nvjpegStatus_t rc = nvjpegCreateSimple(&handle);
    printf("nvjpegCreateSimple=%s\n", st(rc));
    if (rc != NVJPEG_STATUS_SUCCESS) return 1;

    nvjpegJpegState_t state = nullptr;
    rc = nvjpegJpegStateCreate(handle, &state);
    printf("nvjpegJpegStateCreate=%s\n", st(rc));

    int components = 0, widths[NVJPEG_MAX_COMPONENT] = {0}, heights[NVJPEG_MAX_COMPONENT] = {0};
    nvjpegChromaSubsampling_t subsampling;
    rc = nvjpegGetImageInfo(handle, data.data(), (size_t)size, &components, &subsampling,
                            widths, heights);
    printf("nvjpegGetImageInfo=%s components=%d %dx%d\n", st(rc), components,
           widths[0], heights[0]);
    if (rc != NVJPEG_STATUS_SUCCESS) return 1;

    nvjpegImage_t out;
    memset(&out, 0, sizeof(out));
    // RGBI is 3 bytes per pixel regardless of the source component count.
    size_t pitch = (size_t)widths[0] * 3;
    CUdeviceptr dev = 0;
    CUresult al = cuMemAlloc(&dev, pitch * heights[0]);
    printf("cuMemAlloc=%d\n", (int)al);
    out.channel[0] = (unsigned char *)dev;
    out.pitch[0] = pitch;

    rc = nvjpegDecode(handle, state, data.data(), (size_t)size, NVJPEG_OUTPUT_RGBI, &out, 0);
    printf("nvjpegDecode=%s\n", st(rc));
    if (rc == NVJPEG_STATUS_SUCCESS) {
        std::vector<unsigned char> host(pitch * heights[0]);
        CUresult cp = cuMemcpyDtoH(host.data(), dev, host.size());
        printf("cuMemcpyDtoH=%d\n", (int)cp);
        unsigned long sum = 0;
        for (size_t i = 0; i < host.size(); ++i) sum = (sum * 131 + host[i]) & 0xffffffffUL;
        printf("PIXELS=%zu CHECKSUM=%lu\n", host.size(), sum);
    }

    cuMemFree(dev);
    nvjpegJpegStateDestroy(state);
    nvjpegDestroy(handle);
    if (ctx) cuCtxDestroy(ctx);
    printf("BASELINE=DONE\n");
    return rc == NVJPEG_STATUS_SUCCESS ? 0 : 1;
}
