// Minimal nvJPEG baseline: prove the library actually decodes on this machine.
// Every status is printed; nothing about success is assumed.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <nvjpeg.h>
#include <cuda_runtime_api.h>

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
    if (argc < 2) { printf("usage: %s <file.jpg>\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { printf("OPEN_FAILED\n"); return 2; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::vector<unsigned char> data(size);
    if (fread(data.data(), 1, size, f) != (size_t)size) { printf("READ_FAILED\n"); return 2; }
    fclose(f);

    nvjpegHandle_t handle = nullptr;
    nvjpegStatus_t rc = nvjpegCreateSimple(&handle);
    printf("nvjpegCreateSimple=%s\n", st(rc));
    if (rc != NVJPEG_STATUS_SUCCESS) return 1;

    nvjpegJpegState_t state = nullptr;
    rc = nvjpegJpegStateCreate(handle, &state);
    printf("nvjpegJpegStateCreate=%s\n", st(rc));

    int components = 0, widths[NVJPEG_MAX_COMPONENT] = {0}, heights[NVJPEG_MAX_COMPONENT] = {0};
    nvjpegChromaSubsampling_t subsampling;
    rc = nvjpegGetImageInfo(handle, data.data(), size, &components, &subsampling,
                            widths, heights);
    printf("nvjpegGetImageInfo=%s components=%d %dx%d\n", st(rc), components,
           widths[0], heights[0]);
    if (rc != NVJPEG_STATUS_SUCCESS) return 1;

    nvjpegImage_t out;
    memset(&out, 0, sizeof(out));
    size_t pitch = (size_t)widths[0] * components;
    unsigned char *dev = nullptr;
    cudaError_t ce = cudaMalloc((void **)&dev, pitch * heights[0]);
    printf("cudaMalloc=%s\n", cudaGetErrorString(ce));
    out.channel[0] = dev;
    out.pitch[0] = pitch;

    rc = nvjpegDecode(handle, state, data.data(), size, NVJPEG_OUTPUT_RGBI, &out, 0);
    printf("nvjpegDecode=%s\n", st(rc));
    if (rc == NVJPEG_STATUS_SUCCESS) {
        std::vector<unsigned char> host(pitch * heights[0]);
        ce = cudaMemcpy(host.data(), dev, host.size(), cudaMemcpyDeviceToHost);
        printf("cudaMemcpy=%s\n", cudaGetErrorString(ce));
        unsigned long sum = 0;
        for (size_t i = 0; i < host.size(); ++i) sum = (sum * 131 + host[i]) & 0xffffffffUL;
        printf("PIXELS=%zu CHECKSUM=%lu\n", host.size(), sum);
    }

    cudaFree(dev);
    nvjpegJpegStateDestroy(state);
    nvjpegDestroy(handle);
    printf("BASELINE=DONE\n");
    return rc == NVJPEG_STATUS_SUCCESS ? 0 : 1;
}
