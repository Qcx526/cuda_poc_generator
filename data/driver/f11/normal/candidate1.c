#include <cuda.h>
#include <stdio.h>

int main(void) {
    CUresult res;
    CUdevice dev;
    CUcontext ctx = NULL;
    CUdeviceptr dptr = 0;
    unsigned char host[256];
    unsigned char readback[256];
    int ctx_created = 0;
    int mem_allocated = 0;
    int ok = 0;
    int i;

    for (i = 0; i < 256; ++i) {
        host[i] = (unsigned char)((i * 37 + 11) & 0xff);
    }

    res = cuInit(0);
    printf("API cuInit = %d\n", (int)res);
    if (res != CUDA_SUCCESS) {
        return 1;
    }

    res = cuDeviceGet(&dev, 0);
    printf("API cuDeviceGet = %d\n", (int)res);
    if (res != CUDA_SUCCESS) {
        return 1;
    }

    res = cuCtxCreate(&ctx, 0, dev);
    printf("API cuCtxCreate = %d\n", (int)res);
    if (res != CUDA_SUCCESS) {
        return 1;
    }
    ctx_created = 1;

    res = cuMemAlloc(&dptr, sizeof(host));
    printf("API cuMemAlloc = %d\n", (int)res);
    if (res != CUDA_SUCCESS) {
        goto cleanup;
    }
    mem_allocated = 1;

    res = cuMemcpyHtoD(dptr, host, sizeof(host));
    printf("API cuMemcpyHtoD = %d\n", (int)res);
    if (res != CUDA_SUCCESS) {
        goto cleanup;
    }

    res = cuMemcpyDtoH(readback, dptr, sizeof(readback));
    printf("API cuMemcpyDtoH = %d\n", (int)res);
    if (res != CUDA_SUCCESS) {
        goto cleanup;
    }

    ok = 1;
    for (i = 0; i < (int)sizeof(host); ++i) {
        if (readback[i] != host[i]) {
            ok = 0;
            break;
        }
    }
    printf("DATA=%s\n", ok ? "OK" : "MISMATCH");

cleanup:
    if (mem_allocated) {
        res = cuMemFree(dptr);
        printf("API cuMemFree = %d\n", (int)res);
    }

    if (ctx_created) {
        res = cuCtxDestroy(ctx);
        printf("API cuCtxDestroy = %d\n", (int)res);
    }

    return ok ? 0 : 1;
}