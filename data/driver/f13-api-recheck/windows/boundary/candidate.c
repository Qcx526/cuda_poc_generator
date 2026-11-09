#include <cuda.h>
#include <stdio.h>

int main(void)
{
    CUresult res;
    CUresult resFree;
    CUdevice dev = 0;
    CUcontext ctx = NULL;
    CUdeviceptr ptrZero = 0;
    CUdeviceptr ptr256 = 0;
    CUdeviceptr ptrInvalid = 0;

    res = cuInit(0);
    printf("API cuInit = %d\n", (int)res);

    res = cuDeviceGet(&dev, 0);
    printf("API cuDeviceGet = %d\n", (int)res);

    res = cuCtxCreate(&ctx, CU_CTX_SCHED_AUTO, dev);
    printf("API cuCtxCreate = %d\n", (int)res);

    if (res == CUDA_SUCCESS && ctx != NULL) {
        res = cuMemAlloc(&ptrZero, 0);
        printf("API cuMemAlloc = %d\n", (int)res);
        if (res == CUDA_SUCCESS && ptrZero != 0) {
            resFree = cuMemFree(ptrZero);
            printf("API cuMemFree = %d\n", (int)resFree);
        }

        res = cuMemAlloc(&ptr256, 256);
        printf("API cuMemAlloc = %d\n", (int)res);
        if (res == CUDA_SUCCESS && ptr256 != 0) {
            resFree = cuMemFree(ptr256);
            printf("API cuMemFree = %d\n", (int)resFree);
        }

        res = cuCtxDestroy(ctx);
        printf("API cuCtxDestroy = %d\n", (int)res);
        if (res == CUDA_SUCCESS) {
            ctx = NULL;
        }
    }

    res = cuMemAlloc(&ptrInvalid, 256);
    printf("API cuMemAlloc = %d\n", (int)res);
    if (res == CUDA_SUCCESS && ptrInvalid != 0) {
        resFree = cuMemFree(ptrInvalid);
        printf("API cuMemFree = %d\n", (int)resFree);
    }

    if (ctx != NULL) {
        res = cuCtxDestroy(ctx);
        printf("API cuCtxDestroy = %d\n", (int)res);
        ctx = NULL;
    }

    printf("BOUNDARY=DONE\n");
    return 0;
}