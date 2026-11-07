#include <cuda.h>
#include <stdio.h>

#ifdef _MSC_VER
#pragma comment(lib, "cuda.lib")
#endif

int main(void)
{
    CUresult res;
    CUdevice device;
    CUcontext context = NULL;
    CUdeviceptr dptr = 0;
    unsigned char write_buf[256];
    unsigned char read_buf[256];
    size_t nbytes = 256;
    int i;
    int data_ok = 1;
    int allocated = 0;

    res = cuInit(0);
    printf("API cuInit = %d\n", (int)res);
    if (res != CUDA_SUCCESS) {
        return 0;
    }

    res = cuDeviceGet(&device, 0);
    printf("API cuDeviceGet = %d\n", (int)res);
    if (res != CUDA_SUCCESS) {
        return 0;
    }

    res = cuCtxCreate(&context, 0, device);
    printf("API cuCtxCreate = %d\n", (int)res);
    if (res != CUDA_SUCCESS) {
        return 0;
    }

    res = cuMemAlloc(&dptr, nbytes);
    printf("API cuMemAlloc = %d\n", (int)res);
    if (res == CUDA_SUCCESS) {
        allocated = 1;
    }

    for (i = 0; i < (int)nbytes; ++i) {
        write_buf[i] = (unsigned char)((i * 37 + 11) & 0xff);
        read_buf[i] = 0;
    }

    res = cuMemcpyHtoD(dptr, write_buf, nbytes);
    printf("API cuMemcpyHtoD = %d\n", (int)res);
    if (res != CUDA_SUCCESS) {
        data_ok = 0;
    }

    res = cuMemcpyDtoH(read_buf, dptr, nbytes);
    printf("API cuMemcpyDtoH = %d\n", (int)res);
    if (res != CUDA_SUCCESS) {
        data_ok = 0;
    }

    if (data_ok) {
        for (i = 0; i < (int)nbytes; ++i) {
            if (read_buf[i] != write_buf[i]) {
                data_ok = 0;
                break;
            }
        }
    }

    if (data_ok) {
        printf("DATA=OK\n");
    } else {
        printf("DATA=MISMATCH\n");
    }

    if (allocated) {
        res = cuMemFree(dptr);
        printf("API cuMemFree = %d\n", (int)res);
    } else {
        printf("API cuMemFree = skipped\n");
    }

    res = cuCtxDestroy(context);
    printf("API cuCtxDestroy = %d\n", (int)res);

    return 0;
}