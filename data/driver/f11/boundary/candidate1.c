#include <windows.h>
#include <cuda.h>
#include <stdio.h>
#include <stdint.h>

typedef CUresult (CUDAAPI *PFN_cuInit)(unsigned int Flags);
typedef CUresult (CUDAAPI *PFN_cuMemAlloc)(CUdeviceptr *dptr, size_t bytesize);
typedef CUresult (CUDAAPI *PFN_cuMemFree)(CUdeviceptr dptr);
typedef CUresult (CUDAAPI *PFN_cuCtxDestroy)(CUcontext ctx);

static void print_api(const char *name, CUresult rc)
{
    printf("API %s = %d\n", name, (int)rc);
}

int main(void)
{
    HMODULE h = LoadLibraryA("nvcuda.dll");
    if (!h) {
        printf("API LoadLibrary(nvcuda.dll) = %lu\n", (unsigned long)GetLastError());
        printf("BOUNDARY=DONE\n");
        return 0;
    }

    PFN_cuInit cuInit = (PFN_cuInit)GetProcAddress(h, "cuInit");
    PFN_cuMemAlloc cuMemAlloc = (PFN_cuMemAlloc)GetProcAddress(h, "cuMemAlloc");
    if (!cuMemAlloc) {
        cuMemAlloc = (PFN_cuMemAlloc)GetProcAddress(h, "cuMemAlloc_v2");
    }
    PFN_cuMemFree cuMemFree = (PFN_cuMemFree)GetProcAddress(h, "cuMemFree");
    if (!cuMemFree) {
        cuMemFree = (PFN_cuMemFree)GetProcAddress(h, "cuMemFree_v2");
    }
    PFN_cuCtxDestroy cuCtxDestroy = (PFN_cuCtxDestroy)GetProcAddress(h, "cuCtxDestroy");
    if (!cuCtxDestroy) {
        cuCtxDestroy = (PFN_cuCtxDestroy)GetProcAddress(h, "cuCtxDestroy_v2");
    }

    if (!cuInit || !cuMemAlloc || !cuCtxDestroy) {
        printf("API GetProcAddress = -1\n");
        FreeLibrary(h);
        printf("BOUNDARY=DONE\n");
        return 0;
    }

    CUresult rc = cuInit(0);
    print_api("cuInit", rc);

    CUdeviceptr dPtr = 0;
    rc = cuMemAlloc(&dPtr, 0);
    print_api("cuMemAlloc", rc);

    if (rc == CUDA_SUCCESS && dPtr != 0 && cuMemFree) {
        CUresult freeRc = cuMemFree(dPtr);
        print_api("cuMemFree", freeRc);
    }

    rc = cuCtxDestroy((CUcontext)0);
    print_api("cuCtxDestroy", rc);

    FreeLibrary(h);
    printf("BOUNDARY=DONE\n");
    return 0;
}