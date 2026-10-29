#include <cstdint>

__global__ void cpg_probe_kernel(void *out)
{
    if (threadIdx.x == 0xffffffffu) {
        *(uint32_t *)out = threadIdx.x;
    }
}
