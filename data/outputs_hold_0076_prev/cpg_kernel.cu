__global__ void cpg_kernel(int *out)
{
    out[threadIdx.x] = (int)threadIdx.x;
}
