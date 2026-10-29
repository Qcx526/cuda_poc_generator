
__global__ void baseline_kernel(float *p)
{
    p[threadIdx.x] = 1.0f;
}
