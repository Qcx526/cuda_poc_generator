extern "C" __device__ float cve_table[8] = {0.0f,1.0f,2.0f,3.0f,4.0f,5.0f,6.0f,7.0f};
extern "C" __constant__ int cve_const[4] = {1, 2, 3, 4};

__device__ float cve_scale(float x) { return x * 2.0f; }

extern "C" __global__ void cve_kernel_a(float *out)
{
    __shared__ float tile[32];
    unsigned int tid = threadIdx.x;
    tile[tid & 31] = cve_scale(cve_table[tid & 7]) + (float)cve_const[tid & 3];
    __syncthreads();
    out[tid] = tile[tid & 31];
}

extern "C" __global__ void cve_kernel_b(float *out)
{
    out[threadIdx.x] = cve_table[threadIdx.x & 7] + (float)blockIdx.x;
}
