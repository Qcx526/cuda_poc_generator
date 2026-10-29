__global__ void cpg_kernel(float *out) { out[threadIdx.x] = 1.0f; }
__device__ float cpg_state = 2.0f;
__constant__ float cpg_const = 3.0f;
