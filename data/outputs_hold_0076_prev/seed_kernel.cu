__global__ void k(float *p) { p[threadIdx.x] = threadIdx.x * 2.0f; }
