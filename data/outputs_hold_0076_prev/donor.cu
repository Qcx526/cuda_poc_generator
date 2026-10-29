__global__ void k(float* p){ p[threadIdx.x] = p[threadIdx.x] * 2.0f; }
