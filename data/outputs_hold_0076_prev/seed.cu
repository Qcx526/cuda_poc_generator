__global__ void k(int *p) { p[threadIdx.x] = threadIdx.x; }
