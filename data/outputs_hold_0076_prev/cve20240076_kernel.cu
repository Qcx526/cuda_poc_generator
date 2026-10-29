__global__ void k(int *p) { if (threadIdx.x == 0) { p[0] = 1; } }
