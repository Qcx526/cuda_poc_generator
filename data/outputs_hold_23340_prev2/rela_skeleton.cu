__global__ void rela_probe(int *p) { if (threadIdx.x == 0) { p[0] = 1; } }
void rela_launch(int *p) { rela_probe<<<1, 32>>>(p); }
