extern "C" __global__ void cpg_entry(int *out) { out[threadIdx.x] = 1; }
