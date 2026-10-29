
extern "C" __global__ void cve_2024_0076_probe(int *out) {
    int tid = threadIdx.x;
    out[tid] = tid * 2;
}
