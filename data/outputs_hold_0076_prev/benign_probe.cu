extern "C" __global__ void cpg_probe(int *out)
{
    if (threadIdx.x == 0) {
        out[0] = 1;
    }
}
