__global__ void cpg_probe(int *p)
{
    if (p != 0) {
        p[threadIdx.x] = 1;
    }
}
