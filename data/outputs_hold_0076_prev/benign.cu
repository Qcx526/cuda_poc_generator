__global__ void cpg_kernel(int *p)
{
    if (p != 0) {
        *p = 1;
    }
}
