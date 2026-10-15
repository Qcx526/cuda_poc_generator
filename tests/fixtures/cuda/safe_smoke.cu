// Fixed P2-C device-only compilation fixture. Never launch this kernel.
// No host entry point, CUDA API call, memory access, filesystem or networking.
extern "C" __global__ void cuda_poc_safe_smoke() {}
