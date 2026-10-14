<!-- Entirely synthetic offline Windows/WSL fixture; not the real probe result. -->

# Read-only platform probe report

This is a platform observation record, not a vulnerability verification report.
Candidate execution: NOT_EXECUTED. Vulnerability verification: NOT_VERIFIED.

Probe status: COMPLETE

## Development host (local)

Platform: windows; backend: local
Content identity: sha256:796c75135e8aa636127579d47765d765da08880e7fe3b69fceb0ae5854c62f81 (local integrity hash, not hardware attestation)

| Field | Status | Value (redacted) | Source / method |
|---|---|---|---|
| host_os | OBSERVED | Fixture Windows | os_release: read /etc/os-release PRETTY_NAME |
| kernel | OBSERVED | 10.0.fixture | python_stdlib: platform.version (Windows) / platform.release (Linux) |
| architecture | OBSERVED | AMD64 | python_stdlib: platform.machine |
| python_version | OBSERVED | 3.12.0 | python_stdlib: platform.python_version |
| gpu_devices | OBSERVED | [{'index': 0, 'name': 'Fixture GPU A', 'compute_capability': '7.5', 'sm_arch': 'sm_75'}, {'index': 1, 'name': 'Fixture GPU B', 'compute_capability': '8.6', 'sm_arch': 'sm_86'}] | gpu_query: nvidia-smi per-device CSV query |
| driver_release | OBSERVED | 555.42 | gpu_query: nvidia-smi driver_version |
| cuda_driver_api_version | NOT_CHECKED | unknown | : CUDA Driver API not loaded by read-only probe |
| driver_reported_cuda_version | OBSERVED | 12.4 | smi_banner: nvidia-smi banner CUDA compatibility, not Driver API or Toolkit |
| cuda_toolkit_version | OBSERVED | 12.8 | nvcc_version: nvcc --version release |
| nvcc_path | OBSERVED | [private directory]/nvcc.exe | filesystem: existing nvcc executable discovery |
| nvcc_version | OBSERVED | 12.8.93 | nvcc_version: nvcc --version compiler build |
| supported_architectures | OBSERVED | ['compute_75', 'compute_86', 'sm_75', 'sm_86'] | nvcc_gpu_code, nvcc_gpu_arch: nvcc --list-gpu-code and --list-gpu-arch |
| compute_sanitizer_path | OBSERVED | [private directory]/compute-sanitizer.exe | filesystem: existing Compute Sanitizer executable discovery |
| compute_sanitizer_version | OBSERVED | 2025.1.0.0 | sanitizer_version: compute-sanitizer --version |
| host_compiler | OBSERVED | {'msvc': {'status': 'OBSERVED', 'value': '19.0.00000', 'source_ids': ['compiler_fixture'], 'method': 'synthetic cl banner fixture'}} | compiler_fixture: synthetic compiler fixture |

Compiler/GPU queries are not compile, kernel, or PoC execution tests. Smoke: NOT_RUN.

## Selected target

Platform: wsl; backend: wsl
Content identity: sha256:ab244d1fa9da12a0b2eac13e13332bfbe6e7089c9c880e09eea03c0ccc05d8e5 (local integrity hash, not hardware attestation)

| Field | Status | Value (redacted) | Source / method |
|---|---|---|---|
| host_os | OBSERVED | Fixture Linux | os_release: read /etc/os-release PRETTY_NAME |
| kernel | OBSERVED | 6.6-microsoft-standard-WSL2 | python_stdlib: platform.version (Windows) / platform.release (Linux) |
| architecture | OBSERVED | x86_64 | python_stdlib: platform.machine |
| python_version | OBSERVED | 3.10.12 | python_stdlib: platform.python_version |
| gpu_devices | OBSERVED | [{'index': 0, 'name': 'Fixture GPU A', 'compute_capability': '7.5', 'sm_arch': 'sm_75'}, {'index': 1, 'name': 'Fixture GPU B', 'compute_capability': '8.6', 'sm_arch': 'sm_86'}] | gpu_query: nvidia-smi per-device CSV query |
| driver_release | OBSERVED | 555.42 | gpu_query: nvidia-smi driver_version |
| cuda_driver_api_version | NOT_CHECKED | unknown | : CUDA Driver API not loaded by read-only probe |
| driver_reported_cuda_version | OBSERVED | 12.4 | smi_banner: nvidia-smi banner CUDA compatibility, not Driver API or Toolkit |
| cuda_toolkit_version | OBSERVED | 12.8 | nvcc_version: nvcc --version release |
| nvcc_path | OBSERVED | [private directory]/nvcc | filesystem: existing nvcc executable discovery |
| nvcc_version | OBSERVED | 12.8.93 | nvcc_version: nvcc --version compiler build |
| supported_architectures | OBSERVED | ['compute_75', 'compute_86', 'sm_75', 'sm_86'] | nvcc_gpu_code, nvcc_gpu_arch: nvcc --list-gpu-code and --list-gpu-arch |
| compute_sanitizer_path | OBSERVED | [private directory]/compute-sanitizer | filesystem: existing Compute Sanitizer executable discovery |
| compute_sanitizer_version | OBSERVED | 2025.1.0.0 | sanitizer_version: compute-sanitizer --version |
| host_compiler | OBSERVED | {'msvc': {'status': 'OBSERVED', 'value': '19.29.30133', 'source_ids': ['msvc_version'], 'method': 'host compiler version query'}} | filesystem, msvc_version: per-compiler discovery and version queries |

Compiler/GPU queries are not compile, kernel, or PoC execution tests. Smoke: NOT_RUN.

## Transport and diagnostics

Launcher return code: 0
Worker reported exit code: 0
A killed WSL launcher does not prove remote process termination; the worker also has its own time bounds.


Original logs and argv are private in this directory; commands.json contains exact byte encodings and digests.
This summary is generated deterministically without an LLM.
