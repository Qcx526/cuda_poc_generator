# Runtime image for the demo and for grading.
#
# Deliberately plain: the CUDA toolkit the CVE affects, plus what the generated
# scripts need to run and what the fault recorder needs to compile. Nothing else
# is installed, so a verdict cannot depend on a tool that only exists here.
#
#   docker build -t cpg/cuda112-py3:1.0 -f docker/Dockerfile .
FROM nvidia/cuda:11.2.2-devel-ubuntu20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 \
      gcc \
      libc6-dev \
      ca-certificates \
      coreutils \
      file \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work

# The toolchain this image exists for; failing here is better than discovering it
# at grading time.
RUN cuobjdump --version >/dev/null && nvdisasm --version >/dev/null
