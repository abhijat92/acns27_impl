FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential cmake ninja-build git curl ca-certificates pkg-config \
    libssl-dev unzip python3 python3-pip && rm -rf /var/lib/apt/lists/*

# Rust toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Build and install Microsoft SEAL. Pin the version used by the repository.
ARG SEAL_VERSION=v4.4.5
RUN git clone --branch ${SEAL_VERSION} --depth 1 https://github.com/microsoft/SEAL.git /opt/SEAL \
    && cmake -S /opt/SEAL -B /opt/SEAL/build -GNinja \
       -DCMAKE_BUILD_TYPE=Release \
       -DCMAKE_INSTALL_PREFIX=/opt/seal \
    && cmake --build /opt/SEAL/build \
    && cmake --install /opt/SEAL/build

# LibTorch is intentionally not downloaded here because the desired CPU/CUDA
# distribution depends on the host. Mount or copy a matching LibTorch tree to
# /opt/libtorch when building the container.
ENV LIBTORCH_DIR=/opt/libtorch
ENV SEAL_DIR=/opt/seal
WORKDIR /workspace
COPY . /workspace

CMD ["bash", "-lc", "./scripts/run_bench.sh"]
