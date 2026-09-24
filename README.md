# ACNS FL Crypto Benchmark

Reproducible research prototype for the protocol described in the paper:

**Privacy-Preserving Federated Learning with RLWE Secure Aggregation, Verifiable Inclusion and Fairness Auditing**

The repository deliberately separates the ML/HE implementation from the zero-knowledge layer:

```text
C++ / LibTorch
    │
    ├── MLP/CNN local training
    ├── tensor flattening
    └── fixed-point encoding
    │
    ▼
Microsoft SEAL (BGV/RLWE)
    │
    ├── batching / NTT-backed polynomial arithmetic
    ├── encryption
    ├── ciphertext aggregation
    └── decryption
    │
    ▼
C ABI
    │
    ▼
Rust
    ├── Pedersen commitments
    ├── Bulletproof R1CS
    ├── PoI consistency checks
    └── fairness statistics
```

## Important cryptographic scope

Microsoft SEAL is used here for the RLWE-based homomorphic encryption backend. SEAL internally uses NTT/RNS arithmetic, but its public BFV/BGV API does **not** expose a raw arbitrary RLWE ciphertext in NTT representation. The benchmark therefore measures SEAL's supported BGV ciphertext operations rather than claiming that the application directly manipulates SEAL's internal NTT arrays.

The zero-knowledge layer uses the Rust `bulletproofs` 4.0.0 R1CS API with the experimental `yoloproofs` feature. The 4.0.0 source exposes the R1CS module only when this feature is enabled. The linear/matrix-style benchmark intentionally uses public scalar coefficients as linear-combination coefficients and therefore has only one fixed multiplication gate; the vector-style benchmark uses one multiplication gate per element. This isolates the R1CS representation effect without misrepresenting public scalar multiplication as a multiplication gate.

This is a research prototype, not a production-secure parameter set. The paper must report the exact SEAL version, parameter set, Bulletproofs version, hardware, compiler versions, and threat-model assumptions used for the final experiments.

## Dependencies

- C++17 compiler
- CMake >= 3.22
- Rust stable toolchain with Cargo
- LibTorch C++ distribution
- Microsoft SEAL >= 4.4
- Bulletproofs 4.0.0, `yoloproofs`

PyTorch's C++ frontend is a C++17 API containing tensors, `torch::nn`, optimizers, datasets, and related training functionality. The supported CMake integration uses `find_package(Torch REQUIRED)` and links `${TORCH_LIBRARIES}`. See the official LibTorch documentation.

Microsoft SEAL is built with CMake and can be installed locally or through vcpkg/Homebrew. The repository uses `find_package(SEAL 4 REQUIRED)` and links `SEAL::seal`.

## Building

### 1. Install LibTorch

Download a CPU or CUDA LibTorch distribution compatible with your compiler from PyTorch. Suppose it is installed at:

```bash
$HOME/libtorch
```

### 2. Install Microsoft SEAL

For example, build and install SEAL locally:

```bash
git clone --branch v4.4.5 --depth 1 https://github.com/microsoft/SEAL.git
cmake -S SEAL -B SEAL/build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=$HOME/seal
cmake --build SEAL/build -j
cmake --install SEAL/build
```

### 3. Build

```bash
export LIBTORCH_DIR=$HOME/libtorch
export SEAL_DIR=$HOME/seal

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$LIBTORCH_DIR;$SEAL_DIR"
cmake --build build -j
```

On Unix shells where CMake path-list separators are not accepted as expected, provide both prefixes with `-DTorch_DIR` and `-DSEAL_DIR`/`CMAKE_PREFIX_PATH` as appropriate for the local installation.

## Running

Default benchmark:

```bash
./build/fl_bench 256,512,1024,2048,4096,8192 4 2 mlp
```

Arguments:

```text
1. comma-separated update sizes
2. number of clients
3. local training epochs
4. model: mlp or cnn
```

Example CNN experiment:

```bash
./build/fl_bench 256,512,1024,2048 8 3 cnn
```

Output is CSV-like terminal data. The first line documents the columns.

## Measurements

For each update length N the benchmark records:

### Local ML

- LibTorch training time
- final synthetic training loss
- flattened model update length

### RLWE/SEAL

- key-generation time
- batching/encoding time
- encryption time
- ciphertext aggregation time
- decryption time
- serialized ciphertext bytes per client
- plaintext serialization size
- aggregate ciphertext size
- number of BGV batching chunks

### Zero knowledge

- Pedersen commitment time
- Bulletproof R1CS proving time
- Bulletproof R1CS verification time
- serialized proof size
- commitment bytes
- R1CS checks passed/failed

### PoI

The benchmark checks

```text
excluded + own == aggregate
```

and reports the check time and the serialized representation size used by this prototype.

### Fairness

The benchmark computes:

\[
CR_g=I_g/E_g,
\]

\[
\Delta_{incl}=\max_g CR_g-\min_g CR_g,
\]

and Jain's index

\[
J_{incl}=\frac{(\sum_g CR_g)^2}{|G|\sum_g CR_g^2}.
\]

The benchmark measures the local computation time and the explicit statistic representation size.

## Reproducibility

For paper-quality experiments, run multiple repetitions and report median and standard deviation. Pin:

- CPU model and core count
- RAM
- compiler versions
- LibTorch version
- Microsoft SEAL version
- Rust version
- Bulletproofs version
- CMake version
- OS/kernel
- SEAL scheme and parameters
- number of clients
- local epochs
- fixed-point scale

The provided benchmark intentionally uses synthetic datasets so that the cryptographic overhead can be isolated. For the final paper, replace the synthetic tensors with the chosen FL dataset and document the partitioning strategy.

## Relationship to the paper

The implementation maps to the paper as follows:

| Paper component | Repository implementation |
|---|---|
| Local FL training | `cpp/src/ml_models.cpp` |
| MLP | `MLPImpl` |
| CNN | `CNNImpl` |
| Tensor flattening | `flatten_parameters` |
| Fixed-point encoding | `main.cpp` |
| RLWE secure aggregation | `cpp/src/seal_rlwe.cpp` |
| Pedersen commitments | `rust/src/lib.rs` |
| Bulletproof R1CS | `rust/src/lib.rs` |
| PoI | `flzk_check_poi` |
| Inclusion fairness | fairness block in `main.cpp` / Rust benchmark |
| C++/Rust integration | `cpp/include/crypto_ffi.h` |
| Build | `CMakeLists.txt` + `rust/Cargo.toml` |

## Security disclaimer

The code is intended to support reproducible experiments and implementation discussion. It should not be interpreted as a complete deployment-ready secure-aggregation protocol. In particular, production deployment requires a formally specified key-management protocol, authenticated client enrollment, dropout handling, malicious-server defenses, parameter selection at a stated security level, rigorous fixed-point/range constraints, and a complete proof of the fairness-statistic binding relation.

## References

- Microsoft SEAL: https://github.com/microsoft/SEAL
- PyTorch C++ frontend / LibTorch: https://docs.pytorch.org/cppdocs/frontend
- Bulletproofs: https://github.com/dalek-cryptography/bulletproofs
