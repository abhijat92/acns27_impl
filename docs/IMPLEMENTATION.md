# Implementation and Paper Mapping

## 1. Software architecture

The implementation has two language layers. C++ owns the federated-learning and homomorphic-encryption workflow because both LibTorch and Microsoft SEAL expose mature C++ APIs. Rust owns the zero-knowledge layer because the selected Bulletproofs implementation is Rust-native.

The boundary is a small C ABI. The benchmark therefore avoids exposing C++ objects or Rust ownership semantics across the language boundary.

## 2. LibTorch

`ml_models.cpp` defines an MLP and a small CNN using `torch::nn` modules. Synthetic local data are generated in C++ and optimized with `torch::optim::SGD`. Model parameters are detached, moved to CPU, flattened, concatenated, and resized to the requested cryptographic update length.

The resize operation is a benchmark adapter: it makes it possible to study cryptographic cost as a function of update length while retaining a real LibTorch training path. A paper experiment using a real model should instead encrypt the exact model delta without repetition/padding.

## 3. Fixed-point encoding

The benchmark maps floating-point parameters to signed integers using

\[
\tilde m_j=\operatorname{round}(\Delta m_j).
\]

The current code uses `Delta = 1000`. The encoded integer is then represented modulo the BGV plaintext modulus. A final paper implementation should specify the clipping/range policy and prove the corresponding range constraint in the ZK circuit.

## 4. Microsoft SEAL

`seal_rlwe.cpp` uses BGV with batching. A polynomial modulus degree of 8192 provides a fixed number of batching slots; vectors larger than the available slot count are split across multiple ciphertexts. Client ciphertexts are aggregated with `Evaluator::add_inplace`.

SEAL performs its own optimized RNS/NTT arithmetic internally. The code deliberately does not reach into SEAL private implementation headers. This is preferable for reproducibility and API stability.

## 5. R1CS representation comparison

The Rust benchmark provides two circuit constructions.

### Matrix/linear representation

Public coefficients are inserted directly into linear combinations:

\[
\sum_j a_j s_j = b.
\]

This does not require a multiplication gate for each public coefficient. The prototype contains one fixed multiplication gate solely because the selected Bulletproofs R1CS backend is generator/circuit oriented; the N-dependent relation itself is linear.

### Vector representation

The vector benchmark intentionally uses

\[
s_j a_j = o_j
\]

through an R1CS multiplication gate for every element. Consequently the number of multiplication gates grows as

\[
m_{vec}=N.
\]

This is the representation-level comparison used in the paper's implementation discussion.

## 6. Communication accounting

Proof and ciphertext sizes are measured from actual serialized objects. No theoretical size formula is substituted for an observed serialized size.

The principal client-to-server accounting is

\[
B_{C\rightarrow S}
=B_{ct}+B_{com}+B_{zk}+B_{stats}+B_{aux}.
\]

For multiple clients,

\[
B_{total}=\sum_i B_i.
\]

PoI and fairness statistics are separately reported so that their incremental overhead can be isolated.
