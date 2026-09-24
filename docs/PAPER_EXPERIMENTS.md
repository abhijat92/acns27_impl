# Recommended ACNS experiments

## E1: MLP scaling

```bash
./scripts/run_bench.sh 256,512,1024,2048,4096,8192 4 2 mlp | tee mlp.log
python3 scripts/collect_results.py mlp.log results_mlp.csv
```

## E2: CNN scaling

```bash
./scripts/run_bench.sh 256,512,1024,2048,4096,8192 4 2 cnn | tee cnn.log
python3 scripts/collect_results.py cnn.log results_cnn.csv
```

## E3: client scaling

Keep `N=2048` and vary clients:

```bash
./scripts/run_bench.sh 2048 2 2 mlp
./scripts/run_bench.sh 2048 4 2 mlp
./scripts/run_bench.sh 2048 8 2 mlp
./scripts/run_bench.sh 2048 16 2 mlp
```

## E4: R1CS representation

The executable currently benchmarks the linear/matrix-style circuit. To compare the vector-style circuit, call the Rust ABI from a small harness or extend `main.cpp` to call `flzk_benchmark_r1cs(N, 1, ...)` in parallel with mode 0. Report proof size, proving time, verification time, commitment size, and number of multiplication gates.

The vector-style circuit has `N` multiplication gates; the linear-style circuit has one fixed gate plus N-dependent linear-combination synthesis. This should be reported explicitly rather than calling both circuits equivalent.

## E5: communication decomposition

Report at least:

- SEAL ciphertext bytes/client
- Bulletproof bytes/client
- Pedersen commitment bytes/client
- fairness-statistics bytes/client
- PoI bytes/client
- total client-to-server bytes
- server-to-client PoI response bytes

The final paper should distinguish serialized cryptographic objects from protocol metadata.
