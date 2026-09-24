#!/usr/bin/env bash
set -euo pipefail

SIZES="${1:-256,512,1024,2048,4096,8192}"
CLIENTS="${2:-4}"
EPOCHS="${3:-2}"
MODEL="${4:-mlp}"

if [[ -z "${LIBTORCH_DIR:-}" ]]; then
  echo "ERROR: set LIBTORCH_DIR to your LibTorch installation" >&2
  exit 1
fi
if [[ -z "${SEAL_DIR:-}" ]]; then
  echo "ERROR: set SEAL_DIR to your Microsoft SEAL installation" >&2
  exit 1
fi

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="${LIBTORCH_DIR};${SEAL_DIR}"
cmake --build build -j
./build/fl_bench "$SIZES" "$CLIENTS" "$EPOCHS" "$MODEL"
