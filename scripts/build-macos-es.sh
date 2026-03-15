#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_FILE="${ROOT_DIR}/kernel/macos/CoreVanguardES/main.mm"
OUT_DIR="${ROOT_DIR}/kernel/macos/out"
OUT_FILE="${OUT_DIR}/CoreVanguardES"

mkdir -p "${OUT_DIR}"

clang++ \
  -std=c++17 \
  -fobjc-arc \
  -framework Foundation \
  -framework EndpointSecurity \
  "${SRC_FILE}" \
  -o "${OUT_FILE}"

echo "Built ${OUT_FILE}"
