#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_FILE="${ROOT_DIR}/kernel/linux/bpf/corevanguard.bpf.c"
OUT_DIR="${ROOT_DIR}/kernel/linux/out"
OUT_FILE="${OUT_DIR}/corevanguard.bpf.o"

mkdir -p "${OUT_DIR}"

clang \
  -O2 \
  -g \
  -target bpf \
  -D__TARGET_ARCH_x86 \
  -I/usr/include \
  -I/usr/include/x86_64-linux-gnu \
  -c "${SRC_FILE}" \
  -o "${OUT_FILE}"

llvm-objdump -S "${OUT_FILE}" >/dev/null
echo "Built ${OUT_FILE}"

