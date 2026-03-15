#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_FILE="${ROOT_DIR}/kernel/linux/bpf/corevanguard.bpf.c"
USER_SRC="${ROOT_DIR}/kernel/linux/user/corevanguard_ebpf_loader.c"
OUT_DIR="${ROOT_DIR}/kernel/linux/out"
OUT_FILE="${OUT_DIR}/corevanguard.bpf.o"
USER_OUT="${OUT_DIR}/corevanguard-ebpf-loader"

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
cc \
  -O2 \
  -g \
  "${USER_SRC}" \
  -o "${USER_OUT}" \
  $(pkg-config --cflags --libs libbpf)

echo "Built ${OUT_FILE}"
echo "Built ${USER_OUT}"
