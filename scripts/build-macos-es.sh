#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_FILE="${ROOT_DIR}/kernel/macos/CoreVanguardES/main.mm"
XCODEPROJ="${ROOT_DIR}/kernel/macos/CoreVanguardES.xcodeproj"
OUT_DIR="${ROOT_DIR}/kernel/macos/out"
OUT_FILE="${OUT_DIR}/CoreVanguardES"

mkdir -p "${OUT_DIR}"

if [[ -d "${XCODEPROJ}" ]]; then
  xcodebuild \
    -project "${XCODEPROJ}" \
    -scheme CoreVanguardES \
    -configuration Release \
    CONFIGURATION_BUILD_DIR="${OUT_DIR}" \
    build
else
  clang++ \
    -std=c++17 \
    -fobjc-arc \
    -framework Foundation \
    -framework EndpointSecurity \
    "${SRC_FILE}" \
    -o "${OUT_FILE}"
fi

echo "Built ${OUT_FILE}"
