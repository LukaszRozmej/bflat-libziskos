#!/bin/bash
# Differential test of the patched zisklib secp256k1 recovery on the host.
# Usage: ZISK_REF=v1.3.2-alpha tests/secp256k1/run.sh [test_ecrecover.py args...]
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD="$(cd "${HERE}/../../build" && pwd)"
ZISK_DIR="${HERE}/target/zisk"
SECP="ziskos/entrypoint/src/zisklib/lib/secp256k1"

rm -rf "${ZISK_DIR}"
git init -q "${ZISK_DIR}"
git -C "${ZISK_DIR}" fetch -q --depth=1 https://github.com/0xPolygonHermez/zisk.git "${ZISK_REF:?ZISK_REF is not set}"
git -C "${ZISK_DIR}" checkout -q --detach FETCH_HEAD
git -C "${ZISK_DIR}" apply "${BUILD}/secp256k1/secp256k1.patch"

rm -rf "${HERE}/src/secp"
mkdir -p "${HERE}/src/secp"
for f in constants curve ecdsa field glv scalar; do
    cp "${ZISK_DIR}/${SECP}/${f}.rs" "${HERE}/src/secp/"
done
cp "${BUILD}/secp256k1/straus.rs" "${BUILD}/secp256k1/g_tables.rs" "${HERE}/src/secp/"

cargo test --release --quiet --manifest-path "${HERE}/Cargo.toml"
cargo build --release --quiet --manifest-path "${HERE}/Cargo.toml"
EXE="${HERE}/target/release/harness"
[ -f "${EXE}.exe" ] && EXE="${EXE}.exe"
python3 "${HERE}/test_ecrecover.py" "${EXE}" "$@"
