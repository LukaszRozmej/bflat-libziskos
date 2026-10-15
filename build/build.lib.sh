function cleanup() {
    # Clean up previous builds
    echo "Cleaning up previous builds..."
    rm -rf "${TMP_DIR}" "${OUTPUT_DIR}"
    mkdir -p "${TMP_DIR}" "${OUTPUT_DIR}"
}

function prepare_repo() {
    # Clone the repository
    echo "Cloning zisk repository (ref: ${ZISK_REF})..."
    ZISK_DIR="${TMP_DIR}/zisk"

    git init "${ZISK_DIR}"
    pushd "${ZISK_DIR}" > /dev/null
    git remote add origin "${ZISK_REPO}"
    git fetch --depth=1 origin "${ZISK_REF}"
    git checkout --detach FETCH_HEAD

    ZISK_COMMIT=$(git rev-parse HEAD)
    echo "Zisk commit: ${ZISK_COMMIT}"

    # Copy custom target spec
    echo "Copying custom target specification..."
    cp "${SCRIPT_DIR}/riscv64ima-zisk-zkvm-elf.json" . || fail "Failed to copy custom target specification"

    # Copy patch file
    echo "Copying entrypoint patch..."
    cp "${SCRIPT_DIR}/entrypoint.patch" . || fail "Failed to copy patch file"

    # Copy the windowed secp256k1 double-scalar multiplication
    echo "Copying secp256k1 sources and patch..."
    SECP_DIR="ziskos/entrypoint/src/zisklib/lib/secp256k1"
    cp "${SCRIPT_DIR}/secp256k1/straus.rs" "${SCRIPT_DIR}/secp256k1/g_tables.rs" "${SECP_DIR}/" || fail "Failed to copy secp256k1 sources"
    cp "${SCRIPT_DIR}/secp256k1/secp256k1.patch" . || fail "Failed to copy secp256k1 patch"

    popd > /dev/null
}

function build_docker_image() {
    # Build Docker image
    echo "Building Docker image..."
    docker build -t ziskos-builder "${SCRIPT_DIR}" || fail "Failed to build Docker image"
}

function build_in_docker() {
    # Build in Docker
    pushd "${ZISK_DIR}"
        echo "Building with Docker..."
        docker run --rm \
        -v "$(pwd):/workspace" \
        -w /workspace \
        ziskos-builder \
        bash -c "
            set -e
            echo 'Patching lib-c/build.rs for zkvm target...'
            sed -i '3a\\use std::env;' lib-c/build.rs
            sed -i '9a\\    if env::var(\"CARGO_CFG_TARGET_OS\").unwrap_or_default() == \"zkvm\" {\\n        println!(\"cargo:rustc-cfg=feature=\\\\\"no_lib_link\\\\\"\");\\n        return;\\n    }' lib-c/build.rs

            echo 'Building ziskos entrypoint for riscv64ima-zisk-zkvm-elf...'

            # zisk v1.0.0-alpha ships a rust-toolchain.toml pinning the 'stable'
            # channel, but build-std requires nightly + rust-src. Drop the override
            # so the build uses the image's default nightly toolchain, which already
            # has rust-src installed (the plain 'nightly' channel does not).
            rm -f rust-toolchain.toml rust-toolchain

            echo 'Applying patches for no_entrypoint feature...'
            # Apply patch to wrap _start, _zisk_main, memcpy, memmove and replace sys_alloc_aligned
            patch -p1 -l < /workspace/entrypoint.patch || exit 1
            patch -p1 < /workspace/secp256k1.patch || exit 1

            # Rename DMA mem* symbols to __wrap_* (done with sed rather than the
            # patch so upstream changes to the instruction bodies do not break it)
            sed -i -E 's/\\b(memcmp|memcpy|memmove|memset)\\b/__wrap_\\1/g' ziskos/entrypoint/src/dma/mem{cmp,cpy,move,set}.s

            cd ziskos/entrypoint

            # Ensure staticlib output (dropped from crate-type in zisk v0.18.0)
            sed -i 's/^crate-type = \[\"rlib\"\]$/crate-type = [\"rlib\", \"staticlib\"]/' Cargo.toml

            # Add no_entrypoint to existing [features] section
            sed -i '/^\[features\]/a no_entrypoint = []' Cargo.toml

            # Provide a panic_handler stub (crate became no_std for zkvm in v0.18.0,
            # and a staticlib in no_std requires #[panic_handler]; bflat handles
            # actual panic delivery via sys_panic).
            printf '\n#[cfg(all(target_os = \"zkvm\", target_vendor = \"zisk\"))]\n#[panic_handler]\nfn _bflat_panic_handler(_info: &core::panic::PanicInfo) -> ! { loop {} }\n' >> src/lib.rs

            cargo build --release --target /workspace/riscv64ima-zisk-zkvm-elf.json -Z build-std=std,panic_abort -Z json-target-spec --features no_entrypoint

            echo 'Build completed!'
        " || fail "Failed to build ziskos entrypoint"

        # Copy the built library
        echo "Copying built library..."
        BUILT_LIB="target/riscv64ima-zisk-zkvm-elf/release/libziskos.a"
        if [ -f "${BUILT_LIB}" ]; then
            cp "${BUILT_LIB}" "${OUTPUT_DIR}/libziskos.a" || fail "Failed to copy built library"
            echo "Library copied to ${OUTPUT_DIR}/libziskos.a"
        else
            echo "Error: Built library not found at ${BUILT_LIB}"
            echo "Searching for available libraries..."
            find target -name "*.a" -type f
            exit 1
        fi
    popd
}

function build_syscalls() {
    # Build zisk_syscalls.S and add to lib.a
    if [ -f "${ROOT_DIR}/src/zisk_syscalls/zisk_syscalls.S" ]; then
        echo "Building zisk_syscalls.S..."
        docker run --rm \
        -v "${ROOT_DIR}/src/zisk_syscalls:/syscalls" \
        -v "${OUTPUT_DIR}:/output" \
        -w /syscalls \
        ziskos-builder \
        bash -c "
            set -e
            echo 'Assembling zisk_syscalls.S...'
            riscv64-linux-gnu-as --march=rv64ima --mabi=lp64 zisk_syscalls.S -o zisk_syscalls.o || exit 1

            echo 'Adding zisk_syscalls.o to lib.a...'
            cd /output
            riscv64-linux-gnu-ar r libziskos.a /syscalls/zisk_syscalls.o || exit 1
            riscv64-linux-gnu-ranlib libziskos.a || exit 1

            echo 'zisk_syscalls added to lib.a'
        " || fail "Failed to build and add zisk_syscalls"
    else
        echo "Skipping zisk_syscalls - zisk_syscalls.S not found"
    fi
}

function copy_manifest() {
    # Copy manifest
    echo "Copying bflat-manifest.json..."
    if [ -f "${ROOT_DIR}/bflat-manifest.json" ]; then
        cp "${ROOT_DIR}/bflat-manifest.json" "${OUTPUT_DIR}/libziskos.bflat.manifest" || fail "Failed to copy bflat-manifest.json"

        if [ -n "${ZISK_COMMIT}" ] && command -v jq &>/dev/null; then
            jq --arg hash "${ZISK_COMMIT}" '. + {zisk_ref_hash: $hash}' \
                "${OUTPUT_DIR}/libziskos.bflat.manifest" > "${OUTPUT_DIR}/libziskos.bflat.manifest.tmp" \
                && mv "${OUTPUT_DIR}/libziskos.bflat.manifest.tmp" "${OUTPUT_DIR}/libziskos.bflat.manifest"
            echo "Injected zisk_ref_hash: ${ZISK_COMMIT}"
        fi

        echo "Manifest at ${OUTPUT_DIR}/libziskos.bflat.manifest"
    fi
}
