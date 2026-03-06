#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE_NAME="qcow2-rescue-e2e"
OUTPUT_DIR="${1:-$SCRIPT_DIR/test-images}"

echo "=== Phase 0: Building binaries (release) ==="
cd "$PROJECT_ROOT"
cargo build --release -p qcow2-rescue -p qcow2-rescue-e2e

# Phase 1+2: Only generate if manifest doesn't exist yet
if [ -f "$OUTPUT_DIR/manifest.json" ]; then
    echo ""
    echo "=== Skipping generation: $OUTPUT_DIR/manifest.json exists ==="
    echo "    (delete $OUTPUT_DIR to regenerate)"
else
    echo ""
    echo "=== Phase 1: Preparing Docker image ==="
    BUILD_DIR="$SCRIPT_DIR/build"
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR/bin"
    cp "$PROJECT_ROOT/target/release/qcow2-rescue-e2e" "$BUILD_DIR/bin/"
    cp "$SCRIPT_DIR/Dockerfile" "$BUILD_DIR/"
    docker build -t "$IMAGE_NAME" "$BUILD_DIR"
    rm -rf "$BUILD_DIR"

    echo ""
    echo "=== Phase 2: Generating test images in Docker (as root) ==="
    mkdir -p "$OUTPUT_DIR"
    HOST_UID="$(id -u)"
    HOST_GID="$(id -g)"
    docker run --rm --privileged \
        -v "$OUTPUT_DIR:/work/output" \
        -e HOST_UID="$HOST_UID" \
        -e HOST_GID="$HOST_GID" \
        --entrypoint /bin/bash \
        "$IMAGE_NAME" \
        -c "qcow2-rescue-e2e generate /work/output && chown -R \$HOST_UID:\$HOST_GID /work/output"
fi

echo ""
echo "=== Phase 3: Running corruption + recovery tests on host ==="
export QCOW2_RESCUE_BIN="$PROJECT_ROOT/target/release/qcow2-rescue"
"$PROJECT_ROOT/target/release/qcow2-rescue-e2e" test "$OUTPUT_DIR"
