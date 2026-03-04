#!/usr/bin/env bash
# Test: Raw file -> QCOW2 -> multiple snapshots -> rollback -> verify
#
# Simulates the use case: "I have a raw file and want to periodically
# snapshot its state, then roll back to any previous version."

set -uo pipefail

if [ -n "${QCOW2_TOOL:-}" ]; then
    TOOL="$QCOW2_TOOL"
elif [ -x ./target/release/qcow2-tool ]; then
    TOOL=./target/release/qcow2-tool
elif [ -x ./target/debug/qcow2-tool ]; then
    TOOL=./target/debug/qcow2-tool
else
    echo "ERROR: qcow2-tool not found. Run 'cargo build' first."
    exit 1
fi
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

RAW="$WORKDIR/disk.raw"
QCOW2="$WORKDIR/disk.qcow2"

pass=0
fail=0

check() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "  PASS: $desc"
        pass=$((pass + 1))
    else
        echo "  FAIL: $desc"
        fail=$((fail + 1))
    fi
}

echo "=== QCOW2 Snapshot Workflow Test ==="
echo ""

# --- Step 1: Create a raw disk image with initial data ---
echo "[1] Creating 1 MiB raw disk with initial data (0xAA at offset 0)..."
dd if=/dev/zero of="$RAW" bs=1M count=1 status=none
python3 -c "import sys; sys.stdout.buffer.write(b'\xAA'*512)" | \
    dd of="$RAW" bs=1 count=512 conv=notrunc status=none

check "raw file exists" test -f "$RAW"
check "raw file is 1 MiB" test "$(stat -c%s "$RAW")" -eq 1048576
check "raw starts with 0xAA" test "$(xxd -l1 -p "$RAW")" = "aa"

# --- Step 2: Convert raw -> QCOW2 ---
echo ""
echo "[2] Converting raw -> QCOW2..."
$TOOL convert "$RAW" "$QCOW2" --format qcow2

check "qcow2 file exists" test -f "$QCOW2"

echo ""
echo "[2b] Image info:"
$TOOL info "$QCOW2"

# --- Step 3: Create snapshot "v1" (initial state: 0xAA) ---
echo ""
echo "[3] Creating snapshot 'v1' (state: 0xAA at offset 0)..."
$TOOL snapshot create "$QCOW2" v1

echo "  Snapshots:"
$TOOL snapshot list "$QCOW2"
check "snapshot v1 exists" bash -c "$TOOL snapshot list '$QCOW2' 2>&1 | grep -q v1"

# --- Step 4: Modify data — write 0xBB at offset 0 ---
echo ""
echo "[4] Writing 0xBB at offset 0 (overwriting 0xAA)..."

if ! command -v qemu-io &>/dev/null; then
    echo "  SKIP: qemu-io not available (install qemu-utils for full test)"
    echo ""
    echo "=== Results: $pass passed, $fail failed, rest skipped ==="
    exit "$fail"
fi

qemu-io -f qcow2 -c "write -P 0xBB 0 512" "$QCOW2" >/dev/null
check "wrote 0xBB via qemu-io" qemu-io -f qcow2 -c "read -P 0xBB 0 512" "$QCOW2"

# --- Step 5: Create snapshot "v2" (state: 0xBB) ---
echo ""
echo "[5] Creating snapshot 'v2' (state: 0xBB at offset 0)..."
$TOOL snapshot create "$QCOW2" v2

check "snapshot v2 exists" bash -c "$TOOL snapshot list '$QCOW2' 2>&1 | grep -q v2"

# --- Step 6: Modify again — write 0xCC at offset 0 ---
echo ""
echo "[6] Writing 0xCC at offset 0..."
qemu-io -f qcow2 -c "write -P 0xCC 0 512" "$QCOW2" >/dev/null

check "current state is 0xCC" qemu-io -f qcow2 -c "read -P 0xCC 0 512" "$QCOW2"

# --- Step 7: List all snapshots ---
echo ""
echo "[7] Listing snapshots..."
$TOOL snapshot list "$QCOW2"

# --- Step 8: Roll back to v1 (should restore 0xAA) ---
echo ""
echo "[8] Rolling back to snapshot 'v1' (expect 0xAA)..."
$TOOL snapshot apply "$QCOW2" v1

check "v1 rollback restored 0xAA" qemu-io -f qcow2 -c "read -P 0xAA 0 512" "$QCOW2"

# --- Step 9: Roll forward to v2 (should restore 0xBB) ---
echo ""
echo "[9] Rolling back to snapshot 'v2' (expect 0xBB)..."
$TOOL snapshot apply "$QCOW2" v2

check "v2 rollback restored 0xBB" qemu-io -f qcow2 -c "read -P 0xBB 0 512" "$QCOW2"

# --- Step 10: Consistency check ---
echo ""
echo "[10] Running our consistency check..."
$TOOL check "$QCOW2"
check "our check passes" $TOOL check "$QCOW2"

# --- Step 11: QEMU also thinks it's clean ---
echo ""
echo "[11] QEMU consistency check..."
if command -v qemu-img &>/dev/null; then
    qemu-img check "$QCOW2"
    check "qemu-img check passes" qemu-img check "$QCOW2"
else
    echo "  SKIP: qemu-img not available"
fi

# --- Step 12: Export back to raw ---
echo ""
echo "[12] Exporting current state (v2=0xBB) back to raw..."
RESTORED="$WORKDIR/restored.raw"
$TOOL convert "$QCOW2" "$RESTORED" --format raw

check "exported raw exists" test -f "$RESTORED"
check "exported raw starts with 0xBB" test "$(xxd -l1 -p "$RESTORED")" = "bb"

# --- Summary ---
echo ""
echo "==========================================="
echo "  Results: $pass passed, $fail failed"
echo "==========================================="

exit "$fail"
