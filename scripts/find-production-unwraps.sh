#!/usr/bin/env bash
# Find .unwrap() calls in production code (excluding tests, examples, benches).
#
# Usage: ./scripts/find-production-unwraps.sh [crates/]

set -euo pipefail

root="${1:-crates}"

# Step 1: find all .rs source files under src/ dirs, excluding test/example/bench paths
find "$root" -path '*/src/*.rs' \
    -not -path '*/qcow2-rescue-e2e/*' \
    -not -path '*/tests/*' \
    -not -path '*/examples/*' \
    -not -path '*/benches/*' \
    -not -name 'test_*.rs' \
    -not -name '*_test.rs' \
    -not -name 'tests.rs' \
    -print0 |
sort -z |
while IFS= read -r -d '' file; do
    # Step 2: for each file, strip #[cfg(test)] blocks and #[test] functions,
    # then grep for .unwrap()
    awk '
    BEGIN { depth=0; skip=0; test_fn=0; test_depth=0 }

    # Track #[cfg(test)] module blocks
    /^[[:space:]]*#\[cfg\(test\)\]/ { skip=1; next }
    skip && /\{/ {
        if (depth == 0) { depth=1; next }
        depth++
        next
    }
    skip && /\}/ {
        depth--
        if (depth <= 0) { skip=0; depth=0 }
        next
    }
    skip { next }

    # Track #[test] function blocks
    /^[[:space:]]*#\[test\]/ { test_fn=1; next }
    test_fn && /\{/ {
        if (test_depth == 0) { test_depth=1; next }
        test_depth++
        next
    }
    test_fn && /\}/ {
        test_depth--
        if (test_depth <= 0) { test_fn=0; test_depth=0 }
        next
    }
    test_fn { next }

    # Print lines with .unwrap() that are not in comments or doc strings
    /\.unwrap\(\)/ && !/^[[:space:]]*\/\// { print FILENAME ":" NR ": " $0 }
    ' "$file"
done
