#!/usr/bin/env bash
# Find potential panic sources in production code (excluding tests, examples, benches).
#
# Detected patterns:
#   .unwrap()          - panics on Err/None
#   .expect(           - panics on Err/None with message
#   panic!(            - explicit panic
#   unreachable!(      - panics if reached
#   todo!(             - panics (placeholder)
#   unimplemented!(    - panics (placeholder)
#
# Note: array/slice indexing (buf[i]) can also panic on out-of-bounds,
# but is not reliably detectable via text search.
#
# Usage: ./scripts/find-production-panics.sh [crates/]

set -euo pipefail

root="${1:-crates}"
found=0

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

    # Skip comment lines
    /^[[:space:]]*\/\// { next }

    /\.unwrap\(\)/      { tag="unwrap";        match_found() }
    /\.expect\(/        { tag="expect";        match_found() }
    /panic!\(/          { tag="panic!";        match_found() }
    /unreachable!\(/    { tag="unreachable!";  match_found() }
    /todo!\(/           { tag="todo!";         match_found() }
    /unimplemented!\(/  { tag="unimplemented!"; match_found() }

    function match_found() {
        printf "[%-14s] %s:%d: %s\n", tag, FILENAME, NR, $0
    }
    ' "$file"
done
