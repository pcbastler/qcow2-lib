#!/usr/bin/env bash
# Find unsafe code and related risky patterns in production code
# (excluding tests, examples, benches).
#
# Detected patterns:
#   unsafe             - unsafe blocks and functions
#   transmute          - std::mem::transmute (reinterpret cast)
#   as *const / as *mut - raw pointer casts
#   from_raw_parts     - constructing slices from raw pointers
#   forget(            - std::mem::forget (leak resources)
#   MaybeUninit        - uninitialized memory
#   union              - untagged unions
#
# Usage: ./scripts/find-production-unsafe.sh [crates/]

set -euo pipefail

root="${1:-crates}"

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

    /unsafe[[:space:]]*\{/      { tag="unsafe block";   match_found() }
    /unsafe[[:space:]]+fn/      { tag="unsafe fn";      match_found() }
    /unsafe[[:space:]]+impl/    { tag="unsafe impl";    match_found() }
    /unsafe[[:space:]]+trait/   { tag="unsafe trait";   match_found() }
    /transmute/                 { tag="transmute";      match_found() }
    /as \*const/                { tag="raw ptr cast";   match_found() }
    /as \*mut/                  { tag="raw ptr cast";   match_found() }
    /from_raw_parts/            { tag="from_raw_parts"; match_found() }
    /mem::forget\(/             { tag="mem::forget";    match_found() }
    /\.forget\(/                { tag="forget";         match_found() }
    /MaybeUninit/               { tag="MaybeUninit";    match_found() }
    /^[[:space:]]*union[[:space:]]/ { tag="union";      match_found() }

    function match_found() {
        printf "[%-14s] %s:%d: %s\n", tag, FILENAME, NR, $0
    }
    ' "$file"
done
