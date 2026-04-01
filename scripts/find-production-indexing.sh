#!/usr/bin/env bash
# Find potentially panicking array/slice index accesses in production code.
#
# Detected patterns:
#   arr[variable]          - direct index with variable (not constant like [0], [1])
#   arr[expr + expr]       - computed index
#   arr[start..end]        - slice range with variables
#   arr[start..]           - open-ended slice with variable start
#   arr[..end]             - open-ended slice with variable end
#
# Excluded (false positives):
#   - Type annotations:  [u8; 32], [u8], &[T]
#   - Array literals:    [0u8; 512], [0; N]
#   - Attributes:        #[derive(...)], #[cfg(...)]
#   - Constants-only:    [0], [1], [2] etc.
#   - Comments
#   - Test code, examples, benches
#
# Usage: ./scripts/find-production-indexing.sh [crates/]

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

    # Skip attribute lines (#[...])
    /^[[:space:]]*#\[/ { next }

    # Skip type annotations and array literals
    # e.g. [u8; 32], [0u8; 512], &[u8], Vec<[u8; 16]>
    /\[[[:space:]]*[uif](8|16|32|64|128|size)[[:space:]]*[;\]]/ { next }
    /\[[[:space:]]*0[[:space:]]*;/ { next }
    /\[[[:space:]]*0x0[[:space:]]*;/ { next }
    /\[[[:space:]]*0u8[[:space:]]*;/ { next }
    /\[[[:space:]]*b'"'"'/ { next }

    {
        line = $0

        # Variable index: something[variable] where variable is not a pure number
        # Match: word[identifier] or word[identifier +/- expression]
        # We look for [ followed by a letter (variable name start), not a number
        if (match(line, /\[[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\]/) ||
            match(line, /\[[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*[+\-\*\/]/) ||
            match(line, /\[[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\.\./)) {

            # Extract the bracket content for classification
            s = substr(line, RSTART+1, RLENGTH-2)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)

            # Skip if it looks like a type (starts with uppercase and contains no operators)
            if (s ~ /^[A-Z]/ && s !~ /[+\-\*\/]/) next

            # Skip known type patterns
            if (s ~ /^(u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize|bool|f32|f64)/) next

            # Classify
            if (s ~ /\.\./) {
                tag = "range"
            } else if (s ~ /[+\-\*\/]/) {
                tag = "computed"
            } else {
                tag = "variable"
            }

            printf "[%-10s] %s:%d: %s\n", tag, FILENAME, NR, line
        }
        # Also catch ranges starting with numbers: [0..len], [1..end]
        else if (match(line, /\[[[:space:]]*[0-9]+[[:space:]]*\.\.[[:space:]]*[a-zA-Z_]/)) {
            printf "[%-10s] %s:%d: %s\n", "range", FILENAME, NR, line
        }
        # Catch open-ended slices: [..variable]
        else if (match(line, /\[[[:space:]]*\.\.[[:space:]]*[a-zA-Z_][a-zA-Z0-9_]*/)) {
            printf "[%-10s] %s:%d: %s\n", "range", FILENAME, NR, line
        }
    }
    ' "$file"
done
