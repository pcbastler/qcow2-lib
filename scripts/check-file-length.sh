#!/bin/bash
# Check that no .rs source file exceeds the maximum line count.
# Usage: ./scripts/check-file-length.sh [max_lines]
# Default: 600 lines

MAX_LINES="${1:-600}"
FAILED=0

while IFS= read -r file; do
    lines=$(wc -l < "$file")
    if [ "$lines" -gt "$MAX_LINES" ]; then
        echo "FAIL: $file ($lines lines, max $MAX_LINES)"
        FAILED=1
    fi
done < <(find crates -name '*.rs' -not -path '*/tests/*' -not -path '*/tests.rs' -not -name '*test_*.rs' | sort)

if [ "$FAILED" -eq 0 ]; then
    echo "OK: All source files are within $MAX_LINES lines."
fi

exit $FAILED
