.PHONY: test lint check-file-length check

test: lint check-file-length
	cargo test --workspace

lint:
	cargo clippy --workspace --all-targets -- -D warnings

check-file-length:
	./scripts/check-file-length.sh

check: test
