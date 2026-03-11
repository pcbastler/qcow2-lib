.PHONY: test lint check-file-length check fuzz coverage

test: lint check-file-length
	cargo test --workspace

lint:
	cargo clippy --workspace --all-targets -- -D warnings

check-file-length:
	./scripts/check-file-length.sh

FUZZ_TIME ?= 30

fuzz:
	@for t in $$(cargo +nightly fuzz list | grep '^fuzz_'); do \
		echo "=== $$t ($(FUZZ_TIME)s) ==="; \
		cargo +nightly fuzz run "$$t" -- -max_total_time=$(FUZZ_TIME) -rss_limit_mb=6144 || exit 1; \
	done

coverage:
	cargo llvm-cov --workspace --html --open

check: test
