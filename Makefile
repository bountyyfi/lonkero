# Convenience targets for the OrcaRouter provider tests. CI runs the same cargo
# commands directly; these wrappers only save typing. Set CARGO to run them with
# a specific cargo binary.

CARGO ?= cargo

.PHONY: test-orcarouter check-orcarouter live-orcarouter

test-orcarouter:
	$(CARGO) test --locked --test orcarouter_provider -- --skip live_

check-orcarouter:
	$(CARGO) check --locked --all-features --lib --bin lonkero

live-orcarouter:
	$(CARGO) test --locked --test orcarouter_provider -- --exact live_orcarouter_chat_and_catalog --nocapture
