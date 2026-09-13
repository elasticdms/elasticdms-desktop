# Makefile — the folder client's handles, each with one line of description.
#
# `make help` shows them. The house's early-warning figure is "time from git clone to a running
# system" with a threshold of 30 minutes; `make mock` and `make demo` are the short way.

.DEFAULT_GOAL := help
.PHONY: help check test windows rules catalogs mock demo bundle format

## help: This overview.
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed -e 's/^## //' | awk -F': ' '{printf "  %-10s %s\n", $$1, $$2}'

## check: Everything that has to be green — format, clippy, tests, rules, catalogues, Windows.
check: format test catalogs windows
	cargo clippy --workspace --all-targets -- -D warnings

## format: Checks the formatting (changes nothing).
format:
	cargo fmt --all --check

## test: Every test on this machine, architecture rules included.
test:
	cargo test --workspace

## rules: The architecture rules only.
rules:
	cargo test -p architecture-rules

## catalogs: Reads the text catalogues with a second, foreign TOML implementation.
catalogs:
	python3 scripts/check-catalogs.py

## windows: Builds the workspace for Windows (needs cargo-xwin; nothing is run).
windows:
	cargo xwin check --workspace --target x86_64-pc-windows-msvc

## mock: Starts the server mock on 127.0.0.1:8480 (API) and :8481 (sign-in).
mock:
	cargo run -p edms-mock

## demo: Starts the app with sample data and an open window, without a server.
demo:
	cargo run -p elasticdms -- --demo --window

## bundle: Builds elasticdms.app with the file provider extension (macOS only; installs nothing).
bundle:
	scripts/macos-bundle.sh build
