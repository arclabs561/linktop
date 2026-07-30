check:
    cargo +1.88 fmt -- --check
    cargo +1.88 build --locked --bin linktop
    cargo +1.88 test --locked
    cargo +1.88 clippy --locked --all-targets -- -D warnings
    cargo +1.88 rustdoc --locked --lib -- -D warnings
    cargo +1.88 metadata --locked --format-version 1 | jq -e '[.resolve.nodes[] as $node | .packages[] | select(.id == $node.id and .name == "netbraid") | $node.features] == [["scenario-fixtures"]]'
    set -eu; package_list="$(mktemp)"; trap 'rm -f "$package_list"' EXIT; cargo +1.88 package --locked --allow-dirty --list >"$package_list"; grep -Fqx README.md "$package_list"; grep -Fqx LICENSE "$package_list"; grep -Fqx CHANGELOG.md "$package_list"; grep -Fqx src/lib.rs "$package_list"; grep -Fqx src/capture/fixtures/v1/qa_capture_manifest.json "$package_list"; grep -Fqx src/output/fixtures/v1/snapshot.json "$package_list"; grep -Fqx src/review/fixtures/positive-records.jsonl "$package_list"; if grep -Eq '^(\.github/|AGENTS\.md$|docs/|justfile$)' "$package_list"; then printf 'package contains repository-only files\n' >&2; exit 1; fi; cargo +1.88 package --locked --allow-dirty; version="$(cargo +1.88 metadata --no-deps --format-version 1 | jq -er '.packages[0].version')"; cargo +1.88 test --locked --manifest-path "target/package/linktop-${version}/Cargo.toml"; cargo +1.88 rustdoc --locked --manifest-path "target/package/linktop-${version}/Cargo.toml" --lib -- -D warnings

check-netbraid-source:
    @scripts/check-netbraid-source.sh

mutation-check:
    cargo mutants --package linktop --file src/model.rs --re 'path_fingerprint_candidate_from_identity' --test-package linktop --jobs 2 --timeout 180 --no-shuffle -v

# Run a real live view headlessly and save private, styled frames plus a
# completion-last integrity manifest. Comma-separated times produce several frames.
capture-ui view="overview" columns="140" rows="30" at="5":
    cargo run --quiet -- screenshot {{view}} --at {{at}} --columns {{columns}} --rows {{rows}} --output-dir .agents/reports/ui-captures

# Exercise the installed TUI path inside a real fixed-size PTY. This requires
# tmux and emits plain text, ANSI, self-contained HTML, and an integrity manifest.
capture-native view="overview" columns="140" rows="30" at="5":
    cargo run --quiet -- screenshot {{view}} --native --at {{at}} --columns {{columns}} --rows {{rows}} --output-dir .agents/reports/ui-captures

# Exercise a stable initial Wi-Fi, hotspot attachment, and known Wi-Fi return
# across wide, minimum, and intermediate terminal geometries, then revisit the
# returned path at wide width so the completed prior window remains inspectable.
capture-transition:
    cargo run --quiet -- screenshot overview --scene wifi-hotspot-wifi --at 1,3,5,7 --columns 160 --rows 30 --resize 3:60x10 --resize 5:100x24 --resize 7:160x30 --output-dir .agents/reports/ui-captures

capture-transition-native:
    cargo run --quiet -- screenshot overview --native --scene wifi-hotspot-wifi --at 1,3,5,7 --columns 160 --rows 30 --resize 3:60x10 --resize 5:100x24 --resize 7:160x30 --output-dir .agents/reports/ui-captures

# Install the release binary in Cargo's PATH directory and retain the old names
# as compatibility aliases. Refuse to replace user-owned regular files.
install: check
    cargo install --path . --locked --force
    cargo_bin="${CARGO_HOME:-${HOME}/.cargo}/bin"; \
    for alias in pinglet pingl; do \
        if [ -e "$cargo_bin/$alias" ] && [ ! -L "$cargo_bin/$alias" ]; then \
            printf 'refusing to replace non-symlink %s/%s\n' "$cargo_bin" "$alias" >&2; \
            exit 1; \
        fi; \
        ln -sfn linktop "$cargo_bin/$alias"; \
    done

# Point the PATH command at this checkout's debug binary. Every subsequent
# `cargo build`, `cargo run`, `just check`, or capture refreshes the same file.
install-dev: check
    cargo_bin="${CARGO_HOME:-${HOME}/.cargo}/bin"; \
    target="{{justfile_directory()}}/target/debug/linktop"; \
    mkdir -p "$cargo_bin"; \
    ln -sfn "$target" "$cargo_bin/linktop"; \
    for alias in pinglet pingl; do \
        if [ -e "$cargo_bin/$alias" ] && [ ! -L "$cargo_bin/$alias" ]; then \
            printf 'refusing to replace non-symlink %s/%s\n' "$cargo_bin" "$alias" >&2; \
            exit 1; \
        fi; \
        ln -sfn linktop "$cargo_bin/$alias"; \
    done
