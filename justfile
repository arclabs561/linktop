check:
    cargo +1.88 fmt -- --check
    cargo +1.88 build --bin linktop
    cargo +1.88 test
    cargo +1.88 clippy --all-targets -- -D warnings

# Run a real live view headlessly and save private, styled frames at the
# requested elapsed seconds. Comma-separated times produce several frames.
capture-ui view="overview" columns="140" rows="30" at="5":
    cargo run --quiet -- screenshot {{view}} --at {{at}} --columns {{columns}} --rows {{rows}} --output-dir .agents/reports/ui-captures

# Exercise the installed TUI path inside a real fixed-size PTY. This requires
# tmux and emits plain text, ANSI, and a self-contained HTML view.
capture-native view="overview" columns="140" rows="30" at="5":
    cargo run --quiet -- screenshot {{view}} --native --at {{at}} --columns {{columns}} --rows {{rows}} --output-dir .agents/reports/ui-captures

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
