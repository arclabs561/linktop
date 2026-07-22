check:
    cargo fmt -- --check
    cargo test
    cargo clippy --all-targets -- -D warnings

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
