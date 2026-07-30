#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
netbraid_source=${NETBRAID_SOURCE:-}
if [ -z "$netbraid_source" ]; then
    printf '%s\n' 'NETBRAID_SOURCE must point to Netbraid rust/' >&2
    exit 2
fi
netbraid_source=$(CDPATH= cd -- "$netbraid_source" && pwd)

case "$netbraid_source" in
    */rust) ;;
    *)
        printf 'NETBRAID_SOURCE must end in /rust: %s\n' "$netbraid_source" >&2
        exit 2
        ;;
esac

tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/linktop-netbraid-source.XXXXXX")
cleanup() {
    rm -rf -- "$tmp_root"
}
trap cleanup EXIT HUP INT TERM

cp "$repo_root/Cargo.toml" "$repo_root/Cargo.lock" "$repo_root/README.md" \
    "$repo_root/LICENSE" "$repo_root/CHANGELOG.md" "$tmp_root/"
cp -R "$repo_root/src" "$tmp_root/"
if [ -d "$repo_root/tests" ]; then
    cp -R "$repo_root/tests" "$tmp_root/"
fi

python3 - "$tmp_root/Cargo.toml" "$netbraid_source" <<'PY'
import json
import pathlib
import sys

manifest_path = pathlib.Path(sys.argv[1])
netbraid_source = json.dumps(sys.argv[2])
manifest = manifest_path.read_text()
old = 'netbraid = { version = "0.3.0", default-features = false, features = ["scenario-fixtures"] }'
new = f'netbraid = {{ version = "0.3.0", path = {netbraid_source}, default-features = false, features = ["scenario-fixtures"] }}'
if old not in manifest:
    raise SystemExit("Linktop Netbraid dependency line was not found")
manifest_path.write_text(manifest.replace(old, new, 1))
PY

printf 'linktop: testing against Netbraid source %s\n' "$netbraid_source"
cargo test --offline --manifest-path "$tmp_root/Cargo.toml"
cargo clippy --offline --manifest-path "$tmp_root/Cargo.toml" --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --offline --manifest-path "$tmp_root/Cargo.toml" --no-deps
