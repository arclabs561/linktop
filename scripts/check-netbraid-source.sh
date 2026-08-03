#!/bin/sh

set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
netbraid_source=${NETBRAID_SOURCE:-}
if [ -z "$netbraid_source" ]; then
    printf '%s\n' 'NETBRAID_SOURCE must point to Netbraid rust/' >&2
    exit 2
fi
netbraid_source=$(CDPATH='' cd -- "$netbraid_source" && pwd)

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
import re
import sys

manifest_path = pathlib.Path(sys.argv[1])
netbraid_source = json.dumps(sys.argv[2])
manifest = manifest_path.read_text()
pattern = re.compile(
    r'^netbraid = \{ version = "([^"]+)", default-features = false, '
    r'features = \["scenario-fixtures"\] \}$',
    re.MULTILINE,
)
replacement = (
    'netbraid = { version = "\\1", path = '
    f'{netbraid_source}, default-features = false, features = ["scenario-fixtures"] }}'
)
manifest, replacements = pattern.subn(replacement, manifest, count=1)
if replacements != 1:
    raise SystemExit("Linktop Netbraid dependency line was not found")
manifest_path.write_text(manifest)
PY

printf 'linktop: testing against Netbraid source %s\n' "$netbraid_source"
cargo test --offline --manifest-path "$tmp_root/Cargo.toml"
cargo build --offline --manifest-path "$tmp_root/Cargo.toml" --bin linktop
python3 "$tmp_root/tests/review_campaign.py" --self-test
python3 "$tmp_root/tests/review_campaign.py" \
    --linktop "$tmp_root/target/debug/linktop"
cargo clippy --offline --manifest-path "$tmp_root/Cargo.toml" --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --offline --manifest-path "$tmp_root/Cargo.toml" --no-deps
