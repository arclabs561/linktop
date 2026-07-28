---
id: 0013
status: accepted
governs: Cargo.toml, Cargo.lock, CHANGELOG.md, README.md, justfile, .github/workflows/**, .github/settings.yml
why: Linktop is one operator binary with one release cadence; crates.io provides Rust-native installation while checksummed native archives provide toolchain-free installation without creating extra product identities
rejected: source checkout only (avoidable install friction), crates.io only (requires a Rust toolchain), GitHub archives only (misses the Rust-native channel), separately published alias packages or binaries (duplicate identities), tag-triggered bootstrap publication (a tag would own a version before registry publication succeeds), automatic package-manager channels now (no demonstrated maintenance budget), a Windows archive in the first release (no proven native packaging lane)
supersedes: none
superseded_by: none
extends: 0001, 0004, 0008, 0010
confidence: high
review_trigger: an independently useful Linktop library API emerges, managed package-channel demand justifies another release lane, Windows native packaging becomes proven, signing or notarization becomes required, or a compatibility alias needs an independent lifecycle
---

# ADR-0013: publish one Linktop binary package

## Context

Linktop has been public source but deliberately set `publish = false`. That
kept the first standalone implementation from accidentally creating a package
contract while its product boundary, passive defaults, deterministic QA, and
Netbraid relationship were still changing. Those boundaries are now recorded
and exercised, and Netbraid's registry release removes Linktop's unpublished
Git dependencies.

An operator should not need to know this workstation's source layout to run
Linktop. Rust users expect `cargo install`; operators without a Rust toolchain
benefit from a small native archive. Publishing historical names such as
`pinglet` or `pingl`, splitting the binary into artificial subcrates, or
creating package-manager formulae before there is demand would multiply
identities and release work without adding capability.

The first crates.io publication cannot use Trusted Publishing because crates.io
requires an existing crate before a GitHub workflow can be registered as its
publisher. Pushing a release tag before that bootstrap succeeds would make an
immutable version claim while the registry half of the release was absent.

## Decision

Publish one Cargo package and one executable named `linktop`, beginning at
0.1.0. The source repository remains one package rather than a workspace.
Compatibility aliases remain conveniences of the checkout's `just install`
recipe; they are not additional Cargo packages, executables, tags, or release
assets.

Each version has one source commit and one tag of the form
`linktop-v<version>`. The crates.io package and GitHub release archives must be
built from that same clean commit. The package uses an explicit source
whitelist and its release gate tests the extracted package, so repository-only
instructions and workflows do not become accidental package contents while
runtime fixtures remain available.

The initial distribution channels are:

- crates.io for `cargo install linktop --version <version> --locked`; and
- checksummed GitHub archives for x86-64 Linux, Intel macOS, and Apple-silicon
  macOS.

Each native archive contains the `linktop` executable, README, license, and
changelog. CI smoke-tests the archived executable, bundles SHA-256 checksums,
and attaches GitHub build-provenance attestations. The first macOS archives are
not code-signed or notarized. Windows remains supported through Cargo and
source builds until a native archive lane is proven.

Bootstrap the crates.io name from a clean, current-main checkout with a
short-lived token scoped to the new `linktop` crate. Verify the published
package's repository, version, yanked state, and `.cargo_vcs_info.json` commit;
then register `.github/workflows/release.yml` as the Trusted Publisher, prove
the OIDC publication path, and revoke the bootstrap token. Only then create and
push the version tag. Later releases use the same confirmed workflow before
tagging.

Do not add Homebrew, MacPorts, system-package, installer-script, or separately
signed channels until operator demand and a maintained verification path
justify them.

## Options considered

- **Keep source-checkout installation only.** Rejected because it preserves a
  workstation-layout dependency and makes ordinary installation needlessly
  bespoke.
- **Publish only to crates.io.** Rejected because native users should not need
  a Rust toolchain merely to run one operator binary.
- **Publish only native GitHub archives.** Rejected because crates.io is the
  conventional checksummed installation and dependency channel for Rust.
- **Publish aliases or implementation subcrates separately.** Rejected because
  Linktop has one operator-facing lifecycle and no independently useful public
  library boundary.
- **Let a version tag perform first publication.** Rejected because registry
  ownership and Trusted Publishing cannot be proven before the initial crate
  exists.
- **Add every platform and package manager immediately.** Rejected because an
  untested distribution surface is ongoing operational work, not free reach.

## Consequences

`cargo install linktop` becomes the portable default while source installation
continues to provide local compatibility aliases and the latest checkout for
development. Release metadata, changelog entries, the Cargo lock, package
inventory, native builds, checksums, and registry provenance become one
coordinated release contract.

The release workflow is intentionally able to build and validate assets without
publishing them. Registry publication is a confirmed current-main operation;
tag publication is idempotent only when crates.io already contains the exact
version from the exact commit.

Three native targets leave a deliberate Windows distribution gap, and unsigned
macOS binaries may require operator trust handling. Those are explicit limits,
not implied support. Additional channels should reuse the same version, source
commit, checksums, and provenance rather than establishing another release
identity.

## Lineage

Extends ADR-0001's standalone binary identity, ADR-0004's bounded artifact
transaction, ADR-0008's released Netbraid dependency boundary, and ADR-0010's
single typed-model projection. It reverses the temporary `publish = false`
implementation choice now that the package and release gates exist.
