use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use netbraid::evidence::{CoverageStateV0, HostPathObservationV0};
use netbraid::replay::parse_host_path_jsonl;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CAPSULE_SCHEMA_V0: &str = "linktop.incident_capsule.v0";
const MIB: u64 = 1024 * 1024;
const CAPSULE_MANIFEST_MAX_BYTES: u64 = MIB;
const CAPSULE_SOURCE_MAX_BYTES: u64 = 128 * MIB;
const SOURCE_ARTIFACT: &str = "host-path.jsonl";

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Package a canonical private Netbraid host-path log.
    Pack {
        /// Canonical Netbraid host-path JSONL input.
        input: PathBuf,
        /// New private capsule directory to create.
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify a capsule's manifest, digest, and canonical source artifact.
    Verify {
        /// Capsule directory containing capsule.json and host-path.jsonl.
        capsule: PathBuf,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleManifestV0 {
    pub schema: String,
    pub producer: CapsuleProducerV0,
    pub redaction_profile: String,
    pub source: CapsuleSourceV0,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleProducerV0 {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleSourceV0 {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub records: u64,
    pub first_event_time_unix_ms: Option<i64>,
    pub last_event_time_unix_ms: Option<i64>,
    pub observer_ids: Vec<String>,
    pub coverage_states: Vec<String>,
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Pack { input, output } => {
            let manifest = pack(&input, &output)?;
            println!(
                "capsule packed {} record(s) into {}",
                manifest.source.records,
                output.display()
            );
        }
        Command::Verify { capsule } => {
            let manifest = verify(&capsule)?;
            println!(
                "capsule verified {} record(s) from {}",
                manifest.source.records,
                capsule.display()
            );
        }
    }
    Ok(())
}

pub fn pack(input: &Path, output: &Path) -> Result<CapsuleManifestV0> {
    ensure!(input.is_file(), "capsule input is not a regular file");
    ensure!(!output.exists(), "capsule output already exists");
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure!(parent.is_dir(), "capsule output parent is not a directory");

    let bytes = read_bounded(input, CAPSULE_SOURCE_MAX_BYTES, "capsule input")?;
    let records = canonical_records(&bytes)?;
    let manifest = manifest_for(&bytes, &records, env!("CARGO_PKG_VERSION"));
    let temporary = temporary_output(parent, output);

    fs::create_dir(&temporary)
        .with_context(|| format!("create temporary capsule {}", temporary.display()))?;
    if let Err(error) = write_capsule(&temporary, &bytes, &manifest) {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error);
    }
    if let Err(error) = verify(&temporary) {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error).context("verify temporary capsule");
    }
    if let Err(error) = fs::rename(&temporary, output) {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error)
            .with_context(|| format!("publish capsule directory {}", output.display()));
    }
    Ok(manifest)
}

pub fn verify(capsule: &Path) -> Result<CapsuleManifestV0> {
    ensure!(capsule.is_dir(), "capsule is not a directory");
    let manifest_path = capsule.join("capsule.json");
    let source_path = capsule.join(SOURCE_ARTIFACT);
    let manifest_bytes = read_bounded(
        &manifest_path,
        CAPSULE_MANIFEST_MAX_BYTES,
        "capsule manifest",
    )?;
    let manifest: CapsuleManifestV0 =
        serde_json::from_slice(&manifest_bytes).context("parse capsule manifest")?;
    ensure!(
        manifest.schema == CAPSULE_SCHEMA_V0,
        "unsupported capsule schema"
    );
    ensure!(
        manifest.producer.name == "linktop",
        "unsupported capsule producer"
    );
    ensure!(
        !manifest.producer.version.trim().is_empty(),
        "capsule producer version is empty"
    );
    ensure!(
        manifest.redaction_profile == "none",
        "unsupported capsule redaction profile"
    );
    ensure!(
        manifest.source.path == SOURCE_ARTIFACT,
        "unsupported capsule source path"
    );

    let bytes = read_bounded(&source_path, CAPSULE_SOURCE_MAX_BYTES, "capsule source")?;
    let records = canonical_records(&bytes)?;
    let expected = manifest_for(&bytes, &records, &manifest.producer.version);
    ensure!(
        manifest.source == expected.source,
        "capsule manifest does not match its source artifact"
    );
    Ok(manifest)
}

fn read_bounded(path: &Path, max_bytes: u64, artifact: &str) -> Result<Vec<u8>> {
    let mut file =
        File::open(path).with_context(|| format!("open {artifact} {}", path.display()))?;
    let file_bytes = file
        .metadata()
        .with_context(|| format!("inspect {artifact} {}", path.display()))?
        .len();
    ensure!(
        file_bytes <= max_bytes,
        "{artifact} exceeds {max_bytes}-byte limit"
    );

    let mut bytes = Vec::new();
    file.by_ref()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {artifact} {}", path.display()))?;
    ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= max_bytes,
        "{artifact} exceeds {max_bytes}-byte limit"
    );
    Ok(bytes)
}

fn canonical_records(bytes: &[u8]) -> Result<Vec<HostPathObservationV0>> {
    let replay = parse_host_path_jsonl(bytes).context("parse host-path evidence")?;
    let mut canonical = Vec::new();
    for record in &replay.records {
        serde_json::to_writer(&mut canonical, record).context("serialize canonical record")?;
        canonical.push(b'\n');
    }
    ensure!(
        canonical == bytes,
        "host-path input is valid but not canonical JSONL"
    );
    Ok(replay.records)
}

fn manifest_for(
    bytes: &[u8],
    records: &[HostPathObservationV0],
    producer_version: &str,
) -> CapsuleManifestV0 {
    let mut observer_ids = BTreeSet::new();
    let mut coverage_states = BTreeSet::new();
    for record in records {
        observer_ids.insert(record.source.observer_id.clone());
        coverage_states.insert(coverage_state_label(record.coverage.state));
    }
    CapsuleManifestV0 {
        schema: CAPSULE_SCHEMA_V0.into(),
        producer: CapsuleProducerV0 {
            name: "linktop".into(),
            version: producer_version.into(),
        },
        redaction_profile: "none".into(),
        source: CapsuleSourceV0 {
            path: SOURCE_ARTIFACT.into(),
            sha256: sha256(bytes),
            bytes: bytes.len().try_into().unwrap_or(u64::MAX),
            records: records.len().try_into().unwrap_or(u64::MAX),
            first_event_time_unix_ms: records
                .first()
                .map(|record| record.order.event_time_unix_ms),
            last_event_time_unix_ms: records.last().map(|record| record.order.event_time_unix_ms),
            observer_ids: observer_ids.into_iter().collect(),
            coverage_states: coverage_states.into_iter().collect(),
        },
    }
}

fn coverage_state_label(state: CoverageStateV0) -> String {
    match state {
        CoverageStateV0::Complete => "complete",
        CoverageStateV0::Partial => "partial",
        CoverageStateV0::Unavailable => "unavailable",
    }
    .into()
}

fn write_capsule(directory: &Path, bytes: &[u8], manifest: &CapsuleManifestV0) -> Result<()> {
    set_private_directory(directory)?;
    let source_path = directory.join(SOURCE_ARTIFACT);
    fs::write(&source_path, bytes)
        .with_context(|| format!("write capsule source {}", source_path.display()))?;
    set_private_file(&source_path)?;
    let mut manifest_bytes =
        serde_json::to_vec_pretty(manifest).context("serialize capsule manifest")?;
    manifest_bytes.push(b'\n');
    let manifest_path = directory.join("capsule.json");
    fs::write(&manifest_path, manifest_bytes)
        .with_context(|| format!("write capsule manifest {}", manifest_path.display()))?;
    set_private_file(&manifest_path)?;
    Ok(())
}

fn temporary_output(parent: &Path, output: &Path) -> PathBuf {
    let name = output
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("capsule");
    parent.join(format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        unique_nonce()
    ))
}

fn unique_nonce() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn set_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_private_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORD: &[u8] = br#"{"schema":"netmon.host_path_observation.v0","record_id":"observer:7","order":{"event_time_unix_ms":1000,"acquired_time_unix_ms":1005,"source_sequence":7},"source":{"observer_id":"observer","adapter":"linktop","adapter_version":"0.1.0"},"policy":{"mode":"passive_host_local"},"coverage":{"state":"complete","observed_sources":["address","route"]},"path":{"interface":"en0","link_type":"wifi","network_name":{"visibility":"observed","value":"lab"},"association_id":"association-7","associated_bssid":"02:00:00:00:00:07","next_hop":"192.0.2.1","next_hop_link_address":"02:00:00:00:01:01","resolvers":["192.0.2.53","2001:db8::53"],"address_prefixes":["192.0.2.7","2001:db8:7::/64"]}}
"#;

    fn temporary_directory(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "linktop-capsule-{label}-{}-{}",
            std::process::id(),
            unique_nonce()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn pack_then_verify_preserves_canonical_source_and_manifest() {
        let root = temporary_directory("roundtrip");
        let input = root.join("history.jsonl");
        let output = root.join("capsule");
        fs::write(&input, RECORD).unwrap();

        let packed = pack(&input, &output).unwrap();
        let verified = verify(&output).unwrap();

        assert_eq!(packed, verified);
        assert_eq!(verified.schema, CAPSULE_SCHEMA_V0);
        assert_eq!(verified.source.records, 1);
        assert_eq!(fs::read(output.join(SOURCE_ARTIFACT)).unwrap(), RECORD);
        let manifest = fs::read_to_string(output.join("capsule.json")).unwrap();
        assert!(!manifest.contains("history.jsonl"));
        let replay = netbraid::replay::read_jsonl(output.join(SOURCE_ARTIFACT)).unwrap();
        assert_eq!(replay.records.len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pack_rejects_malformed_input_without_publishing() {
        let root = temporary_directory("malformed");
        let input = root.join("history.jsonl");
        let output = root.join("capsule");
        fs::write(&input, b"{\"schema\":\"wrong\"}\n").unwrap();

        let error = pack(&input, &output).unwrap_err();

        assert!(error.to_string().contains("parse host-path evidence"));
        assert!(!output.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pack_rejects_valid_but_noncanonical_input_without_publishing() {
        let root = temporary_directory("noncanonical");
        let input = root.join("history.jsonl");
        let output = root.join("capsule");
        let mut noncanonical = RECORD.to_vec();
        noncanonical.pop();
        fs::write(&input, noncanonical).unwrap();

        let error = pack(&input, &output).unwrap_err();

        assert!(error.to_string().contains("not canonical JSONL"));
        assert!(!output.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pack_rejects_input_one_byte_over_limit_without_publishing() {
        let root = temporary_directory("oversized-input");
        let input = root.join("history.jsonl");
        let output = root.join("capsule");
        File::create(&input)
            .unwrap()
            .set_len(CAPSULE_SOURCE_MAX_BYTES + 1)
            .unwrap();

        let error = pack(&input, &output).unwrap_err();

        assert_eq!(
            error.to_string(),
            format!("capsule input exceeds {CAPSULE_SOURCE_MAX_BYTES}-byte limit")
        );
        assert!(!output.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn verify_rejects_manifest_one_byte_over_limit() {
        let root = temporary_directory("oversized-manifest");
        let input = root.join("history.jsonl");
        let output = root.join("capsule");
        fs::write(&input, RECORD).unwrap();
        pack(&input, &output).unwrap();
        File::create(output.join("capsule.json"))
            .unwrap()
            .set_len(CAPSULE_MANIFEST_MAX_BYTES + 1)
            .unwrap();

        let error = verify(&output).unwrap_err();

        assert_eq!(
            error.to_string(),
            format!("capsule manifest exceeds {CAPSULE_MANIFEST_MAX_BYTES}-byte limit")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn verify_rejects_source_one_byte_over_limit() {
        let root = temporary_directory("oversized-source");
        let input = root.join("history.jsonl");
        let output = root.join("capsule");
        fs::write(&input, RECORD).unwrap();
        pack(&input, &output).unwrap();
        File::create(output.join(SOURCE_ARTIFACT))
            .unwrap()
            .set_len(CAPSULE_SOURCE_MAX_BYTES + 1)
            .unwrap();

        let error = verify(&output).unwrap_err();

        assert_eq!(
            error.to_string(),
            format!("capsule source exceeds {CAPSULE_SOURCE_MAX_BYTES}-byte limit")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_source() {
        let root = temporary_directory("tampered");
        let input = root.join("history.jsonl");
        let output = root.join("capsule");
        fs::write(&input, RECORD).unwrap();
        pack(&input, &output).unwrap();
        let mut tampered = RECORD.to_vec();
        let position = tampered
            .windows(3)
            .position(|window| window == b"lab")
            .unwrap();
        tampered[position..position + 3].copy_from_slice(b"xxx");
        fs::write(output.join(SOURCE_ARTIFACT), tampered).unwrap();

        let error = verify(&output).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("manifest does not match its source artifact")
        );
        fs::remove_dir_all(root).unwrap();
    }
}
