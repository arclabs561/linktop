use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

const REGISTRY_PATHS: [&str; 7] = [
    "/opt/homebrew/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
    "/usr/share/nmap/nmap-mac-prefixes",
    "/opt/homebrew/share/wireshark/manuf",
    "/usr/local/share/wireshark/manuf",
    "/usr/share/wireshark/manuf",
    "/Applications/Wireshark.app/Contents/Resources/share/wireshark/manuf",
];

#[derive(Debug)]
pub struct OuiRegistry {
    source: String,
    entries: HashMap<[u8; 3], String>,
}

impl OuiRegistry {
    pub fn lookup(&self, mac: &str) -> Option<String> {
        self.entries.get(&prefix(mac)?).cloned()
    }

    pub fn source(&self) -> &str {
        &self.source
    }
}

pub fn system_registry() -> Option<&'static OuiRegistry> {
    static REGISTRY: OnceLock<Option<OuiRegistry>> = OnceLock::new();
    REGISTRY
        .get_or_init(|| REGISTRY_PATHS.iter().find_map(|path| load(Path::new(path))))
        .as_ref()
}

pub fn is_locally_administered(mac: &str) -> bool {
    prefix(mac).is_some_and(|bytes| bytes[0] & 0x02 != 0)
}

fn load(path: &Path) -> Option<OuiRegistry> {
    let contents = fs::read_to_string(path).ok()?;
    let mut entries = HashMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (raw_prefix, registrant) = match line.split_once(char::is_whitespace) {
            Some(parts) => parts,
            // A prefix with no vendor name on the line is one unusable entry,
            // not a reason to discard the rest of the registry.
            None => continue,
        };
        let Some(prefix) = parse_registry_prefix(raw_prefix) else {
            continue;
        };
        let registrant = registrant.trim();
        if !registrant.is_empty() {
            entries
                .entry(prefix)
                .or_insert_with(|| registrant.to_string());
        }
    }
    (!entries.is_empty()).then(|| OuiRegistry {
        source: path.display().to_string(),
        entries,
    })
}

fn parse_registry_prefix(value: &str) -> Option<[u8; 3]> {
    let compact: String = value
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .take(6)
        .collect();
    (compact.len() == 6).then(|| {
        [
            u8::from_str_radix(&compact[0..2], 16).ok()?,
            u8::from_str_radix(&compact[2..4], 16).ok()?,
            u8::from_str_radix(&compact[4..6], 16).ok()?,
        ]
        .into()
    })?
}

fn prefix(mac: &str) -> Option<[u8; 3]> {
    let mut octets = mac.split(':');
    Some([
        u8::from_str_radix(octets.next()?, 16).ok()?,
        u8::from_str_radix(octets.next()?, 16).ok()?,
        u8::from_str_radix(octets.next()?, 16).ok()?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nmap_and_wireshark_prefixes() {
        assert_eq!(parse_registry_prefix("AABBCC"), Some([0xaa, 0xbb, 0xcc]));
        assert_eq!(parse_registry_prefix("aa:bb:cc"), Some([0xaa, 0xbb, 0xcc]));
    }

    #[test]
    fn distinguishes_local_from_universal_addresses() {
        assert!(is_locally_administered("02:00:00:00:00:01"));
        assert!(!is_locally_administered("00:11:22:33:44:55"));
    }

    // Bug hunt repro: the nmap/Etherman registry ships lines whose vendor name
    // is missing. One such line used to abort the whole file, so every lookup
    // answered "unknown vendor".
    #[test]
    fn an_unnamed_registry_line_does_not_discard_the_registry() {
        let path = std::env::temp_dir().join(format!(
            "linktop-oui-test-{}-{:?}.txt",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(
            &path,
            "# comment\n\
             00:00:0C\tCisco Systems, Inc\n\
             00:00:0D\n\
             00:00:0E\tFujitsu\n",
        )
        .unwrap();
        let registry = load(&path);
        std::fs::remove_file(&path).unwrap();
        let registry = registry.expect("registry with one unnamed line");
        assert_eq!(
            registry.lookup("00:00:0C:11:22:33").as_deref(),
            Some("Cisco Systems, Inc")
        );
        assert_eq!(
            registry.lookup("00:00:0E:11:22:33").as_deref(),
            Some("Fujitsu")
        );
        assert_eq!(registry.lookup("00:00:0D:11:22:33"), None);
    }
}
