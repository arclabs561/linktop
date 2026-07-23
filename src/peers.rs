use std::collections::BTreeSet;
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;

use if_addrs::IfAddr;

use crate::model::{Health, LinkSnapshot, MacScope, Peer, PeerSnapshot};
use crate::{oui, process};

#[derive(Debug, Clone)]
struct PeerScope {
    active_interface: Option<String>,
    gateway: Option<IpAddr>,
    networks: Vec<LocalNetwork>,
}

#[derive(Debug, Clone, Copy)]
struct LocalNetwork {
    address: IpAddr,
    netmask: IpAddr,
}

impl PeerScope {
    fn for_link(link: &LinkSnapshot) -> Self {
        let active_interface = link.interface.clone();
        let networks = if_addrs::get_if_addrs()
            .unwrap_or_default()
            .into_iter()
            .filter(|interface| {
                active_interface.as_deref().is_none_or(|active| {
                    interface.name == active || interface.ip().to_string() == active
                })
            })
            .map(|interface| match interface.addr {
                IfAddr::V4(address) => LocalNetwork {
                    address: IpAddr::V4(address.ip),
                    netmask: IpAddr::V4(address.netmask),
                },
                IfAddr::V6(address) => LocalNetwork {
                    address: IpAddr::V6(address.ip),
                    netmask: IpAddr::V6(address.netmask),
                },
            })
            .collect();
        Self {
            active_interface,
            gateway: link.gateway.as_deref().and_then(parse_ip_token),
            networks,
        }
    }

    fn contains(&self, peer: &Peer) -> bool {
        let Some(address) = parse_ip_token(&peer.address) else {
            return false;
        };
        if self.gateway == Some(address) {
            return true;
        }
        let interface_matches = match (self.active_interface.as_deref(), peer.interface.as_deref())
        {
            (Some(active), Some(observed)) => active == observed,
            (Some(_), None) => true,
            (None, _) => true,
        };
        interface_matches
            && (self.networks.is_empty()
                || self
                    .networks
                    .iter()
                    .any(|network| network.contains(address)))
    }

    fn is_bounded(&self) -> bool {
        self.active_interface.is_some() && !self.networks.is_empty()
    }
}

impl LocalNetwork {
    fn contains(self, candidate: IpAddr) -> bool {
        match (self.address, self.netmask, candidate) {
            (IpAddr::V4(address), IpAddr::V4(mask), IpAddr::V4(candidate)) => {
                u32::from(address) & u32::from(mask) == u32::from(candidate) & u32::from(mask)
            }
            (IpAddr::V6(address), IpAddr::V6(mask), IpAddr::V6(candidate)) => {
                u128::from(address) & u128::from(mask) == u128::from(candidate) & u128::from(mask)
            }
            _ => false,
        }
    }
}

pub fn collect(link: &LinkSnapshot) -> PeerSnapshot {
    let scope = PeerScope::for_link(link);
    let commands: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("arp", &["-an"]), ("ndp", &["-an"])]
    } else if cfg!(target_os = "windows") {
        &[("arp", &["-a"])]
    } else {
        &[("ip", &["neigh", "show"]), ("arp", &["-an"])]
    };
    let local_addresses: BTreeSet<_> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .map(|address| address.ip())
        .collect();
    let mut sources = Vec::new();
    let mut failed_sources = Vec::new();
    let mut peers = Vec::new();
    let mut seen = BTreeSet::new();

    for (program, arguments) in commands {
        let mut command = Command::new(program);
        command.args(*arguments);
        let Ok(Some(output)) = process::run_bounded(&mut command, Duration::from_secs(2)) else {
            failed_sources.push(source_label(program, arguments));
            continue;
        };
        if !output.status.success() {
            failed_sources.push(source_label(program, arguments));
            continue;
        }
        sources.push(source_label(program, arguments));
        let parsed =
            parse_neighbor_output(&String::from_utf8_lossy(&output.stdout), &local_addresses);
        for peer in parsed.into_iter().filter(|peer| scope.contains(peer)) {
            let key = (
                peer.address.clone(),
                peer.mac.clone(),
                peer.interface.clone(),
            );
            if seen.insert(key) {
                peers.push(peer);
            }
        }
    }

    let oui_registry = oui::system_registry();
    for peer in &mut peers {
        let Some(mac) = peer.mac.as_deref() else {
            continue;
        };
        let local = oui::is_locally_administered(mac);
        peer.mac_scope = Some(if local {
            MacScope::Local
        } else {
            MacScope::Universal
        });
        if !local {
            peer.registrant = oui_registry.and_then(|registry| registry.lookup(mac));
        }
    }
    let oui_source = oui_registry.map(|registry| registry.source().to_string());

    let health = evidence_health(commands.len(), sources.len());
    if health == Health::Unavailable {
        PeerSnapshot {
            health,
            detail: format!(
                "no neighbor-cache source completed: {}",
                failed_sources.join(" + ")
            ),
            sources,
            failed_sources,
            oui_source,
            peers,
        }
    } else {
        peers.sort_by_key(|peer| {
            (
                peer.interface.is_none(),
                peer.address.contains(':'),
                peer.interface.clone(),
                peer.address.clone(),
            )
        });
        let scope_note = if scope.is_bounded() {
            "; active-path filtered"
        } else {
            "; path filter unavailable"
        };
        let failure_note = if failed_sources.is_empty() {
            String::new()
        } else {
            format!(
                "; incomplete evidence: {} failed",
                failed_sources.join(" + ")
            )
        };
        PeerSnapshot {
            health,
            detail: format!(
                "{} cached peer(s); no liveness scan{scope_note}{failure_note}",
                peers.len()
            ),
            sources,
            failed_sources,
            oui_source,
            peers,
        }
    }
}

fn source_label(program: &str, arguments: &[&str]) -> String {
    std::iter::once(program)
        .chain(arguments.iter().copied())
        .collect::<Vec<_>>()
        .join(" ")
}

fn evidence_health(attempted: usize, completed: usize) -> Health {
    match completed {
        0 => Health::Unavailable,
        completed if completed < attempted => Health::Degraded,
        _ => Health::Ok,
    }
}

fn parse_neighbor_output(output: &str, local_addresses: &BTreeSet<IpAddr>) -> Vec<Peer> {
    let mut peers = Vec::new();
    let mut windows_interface = None;
    for line in output.lines() {
        let tokens: Vec<_> = line.split_whitespace().collect();
        if line.trim_start().starts_with("Interface:") {
            windows_interface = tokens
                .get(1)
                .and_then(|token| parse_ip_token(token))
                .map(|address| address.to_string());
            continue;
        }
        let Some(address) = tokens.iter().find_map(|token| parse_ip_token(token)) else {
            continue;
        };
        if local_addresses.contains(&address)
            || address.is_loopback()
            || address.is_multicast()
            || address.is_unspecified()
        {
            continue;
        }
        let mac = tokens.iter().find_map(|token| normalize_mac(token));
        if mac.as_deref().is_some_and(is_multicast_mac) {
            continue;
        }
        let interface = value_after(&tokens, "dev")
            .or_else(|| value_after(&tokens, "on"))
            .map(str::to_string)
            .or_else(|| ndp_interface(&tokens, address))
            .or_else(|| windows_interface.clone());
        let state = [
            "REACHABLE",
            "STALE",
            "DELAY",
            "PROBE",
            "FAILED",
            "INCOMPLETE",
            "DYNAMIC",
        ]
        .into_iter()
        .find(|candidate| {
            tokens
                .iter()
                .any(|token| token.eq_ignore_ascii_case(candidate))
        })
        .map(str::to_string)
        .or_else(|| ndp_state(&tokens, address));
        peers.push(Peer {
            address: address.to_string(),
            mac,
            interface,
            state,
            mac_scope: None,
            registrant: None,
        });
    }
    peers
}

fn parse_ip_token(token: &str) -> Option<IpAddr> {
    let candidate = token
        .trim_matches(|character: char| matches!(character, '(' | ')' | ',' | ';'))
        .split('%')
        .next()?;
    IpAddr::from_str(candidate).ok()
}

fn normalize_mac(token: &str) -> Option<String> {
    let candidate = token
        .trim_matches(|character: char| matches!(character, '(' | ')' | ',' | ';'))
        .to_ascii_lowercase()
        .replace('-', ":");
    let octets: Vec<_> = candidate.split(':').collect();
    (octets.len() == 6
        && octets
            .iter()
            .all(|octet| !octet.is_empty() && octet.len() <= 2))
    .then(|| {
        octets
            .iter()
            .map(|octet| u8::from_str_radix(octet, 16).ok())
            .collect::<Option<Vec<_>>>()
            .map(|octets| {
                octets
                    .iter()
                    .map(|octet| format!("{octet:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            })
    })
    .flatten()
}

fn ndp_interface(tokens: &[&str], address: IpAddr) -> Option<String> {
    if !address.is_ipv6() {
        return None;
    }
    let link_index = tokens
        .iter()
        .position(|token| normalize_mac(token).is_some() || *token == "(incomplete)")?;
    tokens.get(link_index + 1).map(|value| (*value).to_string())
}

fn ndp_state(tokens: &[&str], address: IpAddr) -> Option<String> {
    if !address.is_ipv6() {
        return None;
    }
    tokens.iter().rev().find_map(|token| match *token {
        "R" => Some("REACHABLE".into()),
        "S" => Some("STALE".into()),
        "D" => Some("DELAY".into()),
        "P" => Some("PROBE".into()),
        "N" | "I" => Some("INCOMPLETE".into()),
        _ => None,
    })
}

fn is_multicast_mac(mac: &str) -> bool {
    mac == "ff:ff:ff:ff:ff:ff"
        || mac
            .split(':')
            .next()
            .and_then(|octet| u8::from_str_radix(octet, 16).ok())
            .is_some_and(|octet| octet & 1 == 1)
}

fn value_after<'a>(tokens: &'a [&str], needle: &str) -> Option<&'a str> {
    tokens
        .iter()
        .position(|token| *token == needle)
        .and_then(|index| tokens.get(index + 1))
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_cache_without_local_or_multicast_entries() {
        let local = BTreeSet::from([IpAddr::from_str("192.168.1.42").unwrap()]);
        let peers = parse_neighbor_output(
            "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:fe REACHABLE\n\
             192.168.1.50 dev eth0 lladdr ff:ff:ff:ff:ff:ff STALE\n\
             192.168.1.42 dev eth0 lladdr 10:22:33:44:55:66 STALE\n\
             fe80::2 dev eth0 lladdr 22:33:44:55:66:77 STALE\n",
            &local,
        );
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].address, "192.168.1.1");
        assert_eq!(peers[0].state.as_deref(), Some("REACHABLE"));
        assert_eq!(peers[1].address, "fe80::2");
    }

    #[test]
    fn parses_macos_arp_shape() {
        let peers = parse_neighbor_output(
            "? (192.168.1.1) at aa:bb:cc:dd:ee:fe on en0 ifscope [ethernet]\n",
            &BTreeSet::new(),
        );
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].interface.as_deref(), Some("en0"));
        assert_eq!(peers[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:fe"));
    }

    #[test]
    fn parses_macos_ndp_interface_state_and_short_mac_octets() {
        let peers = parse_neighbor_output(
            "2001:db8::1 00:11:22:33:4:5 en0 28s R R\n\
             fe80::2 (incomplete) utun4 expired N\n",
            &BTreeSet::new(),
        );
        assert_eq!(peers[0].interface.as_deref(), Some("en0"));
        assert_eq!(peers[0].state.as_deref(), Some("REACHABLE"));
        assert_eq!(peers[0].mac.as_deref(), Some("00:11:22:33:04:05"));
        assert_eq!(peers[1].interface.as_deref(), Some("utun4"));
        assert_eq!(peers[1].state.as_deref(), Some("INCOMPLETE"));
    }

    #[test]
    fn old_same_interface_cache_entries_are_excluded_after_a_subnet_change() {
        let scope = PeerScope {
            active_interface: Some("en0".into()),
            gateway: Some(IpAddr::from_str("172.20.10.1").unwrap()),
            networks: vec![LocalNetwork {
                address: IpAddr::from_str("172.20.10.14").unwrap(),
                netmask: IpAddr::from_str("255.255.255.240").unwrap(),
            }],
        };
        let peers = parse_neighbor_output(
            "192.168.1.1 dev en0 lladdr aa:bb:cc:dd:ee:01 STALE\n\
             172.20.10.1 dev en0 lladdr aa:bb:cc:dd:ee:02 REACHABLE\n\
             172.20.10.3 dev en0 lladdr aa:bb:cc:dd:ee:03 STALE\n\
             172.20.10.4 dev en1 lladdr aa:bb:cc:dd:ee:04 STALE\n",
            &BTreeSet::new(),
        );
        let visible: Vec<_> = peers
            .into_iter()
            .filter(|peer| scope.contains(peer))
            .map(|peer| peer.address)
            .collect();
        assert_eq!(visible, ["172.20.10.1", "172.20.10.3"]);
    }

    #[test]
    fn incomplete_native_evidence_is_degraded() {
        assert_eq!(evidence_health(2, 2), Health::Ok);
        assert_eq!(evidence_health(2, 1), Health::Degraded);
        assert_eq!(evidence_health(2, 0), Health::Unavailable);
    }
}
