use std::collections::BTreeSet;
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;

use crate::model::{Health, MacScope, Peer, PeerSnapshot};
use crate::{oui, process};

pub fn collect() -> PeerSnapshot {
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
    let mut peers = Vec::new();
    let mut seen = BTreeSet::new();

    for (program, arguments) in commands {
        let mut command = Command::new(program);
        command.args(*arguments);
        let Ok(Some(output)) = process::run_bounded(&mut command, Duration::from_secs(2)) else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        sources.push(
            std::iter::once(*program)
                .chain(arguments.iter().copied())
                .collect::<Vec<_>>()
                .join(" "),
        );
        let parsed =
            parse_neighbor_output(&String::from_utf8_lossy(&output.stdout), &local_addresses);
        for peer in parsed {
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

    if sources.is_empty() {
        PeerSnapshot {
            health: Health::Unavailable,
            detail: "no neighbor-cache command available".into(),
            sources,
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
        PeerSnapshot {
            health: Health::Ok,
            detail: format!("{} cached peer(s); no liveness scan", peers.len()),
            sources,
            oui_source,
            peers,
        }
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
}
