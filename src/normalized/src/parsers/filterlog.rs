/// pfSense filterlog CSV parser.
///
/// Receives the syslog *message* body — the raw CSV payload after the RFC 5424
/// envelope has already been unwrapped. Triggered as a second pass via an
/// override rule (`reparse = true`, `reparse_as = "filterlog"`).
///
/// FreeBSD filterlog(4) positional CSV format.
///
/// Common header (columns 0–8):
///   0  rule_number
///   1  sub_rule
///   2  anchor
///   3  tracker
///   4  real_interface   (re0, re1, re2.500, …)
///   5  reason           (match, ip-option, bad-offset, …)
///   6  action           (block, pass)
///   7  direction        (in, out)
///   8  ip_version       (4 or 6)
///
/// IPv4 columns 9–19+:
///   9   tos     10  ecn    11  ttl    12  id     13  offset   14  flags
///   15  proto_id           (1=ICMP 2=IGMP 6=TCP 17=UDP 50=ESP …)
///   16  proto_name
///   17  length
///   18  src_ip
///   19  dst_ip
///   20+ protocol-specific:
///       TCP/UDP → src_port, dst_port, data_len [, tcp_flags, …]
///       ICMP    → icmp type description
///       other   → datalength=N or empty
///
/// IPv6 columns 9–16+:
///   9   class   10  flow_label   11  hop_limit
///   12  proto_name               (ICMPv6, UDP, TCP, …)
///   13  proto_id
///   14  length
///   15  src_ip
///   16  dst_ip
///   17+ protocol-specific (same layout as IPv4 for UDP/TCP)

use std::collections::HashMap;
use crate::event::{Event, Format};

pub fn parse(raw: &[u8], source_addr: &str) -> Option<Event> {
    let s = std::str::from_utf8(raw).ok()?.trim();
    let cols: Vec<&str> = s.split(',').collect();

    if cols.len() < 9 {
        return None;
    }

    let action    = cols[6];
    let direction = cols[7];
    let ip_ver    = cols[8];
    let interface = cols[4];

    // Quick rejection: must be a valid filterlog action/version.
    if !matches!(action, "block" | "pass") { return None; }
    if !matches!(ip_ver, "4" | "6")        { return None; }

    let mut fields = HashMap::new();

    // Normalise action to canonical values used by the iptables/UFW rules.
    fields.insert("action".to_string(),    if action == "pass" { "ALLOW" } else { "BLOCK" }.to_string());
    fields.insert("direction".to_string(), direction.to_string());
    fields.insert("interface".to_string(), interface.to_string());

    if ip_ver == "4" {
        // Minimum needed: up to dst_ip at col 19.
        if cols.len() < 20 { return None; }

        let proto  = cols[16];
        let src_ip = cols[18];
        let dst_ip = cols[19];

        if !proto.is_empty()  { fields.insert("protocol".to_string(), proto.to_ascii_uppercase()); }
        if !src_ip.is_empty() { fields.insert("src_ip".to_string(),   src_ip.to_string()); }
        if !dst_ip.is_empty() { fields.insert("dst_ip".to_string(),   dst_ip.to_string()); }

        // UDP and TCP both carry src_port/dst_port at cols 20 and 21.
        if matches!(proto.to_ascii_lowercase().as_str(), "tcp" | "udp") && cols.len() > 21 {
            let sp = cols[20].trim();
            let dp = cols[21].trim();
            if !sp.is_empty() { fields.insert("src_port".to_string(), sp.to_string()); }
            if !dp.is_empty() { fields.insert("dst_port".to_string(), dp.to_string()); }
        }
    } else {
        // IPv6: minimum up to dst_ip at col 16.
        if cols.len() < 17 { return None; }

        let proto  = cols[12];
        let src_ip = cols[15];
        let dst_ip = cols[16];

        if !proto.is_empty()  { fields.insert("protocol".to_string(), proto.to_ascii_uppercase()); }
        if !src_ip.is_empty() { fields.insert("src_ip".to_string(),   src_ip.to_string()); }
        if !dst_ip.is_empty() { fields.insert("dst_ip".to_string(),   dst_ip.to_string()); }

        if matches!(proto.to_ascii_lowercase().as_str(), "tcp" | "udp") && cols.len() > 18 {
            let sp = cols[17].trim();
            let dp = cols[18].trim();
            if !sp.is_empty() { fields.insert("src_port".to_string(), sp.to_string()); }
            if !dp.is_empty() { fields.insert("dst_port".to_string(), dp.to_string()); }
        }
    }

    Some(Event {
        format:      Format::Filterlog,
        source_addr: source_addr.to_owned(),
        facility:    None,
        severity:    None,
        timestamp:   None,
        hostname:    None,
        app_name:    None,
        proc_id:     None,
        msg_id:      None,
        message:     String::new(),
        fields,
        raw:         raw.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // IPv4 UDP block (DHCP broadcast)
    const IPV4_UDP: &[u8] = b"66,,,1701174234,re1,match,block,in,4,0x0,,128,40625,0,none,17,udp,350,0.0.0.0,255.255.255.255,68,67,330";
    // IPv4 TCP pass (HTTPS connection)
    const IPV4_TCP: &[u8] = b"83,,,1781452463,re2.500,match,pass,in,4,0x0,,64,18990,0,DF,6,tcp,60,10.10.50.11,34.149.66.137,33264,443,0,S,2061524244,,64240,,mss;sackOK;TS;nop;wscale";
    // IPv4 IGMP block
    const IPV4_IGMP: &[u8] = b"63,,,1701188289,re1,ip-option,block,in,4,0xc0,,1,35832,0,none,2,igmp,36,192.168.178.1,224.0.0.1,datalength=12 ";
    // IPv6 ICMPv6 block
    const IPV6_ICMPV6: &[u8] = b"4,,,1000000003,re1,match,block,in,6,0x00,0x00000,255,ICMPv6,58,32,fe80::5e17:14f2:aa1b:5ed1,ff02::1,";
    // IPv6 UDP block
    const IPV6_UDP: &[u8] = b"4,,,1000000003,re1,match,block,in,6,0x00,0x1f8b0,1,UDP,17,41,fe80::5e17:14f2:aa1b:5ed1,ff02::1,54673,19133,41";

    fn get(ev: &Event, key: &str) -> Option<String> {
        ev.fields.get(key).cloned()
    }

    #[test]
    fn ipv4_udp_block() {
        let ev = parse(IPV4_UDP, "10.10.50.1").unwrap();
        assert_eq!(ev.format, Format::Filterlog);
        assert_eq!(get(&ev, "action").as_deref(),    Some("BLOCK"));
        assert_eq!(get(&ev, "direction").as_deref(), Some("in"));
        assert_eq!(get(&ev, "interface").as_deref(), Some("re1"));
        assert_eq!(get(&ev, "protocol").as_deref(),  Some("UDP"));
        assert_eq!(get(&ev, "src_ip").as_deref(),    Some("0.0.0.0"));
        assert_eq!(get(&ev, "dst_ip").as_deref(),    Some("255.255.255.255"));
        assert_eq!(get(&ev, "src_port").as_deref(),  Some("68"));
        assert_eq!(get(&ev, "dst_port").as_deref(),  Some("67"));
    }

    #[test]
    fn ipv4_tcp_pass() {
        let ev = parse(IPV4_TCP, "10.10.50.1").unwrap();
        assert_eq!(get(&ev, "action").as_deref(),   Some("ALLOW"));
        assert_eq!(get(&ev, "protocol").as_deref(), Some("TCP"));
        assert_eq!(get(&ev, "src_ip").as_deref(),   Some("10.10.50.11"));
        assert_eq!(get(&ev, "dst_ip").as_deref(),   Some("34.149.66.137"));
        assert_eq!(get(&ev, "src_port").as_deref(), Some("33264"));
        assert_eq!(get(&ev, "dst_port").as_deref(), Some("443"));
        assert_eq!(get(&ev, "interface").as_deref(), Some("re2.500"));
    }

    #[test]
    fn ipv4_igmp_no_ports() {
        let ev = parse(IPV4_IGMP, "10.10.50.1").unwrap();
        assert_eq!(get(&ev, "action").as_deref(),   Some("BLOCK"));
        assert_eq!(get(&ev, "protocol").as_deref(), Some("IGMP"));
        assert_eq!(get(&ev, "src_ip").as_deref(),   Some("192.168.178.1"));
        assert_eq!(get(&ev, "dst_ip").as_deref(),   Some("224.0.0.1"));
        assert!(get(&ev, "src_port").is_none());
        assert!(get(&ev, "dst_port").is_none());
    }

    #[test]
    fn ipv6_icmpv6_no_ports() {
        let ev = parse(IPV6_ICMPV6, "10.10.50.1").unwrap();
        assert_eq!(get(&ev, "action").as_deref(),   Some("BLOCK"));
        assert_eq!(get(&ev, "protocol").as_deref(), Some("ICMPV6"));
        assert_eq!(get(&ev, "src_ip").as_deref(),   Some("fe80::5e17:14f2:aa1b:5ed1"));
        assert_eq!(get(&ev, "dst_ip").as_deref(),   Some("ff02::1"));
        assert!(get(&ev, "src_port").is_none());
    }

    #[test]
    fn ipv6_udp_with_ports() {
        let ev = parse(IPV6_UDP, "10.10.50.1").unwrap();
        assert_eq!(get(&ev, "action").as_deref(),   Some("BLOCK"));
        assert_eq!(get(&ev, "protocol").as_deref(), Some("UDP"));
        assert_eq!(get(&ev, "src_ip").as_deref(),   Some("fe80::5e17:14f2:aa1b:5ed1"));
        assert_eq!(get(&ev, "dst_ip").as_deref(),   Some("ff02::1"));
        assert_eq!(get(&ev, "src_port").as_deref(), Some("54673"));
        assert_eq!(get(&ev, "dst_port").as_deref(), Some("19133"));
    }

    #[test]
    fn rejects_non_filterlog() {
        // Plain syslog message
        assert!(parse(b"Failed password for root from 1.2.3.4", "1.1.1.1").is_none());
        // Too few columns
        assert!(parse(b"a,b,c", "1.1.1.1").is_none());
    }
}
