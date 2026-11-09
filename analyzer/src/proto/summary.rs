use std::net::{Ipv4Addr, Ipv6Addr};

use super::wire::{ArpHeader, EthernetHeader, Ipv4Header, Ipv6Header, TcpHeader, UdpHeader, view};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Address {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    Ethernet([u8; 6]),
}

impl Address {
    pub fn format(self) -> String {
        match self {
            Self::Ipv4(bytes) => Ipv4Addr::from(bytes).to_string(),
            Self::Ipv6(bytes) => Ipv6Addr::from(bytes).to_string(),
            Self::Ethernet(bytes) => format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketSummary {
    pub source: Option<Address>,
    pub destination: Option<Address>,
    pub source_mac: Option<[u8; 6]>,
    pub destination_mac: Option<[u8; 6]>,
    pub protocol: &'static str,
    pub transport: Option<&'static str>,
    pub ip_ttl: Option<u8>,
    pub ipv6_hop_limit: Option<u8>,
    pub tcp_sequence: Option<u32>,
    pub tcp_acknowledgment: Option<u32>,
    pub tcp_flags: Option<u8>,
    pub tcp_window: Option<u16>,
    pub udp_length: Option<u16>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
}

impl PacketSummary {
    const fn new(protocol: &'static str) -> Self {
        Self {
            source: None,
            destination: None,
            source_mac: None,
            destination_mac: None,
            protocol,
            transport: None,
            ip_ttl: None,
            ipv6_hop_limit: None,
            tcp_sequence: None,
            tcp_acknowledgment: None,
            tcp_flags: None,
            tcp_window: None,
            udp_length: None,
            icmp_type: None,
            icmp_code: None,
            source_port: None,
            destination_port: None,
        }
    }
}

pub fn summarize_packet(packet: &[u8], link_type: u16) -> PacketSummary {
    let (ether_type, network_offset, ethernet) = if link_type == 1 {
        let Some(header) = view::<EthernetHeader>(packet) else {
            return PacketSummary::new("Malformed");
        };
        let mut ether_type = header.ether_type.get();
        let mut offset = 14;
        let mut vlan_count = 0;
        while matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) && vlan_count < 4 {
            if packet.len() < offset + 4 {
                return PacketSummary::new("Malformed");
            }
            ether_type = read_u16(packet, offset + 2).unwrap();
            offset += 4;
            vlan_count += 1;
        }
        (ether_type, offset, true)
    } else if link_type == 113 {
        let Some(protocol) = read_u16(packet, 14) else {
            return PacketSummary::new("Malformed");
        };
        (protocol, 16, true)
    } else if link_type == 276 {
        let Some(protocol) = read_u16(packet, 0) else {
            return PacketSummary::new("Malformed");
        };
        (protocol, 20, true)
    } else if matches!(link_type, 12 | 101) {
        match packet.first().map(|byte| byte >> 4) {
            Some(4) => (0x0800, 0, false),
            Some(6) => (0x86dd, 0, false),
            _ => return PacketSummary::new("Malformed"),
        }
    } else {
        return PacketSummary::new("Data");
    };

    let mut result = match ether_type {
        0x0800 => summarize_ipv4(packet, network_offset),
        0x86dd => summarize_ipv6(packet, network_offset),
        0x0806 if ethernet => summarize_arp(packet, network_offset),
        0x8847 | 0x8848 => summarize_mpls(packet, network_offset),
        0x8864 => summarize_pppoe(packet, network_offset),
        _ => PacketSummary::new(if ethernet { "Ethernet" } else { "Data" }),
    };
    if link_type == 1 && packet.len() >= 14 {
        result.destination_mac = Some(packet[..6].try_into().unwrap());
        result.source_mac = Some(packet[6..12].try_into().unwrap());
    }
    result
}

fn summarize_mpls(packet: &[u8], mut offset: usize) -> PacketSummary {
    for _ in 0..16 {
        let Some(label) = packet.get(offset..offset + 4) else {
            return PacketSummary::new("Malformed");
        };
        offset += 4;
        if label[2] & 1 != 0 {
            return match packet.get(offset).map(|byte| byte >> 4) {
                Some(4) => summarize_ipv4(packet, offset),
                Some(6) => summarize_ipv6(packet, offset),
                _ => PacketSummary::new("MPLS"),
            };
        }
    }
    PacketSummary::new("Malformed")
}

fn summarize_pppoe(packet: &[u8], offset: usize) -> PacketSummary {
    let Some(header) = packet.get(offset..offset + 8) else {
        return PacketSummary::new("Malformed");
    };
    if header[0] != 0x11 {
        return PacketSummary::new("Malformed");
    }
    match read_u16(header, 6) {
        Some(0x0021) => summarize_ipv4(packet, offset + 8),
        Some(0x0057) => summarize_ipv6(packet, offset + 8),
        _ => PacketSummary::new("PPPoE"),
    }
}

fn summarize_ipv4(packet: &[u8], offset: usize) -> PacketSummary {
    let Some(header) = packet.get(offset..) else {
        return PacketSummary::new("Malformed");
    };
    let Some(ip) = view::<Ipv4Header>(header) else {
        return PacketSummary::new("Malformed");
    };
    if ip.version_ihl >> 4 != 4 {
        return PacketSummary::new("Malformed");
    }
    let header_len = usize::from(ip.version_ihl & 0x0f) * 4;
    let total_len = usize::from(ip.total_len.get());
    if header_len < 20 || header.len() < header_len || total_len < header_len {
        return PacketSummary::new("Malformed");
    }
    let mut result = PacketSummary::new("IPv4");
    result.source = Some(Address::Ipv4(ip.source));
    result.destination = Some(Address::Ipv4(ip.destination));
    result.ip_ttl = Some(ip.ttl);
    let fragment = ip.flags_fragment_offset.get();
    if fragment & 0x1fff != 0 {
        return result;
    }
    let payload_end = offset.saturating_add(total_len).min(packet.len());
    summarize_transport(
        &mut result,
        ip.protocol,
        packet,
        offset + header_len,
        payload_end,
    );
    result
}

fn summarize_ipv6(packet: &[u8], offset: usize) -> PacketSummary {
    let Some(header) = packet.get(offset..) else {
        return PacketSummary::new("Malformed");
    };
    let Some(ip) = view::<Ipv6Header>(header) else {
        return PacketSummary::new("Malformed");
    };
    if ip.version_traffic_flow[0] >> 4 != 6 {
        return PacketSummary::new("Malformed");
    }
    let mut result = PacketSummary::new("IPv6");
    result.source = Some(Address::Ipv6(ip.source));
    result.destination = Some(Address::Ipv6(ip.destination));
    result.ipv6_hop_limit = Some(ip.hop_limit);
    let payload_end = (offset + 40)
        .saturating_add(usize::from(ip.payload_len.get()))
        .min(packet.len());
    let mut protocol = ip.next_header;
    let mut cursor = offset + 40;
    for _ in 0..8 {
        let Some(remaining) = packet.get(cursor..payload_end) else {
            return PacketSummary::new("Malformed");
        };
        match protocol {
            0 | 43 | 60 if remaining.len() >= 2 => {
                let extension_len = (usize::from(remaining[1]) + 1) * 8;
                if remaining.len() < extension_len {
                    return result;
                }
                protocol = remaining[0];
                cursor += extension_len;
            }
            44 if remaining.len() >= 8 => {
                let fragment = read_u16(remaining, 2).unwrap();
                if fragment & 0xfff8 != 0 {
                    return result;
                }
                protocol = remaining[0];
                cursor += 8;
            }
            51 if remaining.len() >= 2 => {
                let extension_len = (usize::from(remaining[1]) + 2) * 4;
                if remaining.len() < extension_len {
                    return result;
                }
                protocol = remaining[0];
                cursor += extension_len;
            }
            0 | 43 | 44 | 51 | 60 => return result,
            _ => break,
        }
    }
    summarize_transport(&mut result, protocol, packet, cursor, payload_end);
    result
}

fn summarize_transport(
    result: &mut PacketSummary,
    protocol: u8,
    packet: &[u8],
    offset: usize,
    end: usize,
) {
    let Some(data) = packet.get(offset..end) else {
        result.protocol = "Malformed";
        return;
    };
    match protocol {
        6 if data.len() >= 20 => {
            let Some(tcp) = view::<TcpHeader>(data) else {
                result.protocol = "Malformed";
                return;
            };
            let header_len = usize::from(tcp.data_offset_reserved >> 4) * 4;
            if header_len < 20 || data.len() < header_len {
                result.protocol = "Malformed";
                return;
            }
            result.source_port = Some(tcp.source_port.get());
            result.destination_port = Some(tcp.destination_port.get());
            result.transport = Some("TCP");
            result.tcp_sequence = Some(tcp.sequence.get());
            result.tcp_acknowledgment = Some(tcp.acknowledgment.get());
            result.tcp_flags = Some(tcp.flags);
            result.tcp_window = Some(tcp.window.get());
            let payload = &data[header_len..];
            result.protocol = if (result.source_port == Some(5060)
                || result.destination_port == Some(5060))
                && looks_sip(payload)
            {
                "SIP"
            } else if looks_http(payload) {
                "HTTP"
            } else if looks_tls(payload) {
                "TLS"
            } else if (result.source_port == Some(21) || result.destination_port == Some(21))
                && looks_ftp(payload)
            {
                "FTP"
            } else if result.source_port == Some(53) || result.destination_port == Some(53) {
                "DNS"
            } else if looks_ssh(payload)
                || result.source_port == Some(22)
                || result.destination_port == Some(22)
            {
                "SSH"
            } else if matches!(
                (result.source_port, result.destination_port),
                (Some(88 | 389 | 636), _) | (_, Some(88 | 389 | 636))
            ) && has_gssapi_oid(payload)
            {
                "GSSAPI"
            } else if result.source_port == Some(88) || result.destination_port == Some(88) {
                "Kerberos"
            } else if looks_smtp(payload)
                || matches!(
                    (result.source_port, result.destination_port),
                    (Some(25 | 587), _) | (_, Some(25 | 587))
                )
            {
                "SMTP"
            } else if looks_imap(payload)
                || result.source_port == Some(143)
                || result.destination_port == Some(143)
            {
                "IMAP"
            } else {
                "TCP"
            };
        }
        6 => result.protocol = "Malformed",
        17 if data.len() >= 8 => {
            let Some(udp) = view::<UdpHeader>(data) else {
                result.protocol = "Malformed";
                return;
            };
            let length = usize::from(udp.length.get());
            if length < 8 {
                result.protocol = "Malformed";
                return;
            }
            result.source_port = Some(udp.source_port.get());
            result.destination_port = Some(udp.destination_port.get());
            result.transport = Some("UDP");
            result.udp_length = Some(udp.length.get());
            let payload = &data[8..length.min(data.len())];
            result.protocol = if matches!(
                (result.source_port, result.destination_port),
                (Some(67 | 68), Some(67 | 68))
            ) && payload.get(236..240) == Some(&[99, 130, 83, 99])
            {
                "DHCP"
            } else if matches!(
                (result.source_port, result.destination_port),
                (Some(546 | 547), Some(546 | 547))
            ) && payload.first().is_some_and(|kind| (1..=13).contains(kind))
            {
                "DHCPv6"
            } else if (result.source_port == Some(69) || result.destination_port == Some(69))
                && looks_tftp(payload)
            {
                "TFTP"
            } else if (result.source_port == Some(123) || result.destination_port == Some(123))
                && payload.len() >= 48
            {
                "NTP"
            } else if (result.source_port == Some(5060) || result.destination_port == Some(5060))
                && looks_sip(payload)
            {
                "SIP"
            } else if (result.source_port == Some(4789) || result.destination_port == Some(4789))
                && payload.first().is_some_and(|flags| flags & 0x08 != 0)
            {
                "VXLAN"
            } else if matches!(
                (result.source_port, result.destination_port),
                (Some(88 | 389 | 636), _) | (_, Some(88 | 389 | 636))
            ) && has_gssapi_oid(payload)
            {
                "GSSAPI"
            } else if result.source_port == Some(88) || result.destination_port == Some(88) {
                "Kerberos"
            } else if matches!(
                (result.source_port, result.destination_port),
                (Some(500 | 4500), _) | (_, Some(500 | 4500))
            ) {
                "IPsec"
            } else if result.source_port == Some(53) || result.destination_port == Some(53) {
                "DNS"
            } else {
                "UDP"
            };
        }
        17 => result.protocol = "Malformed",
        47 => result.protocol = "GRE",
        50 | 51 => result.protocol = "IPsec",
        1 | 58 if data.len() >= 2 => {
            result.icmp_type = Some(data[0]);
            result.icmp_code = Some(data[1]);
            result.protocol = if protocol == 1 {
                "ICMP"
            } else if matches!(data[0], 133..=137) {
                "NDP"
            } else {
                "ICMPv6"
            };
        }
        1 => result.protocol = "ICMP",
        58 => result.protocol = "ICMPv6",
        _ => {}
    }
}

fn summarize_arp(packet: &[u8], offset: usize) -> PacketSummary {
    let Some(data) = packet.get(offset..) else {
        return PacketSummary::new("Malformed");
    };
    if data.len() < 8 {
        return PacketSummary::new("Malformed");
    }
    let Some(arp) = view::<ArpHeader>(data) else {
        return PacketSummary::new("Malformed");
    };
    let hardware_len = usize::from(arp.hardware_len);
    let protocol_len = usize::from(arp.protocol_len);
    let Some(address_len) = hardware_len.checked_add(protocol_len) else {
        return PacketSummary::new("Malformed");
    };
    let Some(required) = address_len
        .checked_mul(2)
        .and_then(|len| len.checked_add(8))
    else {
        return PacketSummary::new("Malformed");
    };
    if data.len() < required {
        return PacketSummary::new("Malformed");
    }
    let mut result = PacketSummary::new("ARP");
    if protocol_len == 4 {
        result.source = Some(Address::Ipv4(
            data[8 + hardware_len..8 + address_len].try_into().unwrap(),
        ));
        result.destination = Some(Address::Ipv4(
            data[8 + address_len + hardware_len..required]
                .try_into()
                .unwrap(),
        ));
    }
    result
}

fn looks_http(payload: &[u8]) -> bool {
    payload.starts_with(b"GET ")
        || payload.starts_with(b"POST ")
        || payload.starts_with(b"PUT ")
        || payload.starts_with(b"DELETE ")
        || payload.starts_with(b"HEAD ")
        || payload.starts_with(b"OPTIONS ")
        || payload.starts_with(b"PATCH ")
        || payload.starts_with(b"HTTP/")
}

fn looks_tls(payload: &[u8]) -> bool {
    payload.len() >= 5
        && matches!(payload[0], 20..=23)
        && matches!(
            u16::from_be_bytes([payload[1], payload[2]]),
            0x0301..=0x0304
        )
}

fn looks_ssh(payload: &[u8]) -> bool {
    payload.starts_with(b"SSH-")
}

fn looks_smtp(payload: &[u8]) -> bool {
    [
        b"220 ".as_slice(),
        b"250 ".as_slice(),
        b"250-".as_slice(),
        b"EHLO ".as_slice(),
        b"HELO ".as_slice(),
        b"MAIL FROM:".as_slice(),
        b"RCPT TO:".as_slice(),
        b"DATA\r\n".as_slice(),
        b"QUIT\r\n".as_slice(),
    ]
    .iter()
    .any(|prefix| payload.starts_with(prefix))
}

fn looks_imap(payload: &[u8]) -> bool {
    [
        b"* OK ".as_slice(),
        b"* PREAUTH ".as_slice(),
        b"A001 ".as_slice(),
        b"A002 ".as_slice(),
        b"CAPABILITY\r\n".as_slice(),
        b"LOGIN ".as_slice(),
        b"SELECT ".as_slice(),
        b"FETCH ".as_slice(),
        b"LIST ".as_slice(),
        b"NOOP\r\n".as_slice(),
    ]
    .iter()
    .any(|prefix| payload.starts_with(prefix))
}

fn looks_sip(payload: &[u8]) -> bool {
    let line = payload
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if let Some(status) = line.strip_prefix(b"SIP/2.0 ") {
        return status
            .get(..3)
            .is_some_and(|code| code.iter().all(u8::is_ascii_digit));
    }
    line.windows(b" SIP/2.0".len())
        .any(|window| window == b" SIP/2.0")
}

fn looks_ftp(payload: &[u8]) -> bool {
    let line = payload
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.len() >= 3 && line[..3].iter().all(u8::is_ascii_digit) {
        return line.len() == 3 || matches!(line[3], b' ' | b'-');
    }
    let command_length = line
        .iter()
        .position(u8::is_ascii_whitespace)
        .unwrap_or(line.len());
    command_length > 0 && line[..command_length].iter().all(u8::is_ascii_alphabetic)
}

fn looks_tftp(payload: &[u8]) -> bool {
    match payload
        .get(..2)
        .map(|opcode| u16::from_be_bytes([opcode[0], opcode[1]]))
    {
        Some(1 | 2) => payload.len() >= 4 && payload[2..].contains(&0),
        Some(3) => payload.len() >= 4,
        Some(4) => payload.len() == 4,
        Some(5) => payload.len() >= 5 && payload[4..].contains(&0),
        Some(6) => payload.len() >= 4 && payload[2..].contains(&0),
        _ => false,
    }
}

fn has_gssapi_oid(payload: &[u8]) -> bool {
    const KERBEROS_MECHANISM_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
    payload
        .windows(KERBEROS_MECHANISM_OID.len())
        .any(|window| window == KERBEROS_MECHANISM_OID)
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_ipv4_tcp_without_allocating_or_building_layers() {
        let mut packet = [0; 14 + 20 + 20];
        packet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        packet[14] = 0x45;
        packet[16..18].copy_from_slice(&40_u16.to_be_bytes());
        packet[23] = 6;
        packet[26..30].copy_from_slice(&[192, 0, 2, 1]);
        packet[30..34].copy_from_slice(&[198, 51, 100, 2]);
        packet[34..36].copy_from_slice(&12345_u16.to_be_bytes());
        packet[36..38].copy_from_slice(&443_u16.to_be_bytes());
        packet[46] = 0x50;

        assert_eq!(
            summarize_packet(&packet, 1),
            PacketSummary {
                source: Some(Address::Ipv4([192, 0, 2, 1])),
                destination: Some(Address::Ipv4([198, 51, 100, 2])),
                source_mac: Some([0; 6]),
                destination_mac: Some([0; 6]),
                protocol: "TCP",
                transport: Some("TCP"),
                ip_ttl: Some(0),
                ipv6_hop_limit: None,
                tcp_sequence: Some(0),
                tcp_acknowledgment: Some(0),
                tcp_flags: Some(0),
                tcp_window: Some(0),
                udp_length: None,
                icmp_type: None,
                icmp_code: None,
                source_port: Some(12345),
                destination_port: Some(443),
            }
        );
    }

    #[test]
    fn identifies_http_from_payload_not_port_number() {
        let mut packet = [0; 14 + 20 + 20 + 4];
        packet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        packet[14] = 0x45;
        packet[16..18].copy_from_slice(&44_u16.to_be_bytes());
        packet[23] = 6;
        packet[46] = 0x50;
        packet[54..].copy_from_slice(b"GET ");
        assert_eq!(summarize_packet(&packet, 1).protocol, "HTTP");
    }

    #[test]
    fn summarizes_ipv4_over_linux_cooked_capture_and_mpls() {
        let mut ip = [0; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&20_u16.to_be_bytes());
        ip[9] = 1;
        ip[12..16].copy_from_slice(&[192, 0, 2, 1]);
        ip[16..20].copy_from_slice(&[198, 51, 100, 2]);

        let mut cooked = vec![0; 16];
        cooked[14..16].copy_from_slice(&0x0800_u16.to_be_bytes());
        cooked.extend_from_slice(&ip);
        assert_eq!(summarize_packet(&cooked, 113).protocol, "ICMP");

        let mut mpls = vec![0; 14];
        mpls[12..14].copy_from_slice(&0x8847_u16.to_be_bytes());
        mpls.extend_from_slice(&0x0000_0140_u32.to_be_bytes());
        mpls.extend_from_slice(&ip);
        assert_eq!(summarize_packet(&mpls, 1).protocol, "ICMP");
    }

    fn ipv4_packet(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0; 14 + 20 + payload.len()];
        packet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        packet[14] = 0x45;
        packet[16..18].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        packet[23] = protocol;
        packet[34..].copy_from_slice(payload);
        packet
    }

    #[test]
    fn identifies_new_application_protocols_from_headers_and_signatures() {
        let mut tcp = vec![0; 20];
        tcp[0..2].copy_from_slice(&50_000_u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&22_u16.to_be_bytes());
        tcp[12] = 0x50;
        tcp.extend_from_slice(b"SSH-2.0-OpenSSH_9.0\r\n");
        assert_eq!(summarize_packet(&ipv4_packet(6, &tcp), 1).protocol, "SSH");

        let mut udp = vec![0; 8];
        udp[0..2].copy_from_slice(&546_u16.to_be_bytes());
        udp[2..4].copy_from_slice(&547_u16.to_be_bytes());
        udp[4..6].copy_from_slice(&12_u16.to_be_bytes());
        udp.extend_from_slice(&[1, 0, 0, 1]);
        assert_eq!(
            summarize_packet(&ipv4_packet(17, &udp), 1).protocol,
            "DHCPv6"
        );
    }

    #[test]
    fn identifies_ntp_tftp_sip_and_ftp_in_packet_summaries() {
        let mut ntp = vec![0; 8 + 48];
        ntp[0..2].copy_from_slice(&40_000_u16.to_be_bytes());
        ntp[2..4].copy_from_slice(&123_u16.to_be_bytes());
        let ntp_length = ntp.len() as u16;
        ntp[4..6].copy_from_slice(&ntp_length.to_be_bytes());
        ntp[8] = 0x23;
        assert_eq!(summarize_packet(&ipv4_packet(17, &ntp), 1).protocol, "NTP");

        let tftp_payload = b"\0\x01file.txt\0octet\0";
        let mut tftp = vec![0; 8];
        tftp[0..2].copy_from_slice(&40_000_u16.to_be_bytes());
        tftp[2..4].copy_from_slice(&69_u16.to_be_bytes());
        tftp[4..6].copy_from_slice(&((8 + tftp_payload.len()) as u16).to_be_bytes());
        tftp.extend_from_slice(tftp_payload);
        assert_eq!(
            summarize_packet(&ipv4_packet(17, &tftp), 1).protocol,
            "TFTP"
        );

        let mut sip = vec![0; 20];
        sip[0..2].copy_from_slice(&40_000_u16.to_be_bytes());
        sip[2..4].copy_from_slice(&5060_u16.to_be_bytes());
        sip[12] = 0x50;
        sip.extend_from_slice(b"OPTIONS sip:a@example.test SIP/2.0\r\n");
        assert_eq!(summarize_packet(&ipv4_packet(6, &sip), 1).protocol, "SIP");

        let mut ftp = vec![0; 20];
        ftp[0..2].copy_from_slice(&40_000_u16.to_be_bytes());
        ftp[2..4].copy_from_slice(&21_u16.to_be_bytes());
        ftp[12] = 0x50;
        ftp.extend_from_slice(b"RETR file.txt\r\n");
        assert_eq!(summarize_packet(&ipv4_packet(6, &ftp), 1).protocol, "FTP");
    }

    #[test]
    fn identifies_vxlan_gre_ipsec_and_neighbor_discovery() {
        let mut vxlan = vec![0; 16];
        vxlan[0..2].copy_from_slice(&50000_u16.to_be_bytes());
        vxlan[2..4].copy_from_slice(&4789_u16.to_be_bytes());
        vxlan[4..6].copy_from_slice(&16_u16.to_be_bytes());
        vxlan[8] = 0x08;
        assert_eq!(
            summarize_packet(&ipv4_packet(17, &vxlan), 1).protocol,
            "VXLAN"
        );

        assert_eq!(
            summarize_packet(&ipv4_packet(47, &[0, 0, 8, 0]), 1).protocol,
            "GRE"
        );
        assert_eq!(
            summarize_packet(&ipv4_packet(50, &[0; 8]), 1).protocol,
            "IPsec"
        );

        let mut ipv6 = vec![0; 14 + 40 + 4];
        ipv6[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        ipv6[14] = 0x60;
        ipv6[18..20].copy_from_slice(&4_u16.to_be_bytes());
        ipv6[20] = 58;
        ipv6[54] = 135;
        assert_eq!(summarize_packet(&ipv6, 1).protocol, "NDP");
    }
}
