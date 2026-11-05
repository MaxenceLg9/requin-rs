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
            result.protocol = if looks_http(&data[header_len..]) {
                "HTTP"
            } else if result.source_port == Some(53) || result.destination_port == Some(53) {
                "DNS"
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
            } else if result.source_port == Some(53) || result.destination_port == Some(53) {
                "DNS"
            } else {
                "UDP"
            };
        }
        17 => result.protocol = "Malformed",
        1 | 58 if data.len() >= 2 => {
            result.icmp_type = Some(data[0]);
            result.icmp_code = Some(data[1]);
            result.protocol = if protocol == 1 { "ICMP" } else { "ICMPv6" };
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
}
