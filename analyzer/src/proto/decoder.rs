use libloading::Library;
use std::{
    borrow::Cow,
    net::{Ipv4Addr, Ipv6Addr},
};

use crate::parser::{
    frame::Frame,
    layer::{Field, Layer},
};

use super::wire::{ArpHeader, EthernetHeader, Ipv4Header, Ipv6Header, TcpHeader, UdpHeader, view};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportInfo {
    pub protocol: u8,
    pub source_port: u16,
    pub destination_port: u16,
}

pub trait ApplicationDecoder: Send + Sync {
    fn decode(&self, payload: &[u8], transport: TransportInfo, offset: usize) -> Option<Layer>;
}

pub struct DecoderRegistry {
    pub(super) application_decoders: Vec<Box<dyn ApplicationDecoder>>,
    pub(super) plugin_libraries: Vec<Library>,
    pub(super) plugin_names: Vec<String>,
}

impl DecoderRegistry {
    pub fn new() -> Self {
        Self {
            application_decoders: vec![
                Box::new(DnsDecoder),
                Box::new(DhcpDecoder),
                Box::new(HttpDecoder),
                Box::new(TlsDecoder),
            ],
            plugin_libraries: Vec::new(),
            plugin_names: Vec::new(),
        }
    }

    pub fn loaded_plugin_count(&self) -> usize {
        self.plugin_libraries.len()
    }

    pub fn register(&mut self, decoder: impl ApplicationDecoder + 'static) {
        self.application_decoders.push(Box::new(decoder));
    }

    fn decode_application(
        &self,
        payload: &[u8],
        transport: TransportInfo,
        offset: usize,
    ) -> Option<Layer> {
        self.application_decoders
            .iter()
            .find_map(|decoder| decoder.decode(payload, transport, offset))
    }
}

impl Default for DecoderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

struct DnsDecoder;
struct DhcpDecoder;
struct HttpDecoder;
struct TlsDecoder;

impl ApplicationDecoder for DnsDecoder {
    fn decode(&self, payload: &[u8], transport: TransportInfo, offset: usize) -> Option<Layer> {
        if transport.source_port != 53 && transport.destination_port != 53 {
            return None;
        }
        let (dns, dns_offset) = if transport.protocol == 6 {
            let length = usize::from(u16::from_be_bytes(payload.get(..2)?.try_into().ok()?));
            (payload.get(2..2 + length)?, offset + 2)
        } else {
            (payload, offset)
        };
        if dns.len() < 12 {
            return None;
        }
        let flags = be_u16(dns, 2)?;
        let questions = be_u16(dns, 4)?;
        let answers = be_u16(dns, 6)?;
        let mut layer = Layer::with_capacity("DNS", 14);
        push(&mut layer, "Transaction ID", be_u16(dns, 0)?, dns_offset, 2);
        push(
            &mut layer,
            "Response",
            flags & 0x8000 != 0,
            dns_offset + 2,
            2,
        );
        push(
            &mut layer,
            "Opcode",
            (flags >> 11) & 0x0f,
            dns_offset + 2,
            2,
        );
        push(
            &mut layer,
            "Authoritative",
            flags & 0x0400 != 0,
            dns_offset + 2,
            2,
        );
        push(
            &mut layer,
            "Truncated",
            flags & 0x0200 != 0,
            dns_offset + 2,
            2,
        );
        push(
            &mut layer,
            "Recursion desired",
            flags & 0x0100 != 0,
            dns_offset + 2,
            2,
        );
        push(
            &mut layer,
            "Recursion available",
            flags & 0x0080 != 0,
            dns_offset + 2,
            2,
        );
        push(
            &mut layer,
            "Response code",
            flags & 0x000f,
            dns_offset + 2,
            2,
        );
        push(&mut layer, "Questions", questions, dns_offset + 4, 2);
        push(&mut layer, "Answers", answers, dns_offset + 6, 2);
        push(
            &mut layer,
            "Authority records",
            be_u16(dns, 8)?,
            dns_offset + 8,
            2,
        );
        push(
            &mut layer,
            "Additional records",
            be_u16(dns, 10)?,
            dns_offset + 10,
            2,
        );
        if questions > 0
            && let Some((name, consumed)) = dns_name(dns, 12)
        {
            layer
                .fields
                .push(Field::new("Query name", name).at(dns_offset + 12, consumed));
            if let Some(kind) = be_u16(dns, 12 + consumed) {
                layer.fields.push(
                    Field::new("Query type", dns_record_type(kind))
                        .at(dns_offset + 12 + consumed, 2),
                );
            }
            if let Some(class) = be_u16(dns, 14 + consumed) {
                push(
                    &mut layer,
                    "Query class",
                    class,
                    dns_offset + 14 + consumed,
                    2,
                );
            }
        }
        Some(layer)
    }
}

impl ApplicationDecoder for HttpDecoder {
    fn decode(&self, payload: &[u8], transport: TransportInfo, offset: usize) -> Option<Layer> {
        if transport.protocol != 6 || payload.is_empty() {
            return None;
        }
        let is_http = payload.starts_with(b"GET ")
            || payload.starts_with(b"POST ")
            || payload.starts_with(b"PUT ")
            || payload.starts_with(b"DELETE ")
            || payload.starts_with(b"HEAD ")
            || payload.starts_with(b"OPTIONS ")
            || payload.starts_with(b"PATCH ")
            || payload.starts_with(b"HTTP/");
        if !is_http {
            return None;
        }
        let first_line_end = payload
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or(payload.len());
        let first_line = &payload[..first_line_end.min(256)];
        let text = String::from_utf8_lossy(first_line)
            .trim_end_matches(['\r', '\n'])
            .to_string();
        let mut layer = Layer::new("HTTP");
        layer
            .fields
            .push(Field::new("Start line", text.clone()).at(offset, first_line.len()));
        Some(layer)
    }
}

impl ApplicationDecoder for DhcpDecoder {
    fn decode(&self, payload: &[u8], transport: TransportInfo, offset: usize) -> Option<Layer> {
        if transport.protocol != 17
            || !matches!(
                (transport.source_port, transport.destination_port),
                (67 | 68, 67 | 68)
            )
            || payload.len() < 240
            || payload.get(236..240)? != [99, 130, 83, 99]
        {
            return None;
        }
        let mut layer = Layer::with_capacity("Dynamic Host Configuration Protocol", 8);
        push(&mut layer, "Operation", payload[0], offset, 1);
        push(&mut layer, "Hardware type", payload[1], offset + 1, 1);
        push(
            &mut layer,
            "Hardware address length",
            payload[2],
            offset + 2,
            1,
        );
        push(
            &mut layer,
            "Transaction ID",
            be_u32(payload, 4)?,
            offset + 4,
            4,
        );
        layer
            .fields
            .push(Field::new("Client address", address_text(&payload[12..16])).at(offset + 12, 4));
        layer
            .fields
            .push(Field::new("Your address", address_text(&payload[16..20])).at(offset + 16, 4));
        let mut cursor = 240;
        while let Some(option) = payload.get(cursor).copied() {
            cursor += 1;
            match option {
                0 => continue,
                255 => break,
                _ => {}
            }
            let length = usize::from(*payload.get(cursor)?);
            cursor += 1;
            let value = payload.get(cursor..cursor.checked_add(length)?)?;
            match option {
                12 => layer.fields.push(
                    Field::new("Host name", String::from_utf8_lossy(value).into_owned())
                        .at(offset + cursor, length),
                ),
                50 | 54 if length == 4 => layer.fields.push(
                    Field::new(
                        if option == 50 {
                            "Requested IP address"
                        } else {
                            "Server identifier"
                        },
                        address_text(value),
                    )
                    .at(offset + cursor, length),
                ),
                53 if length == 1 => layer.fields.push(
                    Field::new("Message type", dhcp_message_type(value[0])).at(offset + cursor, 1),
                ),
                _ => {}
            }
            cursor += length;
        }
        Some(layer)
    }
}

impl ApplicationDecoder for TlsDecoder {
    fn decode(&self, payload: &[u8], transport: TransportInfo, offset: usize) -> Option<Layer> {
        if transport.protocol != 6 || payload.len() < 5 {
            return None;
        }
        let content_type = payload[0];
        let version = be_u16(payload, 1)?;
        let record_length = usize::from(be_u16(payload, 3)?);
        if !matches!(content_type, 20..=23)
            || !matches!(version, 0x0301..=0x0304)
            || record_length == 0
        {
            return None;
        }
        let mut layer = Layer::with_capacity("Transport Layer Security", 5);
        push(
            &mut layer,
            "Content type",
            tls_content_type(content_type),
            offset,
            1,
        );
        push(
            &mut layer,
            "Legacy record version",
            format!("0x{version:04x}"),
            offset + 1,
            2,
        );
        push(
            &mut layer,
            "Record length",
            record_length as u64,
            offset + 3,
            2,
        );
        if content_type == 22
            && payload.len() >= 9
            && let Some(message_length) = be_u24(payload, 6)
            && message_length > 0
        {
            push(
                &mut layer,
                "Handshake type",
                tls_handshake_type(payload[5]),
                offset + 5,
                1,
            );
            push(
                &mut layer,
                "Handshake length",
                message_length,
                offset + 6,
                3,
            );
        }
        Some(layer)
    }
}

pub fn decode_frame(frame: &mut Frame, link_type: u16, registry: &DecoderRegistry) {
    match link_type {
        1 => decode_ethernet(frame, registry),
        113 => decode_linux_cooked(frame, registry, false),
        276 => decode_linux_cooked(frame, registry, true),
        12 | 101 => decode_raw_ip(frame, registry),
        _ => {
            frame.protocol = Cow::Borrowed("Data");
            frame.info = format!("{} bytes", frame.captured_len);
        }
    }
}

fn decode_raw_ip(frame: &mut Frame, registry: &DecoderRegistry) {
    match frame.raw_data.first().map(|byte| byte >> 4) {
        Some(4) => decode_ipv4(frame, 0, registry),
        Some(6) => decode_ipv6(frame, 0, registry),
        _ => malformed(frame, "Unknown raw IP packet version"),
    }
}

fn decode_ethernet(frame: &mut Frame, registry: &DecoderRegistry) {
    let data = &frame.raw_data;
    let Some(ethernet) = view::<EthernetHeader>(data) else {
        frame.protocol = Cow::Borrowed("Malformed");
        frame.info = "Truncated Ethernet header".to_owned();
        return;
    };
    let mut layer = Layer::with_capacity("Ethernet II", 3);
    layer
        .fields
        .push(Field::new("Destination", ethernet.destination).at(0, 6));
    layer
        .fields
        .push(Field::new("Source", ethernet.source).at(6, 6));
    let mut ether_type = ethernet.ether_type.get();
    layer
        .fields
        .push(Field::hex("Type", u64::from(ether_type)).at(12, 2));
    let mut offset = 14;
    let mut vlan_count = 0;
    while matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) && vlan_count < 4 {
        if data.len() < offset + 4 {
            frame.layers.push(layer);
            frame.protocol = Cow::Borrowed("Malformed");
            frame.info = "Truncated VLAN header".to_owned();
            return;
        }
        let tci = be_u16(data, offset).unwrap();
        push(&mut layer, "VLAN ID", tci & 0x0fff, offset, 2);
        push(&mut layer, "VLAN priority", tci >> 13, offset, 2);
        ether_type = be_u16(data, offset + 2).unwrap();
        offset += 4;
        vlan_count += 1;
    }
    frame.layers.push(layer);
    decode_link_protocol(frame, ether_type, offset, registry);
}

fn decode_link_protocol(
    frame: &mut Frame,
    protocol: u16,
    offset: usize,
    registry: &DecoderRegistry,
) {
    if protocol <= 1500 {
        if offset == frame.raw_data.len() {
            frame.protocol = Cow::Borrowed("Ethernet");
            frame.info = format!("IEEE 802.3 length {protocol}");
            return;
        }
        return decode_llc(frame, offset, registry);
    }
    match protocol {
        0x0800 => decode_ipv4(frame, offset, registry),
        0x86dd => decode_ipv6(frame, offset, registry),
        0x0806 => decode_arp(frame, offset),
        0x8847 | 0x8848 => decode_mpls(frame, offset, registry),
        0x8864 => decode_pppoe(frame, offset, registry),
        _ => {
            frame.protocol = Cow::Borrowed("Ethernet");
            frame.info = format!("EtherType 0x{protocol:04x}");
        }
    }
}

fn decode_linux_cooked(frame: &mut Frame, registry: &DecoderRegistry, version_two: bool) {
    let data = &frame.raw_data;
    let (header_len, protocol) = if version_two {
        if data.len() < 20 {
            return malformed(frame, "Truncated Linux cooked capture v2 header");
        }
        let mut layer = Layer::with_capacity("Linux cooked capture v2", 6);
        layer
            .fields
            .push(Field::hex("Protocol", u64::from(be_u16(data, 0).unwrap())).at(0, 2));
        push(
            &mut layer,
            "Interface index",
            be_u32(data, 4).unwrap(),
            4,
            4,
        );
        push(&mut layer, "Hardware type", be_u16(data, 8).unwrap(), 8, 2);
        push(&mut layer, "Packet type", data[10], 10, 1);
        push(&mut layer, "Address length", data[11], 11, 1);
        layer
            .fields
            .push(Field::new("Address", mac(&data[12..20])).at(12, 8));
        let protocol = be_u16(data, 0).unwrap();
        frame.layers.push(layer);
        (20, protocol)
    } else {
        if data.len() < 16 {
            return malformed(frame, "Truncated Linux cooked capture header");
        }
        let mut layer = Layer::with_capacity("Linux cooked capture", 5);
        push(&mut layer, "Packet type", be_u16(data, 0).unwrap(), 0, 2);
        push(&mut layer, "Hardware type", be_u16(data, 2).unwrap(), 2, 2);
        let address_len = usize::from(be_u16(data, 4).unwrap()).min(8);
        push(&mut layer, "Address length", address_len as u64, 4, 2);
        layer
            .fields
            .push(Field::new("Address", mac(&data[6..6 + address_len])).at(6, address_len));
        let protocol = be_u16(data, 14).unwrap();
        layer
            .fields
            .push(Field::hex("Protocol", u64::from(protocol)).at(14, 2));
        frame.layers.push(layer);
        (16, protocol)
    };
    decode_link_protocol(frame, protocol, header_len, registry);
}

fn decode_llc(frame: &mut Frame, offset: usize, registry: &DecoderRegistry) {
    let Some(header) = frame.raw_data.get(offset..offset + 3) else {
        return malformed(frame, "Truncated IEEE 802.2 LLC header");
    };
    let mut layer = Layer::with_capacity("IEEE 802.2 Logical-Link Control", 4);
    push(
        &mut layer,
        "Destination service access point",
        header[0],
        offset,
        1,
    );
    push(
        &mut layer,
        "Source service access point",
        header[1],
        offset + 1,
        1,
    );
    push(&mut layer, "Control", header[2], offset + 2, 1);
    if header[..3] == [0xaa, 0xaa, 0x03] {
        let Some(snap) = frame.raw_data.get(offset + 3..offset + 8) else {
            return malformed(frame, "Truncated SNAP header");
        };
        layer.fields.push(
            Field::new(
                "Organization code",
                format!("{:02x}:{:02x}:{:02x}", snap[0], snap[1], snap[2]),
            )
            .at(offset + 3, 3),
        );
        let protocol = be_u16(snap, 3).unwrap();
        layer
            .fields
            .push(Field::hex("Protocol", u64::from(protocol)).at(offset + 6, 2));
        frame.layers.push(layer);
        decode_link_protocol(frame, protocol, offset + 8, registry);
    } else {
        frame.layers.push(layer);
        frame.protocol = Cow::Borrowed("LLC");
        frame.info = "IEEE 802.2 frame".to_owned();
    }
}

fn decode_mpls(frame: &mut Frame, offset: usize, registry: &DecoderRegistry) {
    let mut cursor = offset;
    let mut labels = Layer::with_capacity("Multiprotocol Label Switching", 8);
    for _ in 0..16 {
        let Some(label) = frame.raw_data.get(cursor..cursor + 4) else {
            return malformed(frame, "Truncated MPLS label stack");
        };
        let word = be_u32(label, 0).unwrap();
        push(&mut labels, "Label", word >> 12, cursor, 3);
        push(&mut labels, "Traffic class", (word >> 9) & 7, cursor + 2, 1);
        push(
            &mut labels,
            "Bottom of stack",
            word & 0x100 != 0,
            cursor + 2,
            1,
        );
        push(&mut labels, "TTL", word & 0xff, cursor + 3, 1);
        cursor += 4;
        if word & 0x100 != 0 {
            frame.layers.push(labels);
            return match frame.raw_data.get(cursor).map(|byte| byte >> 4) {
                Some(4) => decode_ipv4(frame, cursor, registry),
                Some(6) => decode_ipv6(frame, cursor, registry),
                _ => {
                    frame.protocol = Cow::Borrowed("MPLS");
                    frame.info = "Unknown MPLS payload".to_owned();
                }
            };
        }
    }
    malformed(frame, "MPLS label stack exceeds supported depth");
}

fn decode_pppoe(frame: &mut Frame, offset: usize, registry: &DecoderRegistry) {
    let Some(header) = frame.raw_data.get(offset..offset + 8) else {
        return malformed(frame, "Truncated PPPoE session header");
    };
    let version_type = header[0];
    if version_type >> 4 != 1 || version_type & 0x0f != 1 {
        return malformed(frame, "Invalid PPPoE version or type");
    }
    let length = usize::from(be_u16(header, 4).unwrap());
    if length < 2 || offset + 6 + length > frame.raw_data.len() {
        return malformed(frame, "Invalid PPPoE payload length");
    }
    let protocol = be_u16(header, 6).unwrap();
    let mut layer = Layer::with_capacity("Point-to-Point Protocol over Ethernet", 4);
    push(&mut layer, "Version", version_type >> 4, offset, 1);
    push(&mut layer, "Type", version_type & 0x0f, offset, 1);
    push(&mut layer, "Code", header[1], offset + 1, 1);
    push(
        &mut layer,
        "Session ID",
        be_u16(header, 2).unwrap(),
        offset + 2,
        2,
    );
    push(&mut layer, "Payload length", length as u64, offset + 4, 2);
    frame.layers.push(layer);
    match protocol {
        0x0021 => decode_ipv4(frame, offset + 8, registry),
        0x0057 => decode_ipv6(frame, offset + 8, registry),
        _ => {
            frame.protocol = Cow::Borrowed("PPPoE");
            frame.info = format!("PPP protocol 0x{protocol:04x}");
        }
    }
}

fn decode_arp(frame: &mut Frame, offset: usize) {
    let Some(data) = frame.raw_data.get(offset..) else {
        return malformed(frame, "Truncated ARP header");
    };
    let Some(arp) = view::<ArpHeader>(data) else {
        return malformed(frame, "Truncated ARP header");
    };
    let hardware_len = usize::from(arp.hardware_len);
    let protocol_len = usize::from(arp.protocol_len);
    let address_len = hardware_len + protocol_len;
    let Some(required) = address_len
        .checked_mul(2)
        .and_then(|len| len.checked_add(8))
    else {
        return malformed(frame, "Invalid ARP address lengths");
    };
    if data.len() < required {
        return malformed(frame, "Truncated ARP addresses");
    }
    let operation = arp.operation.get();
    let mut layer = Layer::with_capacity("Address Resolution Protocol", 9);
    push(
        &mut layer,
        "Hardware type",
        arp.hardware_type.get(),
        offset,
        2,
    );
    layer
        .fields
        .push(Field::hex("Protocol type", u64::from(arp.protocol_type.get())).at(offset + 2, 2));
    push(
        &mut layer,
        "Hardware address length",
        arp.hardware_len,
        offset + 4,
        1,
    );
    push(
        &mut layer,
        "Protocol address length",
        arp.protocol_len,
        offset + 5,
        1,
    );
    push(&mut layer, "Operation", operation, offset + 6, 2);
    let sender_hardware = &data[8..8 + hardware_len];
    let sender_protocol = &data[8 + hardware_len..8 + address_len];
    let target_hardware = &data[8 + address_len..8 + address_len + hardware_len];
    let target_protocol = &data[8 + address_len + hardware_len..required];
    layer.fields.push(
        Field::new("Sender hardware address", address_text(sender_hardware))
            .at(offset + 8, hardware_len),
    );
    layer.fields.push(
        Field::new("Sender protocol address", address_text(sender_protocol))
            .at(offset + 8 + hardware_len, protocol_len),
    );
    layer.fields.push(
        Field::new("Target hardware address", address_text(target_hardware))
            .at(offset + 8 + address_len, hardware_len),
    );
    layer.fields.push(
        Field::new("Target protocol address", address_text(target_protocol))
            .at(offset + 8 + address_len + hardware_len, protocol_len),
    );
    frame.protocol = Cow::Borrowed("ARP");
    frame.info = if operation == 1 {
        "Who has?".to_owned()
    } else if operation == 2 {
        "Is at".to_owned()
    } else {
        format!("Operation {operation}")
    };
    frame.layers.push(layer);
}

fn decode_ipv4(frame: &mut Frame, offset: usize, registry: &DecoderRegistry) {
    let Some(data) = frame.raw_data.get(offset..) else {
        return malformed(frame, "Truncated IPv4 header");
    };
    let Some(ip) = view::<Ipv4Header>(data) else {
        return malformed(frame, "Invalid or truncated IPv4 header");
    };
    if ip.version_ihl >> 4 != 4 {
        return malformed(frame, "Invalid or truncated IPv4 header");
    }
    let header_len = usize::from(ip.version_ihl & 0x0f) * 4;
    let total_len = usize::from(ip.total_len.get());
    if header_len < 20 || data.len() < header_len || total_len < header_len {
        return malformed(frame, "Invalid IPv4 header length");
    }
    let source = Ipv4Addr::from(ip.source).to_string();
    let destination = Ipv4Addr::from(ip.destination).to_string();
    let flags_offset = ip.flags_fragment_offset.get();
    let mut layer = Layer::with_capacity("Internet Protocol Version 4", 14);
    push(&mut layer, "Version", ip.version_ihl >> 4, offset, 1);
    push(&mut layer, "Header length", header_len as u64, offset, 1);
    push(
        &mut layer,
        "Differentiated services",
        ip.differentiated_services,
        offset + 1,
        1,
    );
    push(&mut layer, "Total length", total_len as u64, offset + 2, 2);
    push(
        &mut layer,
        "Identification",
        ip.identification.get(),
        offset + 4,
        2,
    );
    push(
        &mut layer,
        "Don't fragment",
        flags_offset & 0x4000 != 0,
        offset + 6,
        2,
    );
    push(
        &mut layer,
        "More fragments",
        flags_offset & 0x2000 != 0,
        offset + 6,
        2,
    );
    push(
        &mut layer,
        "Fragment offset",
        flags_offset & 0x1fff,
        offset + 6,
        2,
    );
    push(&mut layer, "TTL", ip.ttl, offset + 8, 1);
    push(&mut layer, "Protocol", ip.protocol, offset + 9, 1);
    push(
        &mut layer,
        "Header checksum",
        ip.checksum.get(),
        offset + 10,
        2,
    );
    layer
        .fields
        .push(Field::new("Source", ip.source).at(offset + 12, 4));
    layer
        .fields
        .push(Field::new("Destination", ip.destination).at(offset + 16, 4));
    frame.source = Some(source);
    frame.destination = Some(destination);
    frame.protocol = Cow::Borrowed("IPv4");
    frame.layers.push(layer);
    let end = offset.saturating_add(total_len).min(frame.raw_data.len());
    if flags_offset & 0x1fff != 0 || offset + header_len > end {
        frame.protocol = Cow::Borrowed("IPv4");
        frame.info = "Fragmented IPv4 packet".to_owned();
        return;
    }
    decode_transport(frame, ip.protocol, offset + header_len, end, registry);
}

fn decode_ipv6(frame: &mut Frame, offset: usize, registry: &DecoderRegistry) {
    let Some(data) = frame.raw_data.get(offset..) else {
        return malformed(frame, "Truncated IPv6 header");
    };
    let Some(ip) = view::<Ipv6Header>(data) else {
        return malformed(frame, "Invalid or truncated IPv6 header");
    };
    if ip.version_traffic_flow[0] >> 4 != 6 {
        return malformed(frame, "Invalid or truncated IPv6 header");
    }
    let payload_len = usize::from(ip.payload_len.get());
    let mut next_header = ip.next_header;
    let source = Ipv6Addr::from(ip.source).to_string();
    let destination = Ipv6Addr::from(ip.destination).to_string();
    let mut layer = Layer::with_capacity("Internet Protocol Version 6", 9);
    push(&mut layer, "Version", 6_u8, offset, 1);
    push(
        &mut layer,
        "Traffic class",
        ((ip.version_traffic_flow[0] & 0x0f) << 4) | (ip.version_traffic_flow[1] >> 4),
        offset,
        2,
    );
    push(
        &mut layer,
        "Flow label",
        (u32::from(ip.version_traffic_flow[1] & 0x0f) << 16)
            | (u32::from(ip.version_traffic_flow[2]) << 8)
            | u32::from(ip.version_traffic_flow[3]),
        offset + 1,
        3,
    );
    push(
        &mut layer,
        "Payload length",
        payload_len as u64,
        offset + 4,
        2,
    );
    push(&mut layer, "Next header", next_header, offset + 6, 1);
    push(&mut layer, "Hop limit", ip.hop_limit, offset + 7, 1);
    layer
        .fields
        .push(Field::new("Source", ip.source).at(offset + 8, 16));
    layer
        .fields
        .push(Field::new("Destination", ip.destination).at(offset + 24, 16));
    frame.source = Some(source);
    frame.destination = Some(destination);
    frame.protocol = Cow::Borrowed("IPv6");
    frame.layers.push(layer);

    let mut cursor = offset + 40;
    let end = cursor.saturating_add(payload_len).min(frame.raw_data.len());
    for _ in 0..8 {
        match next_header {
            0 | 43 | 60 => {
                let Some(extension) = frame.raw_data.get(cursor..cursor + 2) else {
                    return malformed(frame, "Truncated IPv6 extension header");
                };
                let length = (usize::from(extension[1]) + 1) * 8;
                let Some(full) = frame.raw_data.get(cursor..cursor + length) else {
                    return malformed(frame, "Truncated IPv6 extension header");
                };
                if cursor + length > end {
                    return malformed(frame, "IPv6 extension exceeds payload length");
                }
                let mut ext = Layer::new(match next_header {
                    0 => "IPv6 Hop-by-Hop Options",
                    43 => "IPv6 Routing",
                    _ => "IPv6 Destination Options",
                });
                push(&mut ext, "Next header", full[0], cursor, 1);
                push(&mut ext, "Header length", length as u64, cursor + 1, 1);
                frame.layers.push(ext);
                next_header = full[0];
                cursor += length;
                continue;
            }
            44 => {
                let Some(extension) = frame.raw_data.get(cursor..cursor + 8) else {
                    return malformed(frame, "Truncated IPv6 fragment header");
                };
                if cursor + 8 > end {
                    return malformed(frame, "IPv6 fragment header exceeds payload length");
                }
                let fragment = be_u16(extension, 2).unwrap();
                let mut ext = Layer::new("IPv6 Fragment");
                push(&mut ext, "Next header", extension[0], cursor, 1);
                push(
                    &mut ext,
                    "Fragment offset",
                    (fragment >> 3) & 0x1fff,
                    cursor + 2,
                    2,
                );
                push(&mut ext, "More fragments", fragment & 1 != 0, cursor + 2, 2);
                push(
                    &mut ext,
                    "Identification",
                    be_u32(extension, 4).unwrap(),
                    cursor + 4,
                    4,
                );
                frame.layers.push(ext);
                if fragment & 0xfff8 != 0 {
                    frame.info = "Fragmented IPv6 packet".to_owned();
                    return;
                }
                next_header = extension[0];
                cursor += 8;
                continue;
            }
            51 => {
                let Some(extension) = frame.raw_data.get(cursor..cursor + 2) else {
                    return malformed(frame, "Truncated IPv6 authentication header");
                };
                let length = (usize::from(extension[1]) + 2) * 4;
                let Some(full) = frame.raw_data.get(cursor..cursor + length) else {
                    return malformed(frame, "Truncated IPv6 authentication header");
                };
                if length < 12 {
                    return malformed(frame, "Invalid IPv6 authentication header length");
                }
                if cursor + length > end {
                    return malformed(frame, "IPv6 authentication header exceeds payload length");
                }
                let mut auth = Layer::new("IPv6 Authentication Header");
                push(&mut auth, "Next header", full[0], cursor, 1);
                push(&mut auth, "Payload length", full[1], cursor + 1, 1);
                push(
                    &mut auth,
                    "Reserved",
                    be_u16(full, 2).unwrap(),
                    cursor + 2,
                    2,
                );
                push(
                    &mut auth,
                    "Security parameters index",
                    be_u32(full, 4).unwrap(),
                    cursor + 4,
                    4,
                );
                push(
                    &mut auth,
                    "Sequence number",
                    be_u32(full, 8).unwrap(),
                    cursor + 8,
                    4,
                );
                if length > 12 {
                    auth.fields.push(
                        Field::new("Authentication data", full[12..length].to_vec())
                            .at(cursor + 12, length - 12),
                    );
                }
                frame.layers.push(auth);
                next_header = full[0];
                cursor += length;
                continue;
            }
            _ => break,
        }
    }
    decode_transport(frame, next_header, cursor, end, registry);
}

fn decode_transport(
    frame: &mut Frame,
    protocol: u8,
    offset: usize,
    end: usize,
    registry: &DecoderRegistry,
) {
    let Some(data) = frame.raw_data.get(offset..end) else {
        return malformed(frame, "Invalid transport payload bounds");
    };
    if protocol == 47 {
        return decode_gre(frame, offset, end, registry);
    }
    let decoded = match protocol {
        6 => decode_tcp(data, offset, registry),
        17 => decode_udp(data, offset, registry),
        1 | 58 => decode_icmp(data, offset, protocol == 58),
        _ => {
            frame.protocol = match protocol {
                2 => Cow::Borrowed("IGMP"),
                47 => Cow::Borrowed("GRE"),
                50 => Cow::Borrowed("ESP"),
                89 => Cow::Borrowed("OSPF"),
                _ => frame.protocol.clone(),
            };
            frame.info = format!("IP protocol {protocol}");
            return;
        }
    };
    match decoded {
        Ok(decoded) => {
            frame.layers.push(decoded.layer);
            if let Some(application_layer) = decoded.application_layer {
                frame.layers.push(application_layer);
            }
            frame.protocol = decoded.protocol;
            frame.info = decoded.info;
        }
        Err(message) => malformed(frame, message),
    }
}

fn decode_gre(frame: &mut Frame, offset: usize, end: usize, registry: &DecoderRegistry) {
    let parsed = frame
        .raw_data
        .get(offset..end)
        .ok_or("Invalid GRE payload bounds")
        .and_then(|data| parse_gre(data, offset));
    let (layer, protocol, cursor) = match parsed {
        Ok(parsed) => parsed,
        Err(message) => return malformed(frame, message),
    };
    frame.layers.push(layer);
    match protocol {
        0x0800 => decode_ipv4(frame, offset + cursor, registry),
        0x86dd => decode_ipv6(frame, offset + cursor, registry),
        0x6558 => decode_ethernet_inner(frame, offset + cursor, registry),
        _ => {
            frame.protocol = Cow::Borrowed("GRE");
            frame.info = format!("Protocol 0x{protocol:04x}");
        }
    }
}

fn parse_gre(data: &[u8], offset: usize) -> Result<(Layer, u16, usize), &'static str> {
    if data.len() < 4 {
        return Err("Truncated GRE header");
    }
    let flags_version = be_u16(data, 0).unwrap();
    let protocol = be_u16(data, 2).unwrap();
    if flags_version & 0x0007 != 0 {
        return Err("Unsupported GRE version");
    }
    let mut layer = Layer::with_capacity("Generic Routing Encapsulation", 8);
    push(
        &mut layer,
        "Checksum present",
        flags_version & 0x8000 != 0,
        offset,
        2,
    );
    push(
        &mut layer,
        "Routing present",
        flags_version & 0x4000 != 0,
        offset,
        2,
    );
    push(
        &mut layer,
        "Key present",
        flags_version & 0x2000 != 0,
        offset,
        2,
    );
    push(
        &mut layer,
        "Sequence present",
        flags_version & 0x1000 != 0,
        offset,
        2,
    );
    layer
        .fields
        .push(Field::hex("Protocol", u64::from(protocol)).at(offset + 2, 2));
    let mut cursor = 4;
    if flags_version & 0xc000 != 0 {
        let Some(checksum) = data.get(cursor..cursor + 4) else {
            return Err("Truncated GRE checksum or routing fields");
        };
        if flags_version & 0x8000 != 0 {
            layer.fields.push(
                Field::hex("Checksum", u64::from(be_u16(checksum, 0).unwrap()))
                    .at(offset + cursor, 2),
            );
        }
        cursor += 4;
    }
    if flags_version & 0x4000 != 0 {
        let mut terminated = false;
        for _ in 0..64 {
            let Some(route) = data.get(cursor..cursor + 4) else {
                return Err("Truncated GRE source-route entry");
            };
            let family = be_u16(route, 0).unwrap();
            let route_length = usize::from(route[3]);
            cursor += 4;
            if family == 0 && route_length == 0 {
                terminated = true;
                break;
            }
            if data.get(cursor..cursor + route_length).is_none() {
                return Err("Truncated GRE source-route data");
            }
            cursor += route_length;
        }
        if !terminated {
            return Err("Unterminated GRE source-route list");
        }
    }
    if flags_version & 0x2000 != 0 {
        let Some(key) = be_u32(data, cursor) else {
            return Err("Truncated GRE key");
        };
        push(&mut layer, "Key", key, offset + cursor, 4);
        cursor += 4;
    }
    if flags_version & 0x1000 != 0 {
        let Some(sequence) = be_u32(data, cursor) else {
            return Err("Truncated GRE sequence");
        };
        push(&mut layer, "Sequence number", sequence, offset + cursor, 4);
        cursor += 4;
    }
    Ok((layer, protocol, cursor))
}

fn decode_ethernet_inner(frame: &mut Frame, offset: usize, registry: &DecoderRegistry) {
    let Some(header) = frame.raw_data.get(offset..offset + 14) else {
        return malformed(frame, "Truncated Ethernet frame inside GRE");
    };
    let mut layer = Layer::with_capacity("Ethernet II", 3);
    layer
        .fields
        .push(Field::new("Destination", <[u8; 6]>::try_from(&header[0..6]).unwrap()).at(offset, 6));
    layer
        .fields
        .push(Field::new("Source", <[u8; 6]>::try_from(&header[6..12]).unwrap()).at(offset + 6, 6));
    let protocol = be_u16(header, 12).unwrap();
    layer
        .fields
        .push(Field::hex("Type", u64::from(protocol)).at(offset + 12, 2));
    frame.layers.push(layer);
    decode_link_protocol(frame, protocol, offset + 14, registry);
}

struct DecodedTransport {
    layer: Layer,
    application_layer: Option<Layer>,
    protocol: Cow<'static, str>,
    info: String,
}

fn decode_tcp(
    data: &[u8],
    offset: usize,
    registry: &DecoderRegistry,
) -> Result<DecodedTransport, &'static str> {
    if data.len() < 20 {
        return Err("Truncated TCP header");
    }
    let Some(tcp) = view::<TcpHeader>(data) else {
        return Err("Truncated TCP header");
    };
    let header_len = usize::from(tcp.data_offset_reserved >> 4) * 4;
    if header_len < 20 || data.len() < header_len {
        return Err("Invalid TCP header length");
    }
    let source_port = tcp.source_port.get();
    let destination_port = tcp.destination_port.get();
    let flags = (u16::from(tcp.data_offset_reserved & 1) << 8) | u16::from(tcp.flags);
    let mut layer = Layer::with_capacity("Transmission Control Protocol", 17);
    push(&mut layer, "Source port", source_port, offset, 2);
    push(
        &mut layer,
        "Destination port",
        destination_port,
        offset + 2,
        2,
    );
    push(
        &mut layer,
        "Sequence number",
        tcp.sequence.get(),
        offset + 4,
        4,
    );
    push(
        &mut layer,
        "Acknowledgment number",
        tcp.acknowledgment.get(),
        offset + 8,
        4,
    );
    push(
        &mut layer,
        "Header length",
        header_len as u64,
        offset + 12,
        1,
    );
    for (name, mask) in [
        ("FIN", 0x001),
        ("SYN", 0x002),
        ("RST", 0x004),
        ("PSH", 0x008),
        ("ACK", 0x010),
        ("URG", 0x020),
        ("ECE", 0x040),
        ("CWR", 0x080),
        ("NS", 0x100),
    ] {
        push(&mut layer, name, flags & mask != 0, offset + 12, 2);
    }
    push(&mut layer, "Window size", tcp.window.get(), offset + 14, 2);
    push(&mut layer, "Checksum", tcp.checksum.get(), offset + 16, 2);
    push(
        &mut layer,
        "Urgent pointer",
        tcp.urgent_pointer.get(),
        offset + 18,
        2,
    );
    let mut application_layer = None;
    let mut protocol = Cow::Borrowed("TCP");
    let mut info = format!("{source_port} → {destination_port}");
    if flags & 0x002 != 0 {
        info.push_str(" [SYN]");
    }
    if flags & 0x010 != 0 {
        info.push_str(" [ACK]");
    }
    let transport = TransportInfo {
        protocol: 6,
        source_port,
        destination_port,
    };
    let payload = &data[header_len..];
    if let Some(application) = registry.decode_application(payload, transport, offset + header_len)
    {
        protocol = application_protocol(&application);
        if let Some(start_line) = application
            .fields
            .iter()
            .find(|field| field.name == "Start line")
        {
            info = start_line.value.to_string();
        }
        application_layer = Some(application);
    }
    Ok(DecodedTransport {
        layer,
        application_layer,
        protocol,
        info,
    })
}

fn decode_udp(
    data: &[u8],
    offset: usize,
    registry: &DecoderRegistry,
) -> Result<DecodedTransport, &'static str> {
    if data.len() < 8 {
        return Err("Truncated UDP header");
    }
    let Some(udp) = view::<UdpHeader>(data) else {
        return Err("Truncated UDP header");
    };
    let source_port = udp.source_port.get();
    let destination_port = udp.destination_port.get();
    let length = usize::from(udp.length.get());
    if length < 8 {
        return Err("Invalid UDP length");
    }
    let mut layer = Layer::with_capacity("User Datagram Protocol", 4);
    push(&mut layer, "Source port", source_port, offset, 2);
    push(
        &mut layer,
        "Destination port",
        destination_port,
        offset + 2,
        2,
    );
    push(&mut layer, "Length", length as u64, offset + 4, 2);
    push(&mut layer, "Checksum", udp.checksum.get(), offset + 6, 2);
    let mut application_layer = None;
    let mut protocol = Cow::Borrowed("UDP");
    let mut info = format!("{source_port} → {destination_port}");
    let payload_end = length.min(data.len());
    let transport = TransportInfo {
        protocol: 17,
        source_port,
        destination_port,
    };
    if let Some(application) =
        registry.decode_application(&data[8..payload_end], transport, offset + 8)
    {
        protocol = application_protocol(&application);
        if let Some(query) = application
            .fields
            .iter()
            .find(|field| field.name == "Query name")
        {
            info = query.value.to_string();
        }
        application_layer = Some(application);
    }
    Ok(DecodedTransport {
        layer,
        application_layer,
        protocol,
        info,
    })
}

fn decode_icmp(data: &[u8], offset: usize, ipv6: bool) -> Result<DecodedTransport, &'static str> {
    if data.len() < 4 {
        return Err("Truncated ICMP header");
    }
    let mut layer = Layer::with_capacity(
        if ipv6 {
            "Internet Control Message Protocol v6"
        } else {
            "Internet Control Message Protocol"
        },
        5,
    );
    push(&mut layer, "Type", data[0], offset, 1);
    push(&mut layer, "Code", data[1], offset + 1, 1);
    push(
        &mut layer,
        "Checksum",
        be_u16(data, 2).unwrap(),
        offset + 2,
        2,
    );
    let echo = if ipv6 {
        matches!(data[0], 128 | 129)
    } else {
        matches!(data[0], 0 | 8)
    };
    if echo && data.len() >= 8 {
        push(
            &mut layer,
            "Identifier",
            be_u16(data, 4).unwrap(),
            offset + 4,
            2,
        );
        push(
            &mut layer,
            "Sequence number",
            be_u16(data, 6).unwrap(),
            offset + 6,
            2,
        );
    } else if data.len() >= 8 {
        layer
            .fields
            .push(Field::new("Rest of header", data[4..8].to_vec()).at(offset + 4, 4));
    }
    Ok(DecodedTransport {
        layer,
        application_layer: None,
        protocol: Cow::Borrowed(if ipv6 { "ICMPv6" } else { "ICMP" }),
        info: format!("Type {}, code {}", data[0], data[1]),
    })
}

fn malformed(frame: &mut Frame, message: &str) {
    frame.protocol = Cow::Borrowed("Malformed");
    frame.info = message.to_owned();
}

fn push(
    layer: &mut Layer,
    name: &'static str,
    value: impl Into<crate::parser::layer::FieldValue>,
    offset: usize,
    length: usize,
) {
    layer
        .fields
        .push(Field::new(name, value).at(offset, length));
}

fn be_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn be_u24(bytes: &[u8], offset: usize) -> Option<u32> {
    let bytes = bytes.get(offset..offset + 3)?;
    Some((u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]))
}

fn be_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn mac(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut address = String::with_capacity(bytes.len().saturating_mul(3).saturating_sub(1));
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            address.push(':');
        }
        let _ = write!(address, "{byte:02x}");
    }
    address
}

fn address_text(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string(),
        16 => Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap()).to_string(),
        _ => mac(bytes),
    }
}

fn dns_record_type(kind: u16) -> String {
    match kind {
        1 => "A".to_owned(),
        2 => "NS".to_owned(),
        5 => "CNAME".to_owned(),
        6 => "SOA".to_owned(),
        12 => "PTR".to_owned(),
        15 => "MX".to_owned(),
        28 => "AAAA".to_owned(),
        33 => "SRV".to_owned(),
        255 => "ANY".to_owned(),
        _ => format!("TYPE{kind}"),
    }
}

fn application_protocol(application: &Layer) -> Cow<'static, str> {
    match application.name.as_ref() {
        "DNS" => Cow::Borrowed("DNS"),
        "HTTP" => Cow::Borrowed("HTTP"),
        "Dynamic Host Configuration Protocol" => Cow::Borrowed("DHCP"),
        "Transport Layer Security" => Cow::Borrowed("TLS"),
        _ => application.name.clone(),
    }
}

fn tls_content_type(content_type: u8) -> &'static str {
    match content_type {
        20 => "Change cipher spec",
        21 => "Alert",
        22 => "Handshake",
        23 => "Application data",
        _ => "Unknown",
    }
}

fn tls_handshake_type(handshake_type: u8) -> &'static str {
    match handshake_type {
        1 => "Client Hello",
        2 => "Server Hello",
        4 => "New Session Ticket",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        12 => "Server Key Exchange",
        13 => "Certificate Request",
        14 => "Server Hello Done",
        15 => "Certificate Verify",
        16 => "Client Key Exchange",
        20 => "Finished",
        _ => "Unknown",
    }
}

fn dhcp_message_type(message_type: u8) -> &'static str {
    match message_type {
        1 => "Discover",
        2 => "Offer",
        3 => "Request",
        4 => "Decline",
        5 => "ACK",
        6 => "NAK",
        7 => "Release",
        8 => "Inform",
        _ => "Unknown",
    }
}

fn dns_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut consumed = 0;
    let mut jumped = false;
    let mut jumps = 0;
    loop {
        let length = *data.get(cursor)?;
        if length == 0 {
            if !jumped {
                consumed += 1;
            }
            break;
        }
        if length & 0xc0 == 0xc0 {
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(*data.get(cursor + 1)?);
            if !jumped {
                consumed += 2;
            }
            cursor = pointer;
            jumped = true;
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            continue;
        }
        if length & 0xc0 != 0 {
            return None;
        }
        let length = usize::from(length);
        let label = data.get(cursor + 1..cursor + 1 + length)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        if !jumped {
            consumed += length + 1;
        }
        cursor += length + 1;
        if labels.len() > 127 {
            return None;
        }
    }
    Some((labels.join("."), consumed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::summarize_packet;

    fn ipv4_frame(protocol: u8, payload: &[u8]) -> Frame {
        let mut bytes = vec![0; 14 + 20 + payload.len()];
        bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        bytes[14] = 0x45;
        bytes[16..18].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        bytes[22] = 64;
        bytes[23] = protocol;
        bytes[26..30].copy_from_slice(&[192, 0, 2, 1]);
        bytes[30..34].copy_from_slice(&[198, 51, 100, 2]);
        bytes[34..].copy_from_slice(payload);
        Frame::new(1, std::time::Duration::ZERO, bytes.len() as u32, 1, bytes)
    }

    #[test]
    fn decodes_tls_handshake_fields_and_summary_protocol() {
        let mut tcp = vec![0; 20];
        tcp[0..2].copy_from_slice(&45000_u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443_u16.to_be_bytes());
        tcp[12] = 0x50;
        tcp.extend_from_slice(&[22, 3, 3, 0, 5, 1, 0, 0, 1, 0]);
        let mut frame = ipv4_frame(6, &tcp);
        decode_frame(&mut frame, 1, &DecoderRegistry::new());
        assert_eq!(frame.protocol, "TLS");
        let tls = frame
            .layers
            .iter()
            .find(|layer| layer.name == "Transport Layer Security")
            .unwrap();
        assert!(tls.fields.iter().any(|field| {
            field.name == "Handshake type" && field.value.to_string() == "Client Hello"
        }));
        assert_eq!(summarize_packet(&frame.raw_data, 1).protocol, "TCP");
    }

    #[test]
    fn decodes_dhcp_message_options() {
        let mut dhcp = vec![0; 244];
        dhcp[0] = 1;
        dhcp[1] = 1;
        dhcp[2] = 6;
        dhcp[4..8].copy_from_slice(&0x1234_5678_u32.to_be_bytes());
        dhcp[236..240].copy_from_slice(&[99, 130, 83, 99]);
        dhcp[240..244].copy_from_slice(&[53, 1, 1, 255]);
        let mut udp = vec![0; 8];
        udp[0..2].copy_from_slice(&68_u16.to_be_bytes());
        udp[2..4].copy_from_slice(&67_u16.to_be_bytes());
        udp[4..6].copy_from_slice(&((8 + dhcp.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&dhcp);
        let mut frame = ipv4_frame(17, &udp);
        decode_frame(&mut frame, 1, &DecoderRegistry::new());
        assert_eq!(frame.protocol, "DHCP");
        assert_eq!(summarize_packet(&frame.raw_data, 1).protocol, "DHCP");
        let dhcp = frame
            .layers
            .iter()
            .find(|layer| layer.name == "Dynamic Host Configuration Protocol")
            .unwrap();
        assert!(dhcp.fields.iter().any(|field| {
            field.name == "Message type" && field.value.to_string() == "Discover"
        }));
    }

    #[test]
    fn decodes_inner_ipv4_inside_gre_tunnel() {
        let mut gre_payload = vec![0, 0, 0x08, 0x00];
        gre_payload.extend_from_slice(&[
            0x45, 0, 0, 24, 0, 0, 0, 0, 64, 1, 0, 0, 203, 0, 113, 1, 203, 0, 113, 2,
        ]);
        gre_payload.extend_from_slice(&[8, 0, 0, 0]);
        let mut frame = ipv4_frame(47, &gre_payload);
        decode_frame(&mut frame, 1, &DecoderRegistry::new());
        assert!(
            frame
                .layers
                .iter()
                .any(|layer| layer.name == "Generic Routing Encapsulation")
        );
        assert_eq!(frame.protocol, "ICMP");
    }
}
