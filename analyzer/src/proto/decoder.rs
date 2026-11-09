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
                Box::new(DhcpV6Decoder),
                Box::new(SipDecoder),
                Box::new(HttpDecoder),
                Box::new(TlsDecoder),
                Box::new(SshDecoder),
                Box::new(SmtpDecoder),
                Box::new(ImapDecoder),
                Box::new(VxlanDecoder),
                Box::new(GssapiDecoder),
                Box::new(NtpDecoder),
                Box::new(TftpDecoder),
                Box::new(FtpDecoder),
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
struct DhcpV6Decoder;
struct HttpDecoder;
struct TlsDecoder;
struct SshDecoder;
struct SmtpDecoder;
struct ImapDecoder;
struct VxlanDecoder;
struct GssapiDecoder;
struct NtpDecoder;
struct TftpDecoder;
struct SipDecoder;
struct FtpDecoder;

impl ApplicationDecoder for NtpDecoder {
    fn decode(&self, payload: &[u8], transport: TransportInfo, offset: usize) -> Option<Layer> {
        if transport.protocol != 17
            || (transport.source_port != 123 && transport.destination_port != 123)
            || payload.len() < 48
        {
            return None;
        }

        let flags = payload[0];
        let mut layer = Layer::with_capacity("Network Time Protocol", 24);
        push(
            &mut layer,
            "Leap indicator",
            match flags >> 6 {
                0 => "No warning",
                1 => "Last minute has 61 seconds",
                2 => "Last minute has 59 seconds",
                _ => "Alarm condition",
            },
            offset,
            1,
        );
        push(&mut layer, "Version", (flags >> 3) & 0x07, offset, 1);
        push(&mut layer, "Mode", ntp_mode(flags & 0x07), offset, 1);
        push(&mut layer, "Stratum", payload[1], offset + 1, 1);
        push(
            &mut layer,
            "Poll interval",
            i8::from_be_bytes([payload[2]]).to_string(),
            offset + 2,
            1,
        );
        push(
            &mut layer,
            "Precision",
            i8::from_be_bytes([payload[3]]).to_string(),
            offset + 3,
            1,
        );
        let root_delay = i32::from_be_bytes(payload[4..8].try_into().ok()?);
        push(
            &mut layer,
            "Root delay",
            format!("{:.4}", f64::from(root_delay) / 65_536.0),
            offset + 4,
            4,
        );
        let root_dispersion = be_u32(payload, 8)?;
        push(
            &mut layer,
            "Root dispersion",
            format!("{:.4}", f64::from(root_dispersion) / 65_536.0),
            offset + 8,
            4,
        );
        layer
            .fields
            .push(Field::new("Reference ID", encode_hex(&payload[12..16])).at(offset + 12, 4));
        for (name, start) in [
            ("Reference timestamp", 16),
            ("Originate timestamp", 24),
            ("Receive timestamp", 32),
            ("Transmit timestamp", 40),
        ] {
            push(
                &mut layer,
                format!("{name} seconds"),
                be_u32(payload, start)?,
                offset + start,
                4,
            );
            push(
                &mut layer,
                format!("{name} fraction"),
                be_u32(payload, start + 4)?,
                offset + start + 4,
                4,
            );
        }

        let mut cursor = 48;
        while cursor + 4 <= payload.len() {
            let length = usize::from(be_u16(payload, cursor + 2)?);
            if length < 4 || length % 4 != 0 || cursor.checked_add(length)? > payload.len() {
                break;
            }
            push(
                &mut layer,
                "Extension type",
                be_u16(payload, cursor)?,
                offset + cursor,
                2,
            );
            push(
                &mut layer,
                "Extension length",
                length as u64,
                offset + cursor + 2,
                2,
            );
            layer.fields.push(
                Field::new(
                    "Extension data",
                    payload[cursor + 4..cursor + length].to_vec(),
                )
                .at(offset + cursor + 4, length - 4),
            );
            cursor += length;
        }
        if payload.len() - cursor >= 4 {
            push(
                &mut layer,
                "Authentication key ID",
                be_u32(payload, cursor)?,
                offset + cursor,
                4,
            );
            if cursor + 4 < payload.len() {
                layer.fields.push(
                    Field::new("Authentication digest", payload[cursor + 4..].to_vec())
                        .at(offset + cursor + 4, payload.len() - cursor - 4),
                );
            }
        } else if cursor < payload.len() {
            layer.fields.push(
                Field::new("Trailing data", payload[cursor..].to_vec())
                    .at(offset + cursor, payload.len() - cursor),
            );
        }
        Some(layer)
    }
}

impl ApplicationDecoder for TftpDecoder {
    fn decode(&self, payload: &[u8], transport: TransportInfo, offset: usize) -> Option<Layer> {
        if transport.protocol != 17
            || (transport.source_port != 69 && transport.destination_port != 69)
        {
            return None;
        }
        let opcode = be_u16(payload, 0)?;
        let mut layer = Layer::with_capacity("Trivial File Transfer Protocol", 8);
        push(&mut layer, "Opcode", tftp_opcode(opcode)?, offset, 2);
        match opcode {
            1 | 2 => {
                let (filename, consumed) = tftp_string(payload, 2)?;
                let (mode, mode_consumed) = tftp_string(payload, 2 + consumed)?;
                if filename.is_empty() || mode.is_empty() {
                    return None;
                }
                layer
                    .fields
                    .push(Field::new("Filename", filename).at(offset + 2, consumed));
                layer.fields.push(
                    Field::new("Transfer mode", mode).at(offset + 2 + consumed, mode_consumed),
                );
                decode_tftp_options(payload, 2 + consumed + mode_consumed, offset, &mut layer)?;
            }
            3 => {
                push(
                    &mut layer,
                    "Block number",
                    be_u16(payload, 2)?,
                    offset + 2,
                    2,
                );
                layer.fields.push(
                    Field::new("Data", payload[4..].to_vec())
                        .at(offset + 4, payload.len().saturating_sub(4)),
                );
            }
            4 => {
                if payload.len() != 4 {
                    return None;
                }
                push(
                    &mut layer,
                    "Block number",
                    be_u16(payload, 2)?,
                    offset + 2,
                    2,
                );
            }
            5 => {
                let code = be_u16(payload, 2)?;
                let (message, consumed) = tftp_string(payload, 4)?;
                if 4 + consumed != payload.len() {
                    return None;
                }
                push(
                    &mut layer,
                    "Error code",
                    tftp_error_code(code),
                    offset + 2,
                    2,
                );
                layer
                    .fields
                    .push(Field::new("Error message", message).at(offset + 4, consumed - 1));
            }
            6 => decode_tftp_options(payload, 2, offset, &mut layer)?,
            _ => return None,
        }
        Some(layer)
    }
}

impl ApplicationDecoder for SipDecoder {
    fn decode(&self, payload: &[u8], transport: TransportInfo, offset: usize) -> Option<Layer> {
        if !matches!(transport.protocol, 6 | 17)
            || (transport.source_port != 5060 && transport.destination_port != 5060)
        {
            return None;
        }
        let first_line_end = payload.iter().position(|byte| *byte == b'\n')?;
        let first_line = trim_ascii_end(&payload[..first_line_end]);
        let start_line = std::str::from_utf8(first_line).ok()?;
        let mut parts = start_line.split_ascii_whitespace();
        let first = parts.next()?;
        let mut layer = Layer::with_capacity("Session Initiation Protocol", 12);
        layer
            .fields
            .push(Field::new("Start line", start_line.to_owned()).at(offset, first_line.len()));
        if first.eq_ignore_ascii_case("SIP/2.0") {
            let status = parts.next()?;
            if status.len() != 3 || !status.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            let status_code = status.parse::<u16>().ok()?;
            let status_offset = first_line
                .windows(status.len())
                .position(|window| window == status.as_bytes())?;
            push(
                &mut layer,
                "Status code",
                status_code,
                offset + status_offset,
                status.len(),
            );
            let reason_start = status_offset + status.len();
            let reason_start = first_line[reason_start..]
                .iter()
                .position(|byte| !byte.is_ascii_whitespace())
                .map_or(first_line.len(), |relative| reason_start + relative);
            if reason_start < first_line.len() {
                layer.fields.push(
                    Field::new(
                        "Reason phrase",
                        String::from_utf8_lossy(&first_line[reason_start..]).into_owned(),
                    )
                    .at(offset + reason_start, first_line.len() - reason_start),
                );
            }
        } else {
            let method = sip_method(first)?;
            let uri = parts.next()?;
            let version = parts.next()?;
            if version != "SIP/2.0" || parts.next().is_some() {
                return None;
            }
            layer
                .fields
                .push(Field::new("Method", method).at(offset, first.len()));
            let uri_offset = first_line
                .windows(uri.len())
                .position(|window| window == uri.as_bytes())?;
            layer
                .fields
                .push(Field::new("Request URI", uri).at(offset + uri_offset, uri.len()));
            let version_offset = first_line
                .windows(version.len())
                .rposition(|window| window == version.as_bytes())?;
            layer
                .fields
                .push(Field::new("Version", version).at(offset + version_offset, version.len()));
        }

        let mut cursor = first_line_end + 1;
        let mut content_length = None;
        let mut header_count = 0;
        while cursor < payload.len() && header_count < 256 {
            let line_start = cursor;
            let line_end = payload[cursor..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(payload.len(), |relative| cursor + relative);
            let line = trim_ascii_end(&payload[line_start..line_end]);
            cursor = line_end.saturating_add(1);
            if line.is_empty() {
                break;
            }
            if line.first().is_some_and(u8::is_ascii_whitespace) {
                layer.fields.push(
                    Field::new(
                        "Header continuation",
                        String::from_utf8_lossy(line).into_owned(),
                    )
                    .at(offset + line_start, line.len()),
                );
                header_count += 1;
                continue;
            }
            let separator = line.iter().position(|byte| *byte == b':')?;
            let name = std::str::from_utf8(&line[..separator]).ok()?;
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return None;
            }
            let value_start = line[separator + 1..]
                .iter()
                .position(|byte| !byte.is_ascii_whitespace())
                .map_or(line.len(), |relative| separator + 1 + relative);
            let value = String::from_utf8_lossy(&line[value_start..]).into_owned();
            if name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("l") {
                content_length = Some(value.parse::<usize>().ok()?);
            }
            layer.fields.push(
                Field::new(format!("Header: {name}"), value)
                    .at(offset + line_start + value_start, line.len() - value_start),
            );
            header_count += 1;
        }
        let body_length = content_length.unwrap_or(payload.len().saturating_sub(cursor));
        if body_length > payload.len().saturating_sub(cursor) {
            return None;
        }
        if body_length > 0 {
            layer.fields.push(
                Field::new(
                    "Message body",
                    String::from_utf8_lossy(&payload[cursor..cursor + body_length]).into_owned(),
                )
                .at(offset + cursor, body_length),
            );
        }
        Some(layer)
    }
}

impl ApplicationDecoder for FtpDecoder {
    fn decode(&self, payload: &[u8], transport: TransportInfo, offset: usize) -> Option<Layer> {
        if transport.protocol != 6
            || (transport.source_port != 21 && transport.destination_port != 21)
        {
            return None;
        }
        let line_end = payload
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or(payload.len());
        let line = trim_ascii_end(&payload[..line_end.min(1024)]);
        let separator = line.iter().position(u8::is_ascii_whitespace);
        let token_end = separator.unwrap_or(line.len());
        let token = std::str::from_utf8(&line[..token_end]).ok()?;
        let mut layer = Layer::with_capacity("File Transfer Protocol", 3);
        if token.len() == 3 && token.bytes().all(|byte| byte.is_ascii_digit()) {
            push(
                &mut layer,
                "Response code",
                token.parse::<u16>().ok()?,
                offset,
                3,
            );
            if token_end < line.len() {
                let delimiter = line[token_end];
                if !matches!(delimiter, b' ' | b'-') {
                    return None;
                }
                push(
                    &mut layer,
                    "Response continuation",
                    delimiter == b'-',
                    offset + token_end,
                    1,
                );
            }
        } else {
            if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_alphabetic()) {
                return None;
            }
            layer
                .fields
                .push(Field::new("Command", token.to_ascii_uppercase()).at(offset, token_end));
        }
        if token_end < line.len() {
            let argument_start = token_end + usize::from(line[token_end].is_ascii_whitespace());
            if argument_start < line.len() {
                layer.fields.push(
                    Field::new(
                        if token.len() == 3 {
                            "Response text"
                        } else {
                            "Argument"
                        },
                        String::from_utf8_lossy(&line[argument_start..]).into_owned(),
                    )
                    .at(offset + argument_start, line.len() - argument_start),
                );
            }
        }
        layer.fields.push(
            Field::new("Line", String::from_utf8_lossy(line).into_owned()).at(offset, line.len()),
        );
        Some(layer)
    }
}

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
        decode_dns_records(dns, dns_offset, questions, answers, &mut layer);
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

impl ApplicationDecoder for DhcpV6Decoder {
    fn decode(&self, payload: &[u8], transport: TransportInfo, offset: usize) -> Option<Layer> {
        if transport.protocol != 17
            || !matches!(
                (transport.source_port, transport.destination_port),
                (546 | 547, 546 | 547)
            )
            || payload.len() < 4
        {
            return None;
        }
        let message_type = payload[0];
        let relay = matches!(message_type, 12 | 13);
        let mut layer = Layer::with_capacity("DHCPv6", 12);
        push(
            &mut layer,
            "Message type",
            dhcpv6_message_type(message_type),
            offset,
            1,
        );
        let mut cursor;
        if relay {
            if payload.len() < 34 {
                return None;
            }
            push(&mut layer, "Hop count", payload[1], offset + 1, 1);
            layer.fields.push(
                Field::new("Link address", <[u8; 16]>::try_from(&payload[2..18]).ok()?)
                    .at(offset + 2, 16),
            );
            layer.fields.push(
                Field::new("Peer address", <[u8; 16]>::try_from(&payload[18..34]).ok()?)
                    .at(offset + 18, 16),
            );
            cursor = 34;
        } else {
            push(
                &mut layer,
                "Transaction ID",
                be_u24(payload, 1)?,
                offset + 1,
                3,
            );
            cursor = 4;
        }
        let mut options = 0;
        while cursor + 4 <= payload.len() && options < 128 {
            let code = be_u16(payload, cursor)?;
            let length = usize::from(be_u16(payload, cursor + 2)?);
            let value_start = cursor + 4;
            let value_end = value_start.checked_add(length)?;
            let value = payload.get(value_start..value_end)?;
            let option_name = dhcpv6_option_name(code);
            let option_value = match code {
                1 | 2 if length == 4 => format!("0x{}", encode_hex(value)),
                6 if length.is_multiple_of(2) => value
                    .chunks_exact(2)
                    .map(|pair| dhcpv6_option_name(be_u16(pair, 0).unwrap()).to_owned())
                    .collect::<Vec<_>>()
                    .join(", "),
                14 if length == 0 => "Rapid commit".to_owned(),
                23 if length.is_multiple_of(16) => value
                    .chunks_exact(16)
                    .map(|address| {
                        Ipv6Addr::from(<[u8; 16]>::try_from(address).unwrap()).to_string()
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
                _ => format!("{} bytes", length),
            };
            layer
                .fields
                .push(Field::new(option_name, option_value).at(offset + cursor, 4 + length));
            cursor = value_end;
            options += 1;
        }
        if cursor != payload.len() && cursor + 4 > payload.len() {
            return None;
        }
        Some(layer)
    }
}

impl ApplicationDecoder for SshDecoder {
    fn decode(&self, payload: &[u8], transport: TransportInfo, offset: usize) -> Option<Layer> {
        if transport.protocol != 6 || !payload.starts_with(b"SSH-") {
            return None;
        }
        let line_end = payload
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or(payload.len());
        let line = payload[..line_end].trim_ascii_end();
        let mut layer = Layer::new("Secure Shell");
        layer.fields.push(
            Field::new(
                "Identification string",
                String::from_utf8_lossy(line).into_owned(),
            )
            .at(offset, line.len()),
        );
        Some(layer)
    }
}

impl ApplicationDecoder for SmtpDecoder {
    fn decode(&self, payload: &[u8], transport: TransportInfo, offset: usize) -> Option<Layer> {
        if transport.protocol != 6
            || !matches!(
                (transport.source_port, transport.destination_port),
                (25 | 465 | 587, _) | (_, 25 | 465 | 587)
            )
        {
            return None;
        }
        let line_end = payload
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or(payload.len())
            .min(512);
        let line = payload.get(..line_end)?.trim_ascii_end();
        let command = line
            .split(|byte| byte.is_ascii_whitespace())
            .next()
            .filter(|command| {
                matches!(
                    *command,
                    b"220"
                        | b"221"
                        | b"250"
                        | b"354"
                        | b"421"
                        | b"450"
                        | b"451"
                        | b"452"
                        | b"500"
                        | b"501"
                        | b"502"
                        | b"503"
                        | b"504"
                        | b"550"
                        | b"551"
                        | b"552"
                        | b"553"
                        | b"554"
                        | b"EHLO"
                        | b"HELO"
                        | b"MAIL"
                        | b"RCPT"
                        | b"DATA"
                        | b"RSET"
                        | b"NOOP"
                        | b"QUIT"
                        | b"STARTTLS"
                )
            })?;
        let mut layer = Layer::new("Simple Mail Transfer Protocol");
        layer.fields.push(
            Field::new(
                "Command or response",
                String::from_utf8_lossy(command).into_owned(),
            )
            .at(offset, command.len()),
        );
        layer.fields.push(
            Field::new("Line", String::from_utf8_lossy(line).into_owned()).at(offset, line.len()),
        );
        Some(layer)
    }
}

impl ApplicationDecoder for ImapDecoder {
    fn decode(&self, payload: &[u8], transport: TransportInfo, offset: usize) -> Option<Layer> {
        if transport.protocol != 6
            || (transport.source_port != 143 && transport.destination_port != 143)
        {
            return None;
        }
        let line_end = payload
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or(payload.len())
            .min(512);
        let line = payload.get(..line_end)?.trim_ascii_end();
        let command = line
            .split(|byte| byte.is_ascii_whitespace())
            .next()
            .filter(|command| {
                matches!(
                    command.to_ascii_uppercase().as_slice(),
                    b"*" | b"A001"
                        | b"A002"
                        | b"A003"
                        | b"A004"
                        | b"A005"
                        | b"CAPABILITY"
                        | b"LOGIN"
                        | b"LOGOUT"
                        | b"SELECT"
                        | b"EXAMINE"
                        | b"CREATE"
                        | b"DELETE"
                        | b"RENAME"
                        | b"SUBSCRIBE"
                        | b"UNSUBSCRIBE"
                        | b"LIST"
                        | b"LSUB"
                        | b"STATUS"
                        | b"APPEND"
                        | b"CHECK"
                        | b"CLOSE"
                        | b"EXPUNGE"
                        | b"SEARCH"
                        | b"FETCH"
                        | b"STORE"
                        | b"COPY"
                        | b"NOOP"
                        | b"STARTTLS"
                        | b"OK"
                        | b"PREAUTH"
                        | b"NO"
                        | b"BAD"
                )
            })?;
        let mut layer = Layer::new("Internet Message Access Protocol");
        layer.fields.push(
            Field::new(
                "Command or response",
                String::from_utf8_lossy(command).into_owned(),
            )
            .at(offset, command.len()),
        );
        layer.fields.push(
            Field::new("Line", String::from_utf8_lossy(line).into_owned()).at(offset, line.len()),
        );
        Some(layer)
    }
}

impl ApplicationDecoder for VxlanDecoder {
    fn decode(&self, payload: &[u8], transport: TransportInfo, offset: usize) -> Option<Layer> {
        if transport.protocol != 17
            || (transport.source_port != 4789 && transport.destination_port != 4789)
            || payload.len() < 8
            || payload[0] & 0x08 == 0
        {
            return None;
        }
        let mut layer = Layer::with_capacity("Virtual eXtensible LAN", 4);
        push(&mut layer, "Flags", payload[0], offset, 1);
        layer
            .fields
            .push(Field::new("Reserved", payload[1..4].to_vec()).at(offset + 1, 3));
        push(
            &mut layer,
            "VNI",
            (u32::from(payload[4]) << 16) | (u32::from(payload[5]) << 8) | u32::from(payload[6]),
            offset + 4,
            3,
        );
        push(&mut layer, "Reserved", payload[7], offset + 7, 1);
        Some(layer)
    }
}

impl ApplicationDecoder for GssapiDecoder {
    fn decode(&self, payload: &[u8], transport: TransportInfo, offset: usize) -> Option<Layer> {
        if !matches!(transport.protocol, 6 | 17)
            || !matches!(
                (transport.source_port, transport.destination_port),
                (88 | 389 | 636, _) | (_, 88 | 389 | 636)
            )
        {
            return None;
        }
        const KERBEROS_MECHANISM_OID: &[u8] =
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
        let oid_start = payload
            .windows(KERBEROS_MECHANISM_OID.len())
            .position(|window| window == KERBEROS_MECHANISM_OID)?;
        let mut layer = Layer::new("Generic Security Services API");
        layer.fields.push(
            Field::new("Mechanism", "Kerberos 5")
                .at(offset + oid_start, KERBEROS_MECHANISM_OID.len()),
        );
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
            if payload[5] == 1 {
                decode_tls_client_hello(payload, offset, &mut layer);
            }
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
        layer.fields.push(Field::new(
            "VLAN tag index",
            u64::try_from(vlan_count + 1).unwrap(),
        ));
        layer
            .fields
            .push(Field::hex("Tag protocol identifier", u64::from(ether_type)).at(offset - 2, 2));
        push(&mut layer, "VLAN ID", tci & 0x0fff, offset, 2);
        push(&mut layer, "VLAN priority", tci >> 13, offset, 2);
        push(&mut layer, "Drop eligible", tci & 0x1000 != 0, offset, 2);
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
    if protocol == 47 {
        return decode_gre(frame, offset, end, registry);
    }
    if protocol == 51 {
        return decode_ah(frame, offset, end, registry);
    }
    let Some(data) = frame.raw_data.get(offset..end) else {
        return malformed(frame, "Invalid transport payload bounds");
    };
    let decoded = match protocol {
        6 => decode_tcp(data, offset, registry),
        17 => decode_udp(data, offset, registry),
        1 | 58 => decode_icmp(data, offset, protocol == 58),
        50 => decode_esp(data, offset),
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
            let vxlan = decoded
                .application_layer
                .as_ref()
                .is_some_and(|layer| layer.name == "Virtual eXtensible LAN");
            frame.layers.push(decoded.layer);
            if let Some(application_layer) = decoded.application_layer {
                frame.layers.push(application_layer);
            }
            frame.protocol = decoded.protocol;
            frame.info = decoded.info;
            if vxlan {
                decode_ethernet_inner(frame, offset + 16, end, registry);
            }
        }
        Err(message) => malformed(frame, message),
    }
}

fn decode_esp(data: &[u8], offset: usize) -> Result<DecodedTransport, &'static str> {
    if data.len() < 8 {
        return Err("Truncated IPsec ESP header");
    }
    let mut layer = Layer::new("Encapsulating Security Payload");
    push(
        &mut layer,
        "Security parameters index",
        be_u32(data, 0).unwrap(),
        offset,
        4,
    );
    push(
        &mut layer,
        "Sequence number",
        be_u32(data, 4).unwrap(),
        offset + 4,
        4,
    );
    if data.len() > 8 {
        layer.fields.push(
            Field::new("Encrypted payload", data[8..].to_vec()).at(offset + 8, data.len() - 8),
        );
    }
    Ok(DecodedTransport {
        layer,
        application_layer: None,
        protocol: Cow::Borrowed("ESP"),
        info: "Encrypted IPsec payload".to_owned(),
    })
}

fn decode_ah(frame: &mut Frame, offset: usize, end: usize, registry: &DecoderRegistry) {
    let parsed = frame
        .raw_data
        .get(offset..end)
        .ok_or("Invalid transport payload bounds")
        .and_then(|data| {
            if data.len() < 12 {
                return Err("Truncated IPsec Authentication Header");
            }
            let next_header = data[0];
            let length = (usize::from(data[1]) + 2) * 4;
            if length < 12 || data.len() < length {
                return Err("Invalid IPsec Authentication Header length");
            }
            let mut layer = Layer::with_capacity("Authentication Header", 5);
            push(&mut layer, "Next header", next_header, offset, 1);
            push(&mut layer, "Payload length", data[1], offset + 1, 1);
            push(
                &mut layer,
                "Reserved",
                be_u16(data, 2).unwrap(),
                offset + 2,
                2,
            );
            push(
                &mut layer,
                "Security parameters index",
                be_u32(data, 4).unwrap(),
                offset + 4,
                4,
            );
            push(
                &mut layer,
                "Sequence number",
                be_u32(data, 8).unwrap(),
                offset + 8,
                4,
            );
            if length > 12 {
                layer.fields.push(
                    Field::new("Integrity check value", data[12..length].to_vec())
                        .at(offset + 12, length - 12),
                );
            }
            Ok((layer, next_header, length))
        });
    let (layer, next_header, length) = match parsed {
        Ok(parsed) => parsed,
        Err(message) => return malformed(frame, message),
    };
    if offset + length > end {
        return malformed(frame, "Authentication Header exceeds IP payload");
    }
    frame.layers.push(layer);
    if matches!(next_header, 6 | 17 | 1 | 58 | 47 | 50 | 51) {
        decode_transport(frame, next_header, offset + length, end, registry);
    } else {
        frame.protocol = Cow::Borrowed("AH");
        frame.info = format!("Next header {next_header}");
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
        0x6558 => decode_ethernet_inner(frame, offset + cursor, end, registry),
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

fn decode_ethernet_inner(frame: &mut Frame, offset: usize, end: usize, registry: &DecoderRegistry) {
    let Some(header_end) = offset
        .checked_add(14)
        .filter(|header_end| *header_end <= end)
    else {
        return malformed(frame, "Truncated encapsulated Ethernet header");
    };
    let Some(header) = frame.raw_data.get(offset..header_end) else {
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
    let neighbor_discovery = ipv6 && matches!(data[0], 133..=137);
    if neighbor_discovery {
        decode_neighbor_discovery(data, offset, &mut layer)?;
    }
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
        protocol: Cow::Borrowed(if neighbor_discovery {
            "NDP"
        } else if ipv6 {
            "ICMPv6"
        } else {
            "ICMP"
        }),
        info: format!("Type {}, code {}", data[0], data[1]),
    })
}

fn decode_neighbor_discovery(
    data: &[u8],
    offset: usize,
    layer: &mut Layer,
) -> Result<(), &'static str> {
    layer.name = "ICMPv6 Neighbor Discovery".into();
    let mut options_offset = match data[0] {
        133 => {
            if data.len() < 8 {
                return Err("Truncated router solicitation");
            }
            push(layer, "Reserved", be_u32(data, 4).unwrap(), offset + 4, 4);
            8
        }
        134 => {
            if data.len() < 16 {
                return Err("Truncated router advertisement");
            }
            push(layer, "Current hop limit", data[4], offset + 4, 1);
            push(
                layer,
                "Managed address configuration",
                data[5] & 0x80 != 0,
                offset + 5,
                1,
            );
            push(
                layer,
                "Other configuration",
                data[5] & 0x40 != 0,
                offset + 5,
                1,
            );
            push(
                layer,
                "Router lifetime",
                be_u16(data, 6).unwrap(),
                offset + 6,
                2,
            );
            push(
                layer,
                "Reachable time",
                be_u32(data, 8).unwrap(),
                offset + 8,
                4,
            );
            push(
                layer,
                "Retransmission timer",
                be_u32(data, 12).unwrap(),
                offset + 12,
                4,
            );
            16
        }
        135 | 136 => {
            if data.len() < 24 {
                return Err("Truncated neighbor solicitation or advertisement");
            }
            if data[0] == 136 {
                push(layer, "Router", data[4] & 0x80 != 0, offset + 4, 1);
                push(layer, "Solicited", data[4] & 0x40 != 0, offset + 4, 1);
                push(layer, "Override", data[4] & 0x20 != 0, offset + 4, 1);
            } else {
                push(layer, "Reserved", be_u32(data, 4).unwrap(), offset + 4, 4);
            }
            layer.fields.push(
                Field::new(
                    "Target address",
                    <[u8; 16]>::try_from(&data[8..24]).unwrap(),
                )
                .at(offset + 8, 16),
            );
            24
        }
        137 => {
            if data.len() < 40 {
                return Err("Truncated neighbor redirect");
            }
            push(layer, "Reserved", be_u32(data, 4).unwrap(), offset + 4, 4);
            layer.fields.push(
                Field::new(
                    "Target address",
                    <[u8; 16]>::try_from(&data[8..24]).unwrap(),
                )
                .at(offset + 8, 16),
            );
            layer.fields.push(
                Field::new(
                    "Destination address",
                    <[u8; 16]>::try_from(&data[24..40]).unwrap(),
                )
                .at(offset + 24, 16),
            );
            40
        }
        _ => return Ok(()),
    };

    let mut option_count = 0;
    while options_offset < data.len() && option_count < 64 {
        let option = data
            .get(options_offset..options_offset + 2)
            .ok_or("Truncated Neighbor Discovery option header")?;
        let option_len = usize::from(option[1])
            .checked_mul(8)
            .filter(|length| *length >= 8)
            .ok_or("Invalid Neighbor Discovery option length")?;
        let bytes = data
            .get(options_offset..options_offset + option_len)
            .ok_or("Truncated Neighbor Discovery option")?;
        let option_offset = offset + options_offset;
        match option[0] {
            1 | 2 if option_len >= 8 => layer.fields.push(
                Field::new(
                    if option[0] == 1 {
                        "Source link-layer address"
                    } else {
                        "Target link-layer address"
                    },
                    mac(&bytes[2..8]),
                )
                .at(option_offset + 2, 6),
            ),
            3 if option_len == 32 => {
                push(layer, "Prefix length", bytes[2], option_offset + 2, 1);
                push(layer, "On-link", bytes[3] & 0x80 != 0, option_offset + 3, 1);
                push(
                    layer,
                    "Autonomous",
                    bytes[3] & 0x40 != 0,
                    option_offset + 3,
                    1,
                );
                push(
                    layer,
                    "Valid lifetime",
                    be_u32(bytes, 4).unwrap(),
                    option_offset + 4,
                    4,
                );
                push(
                    layer,
                    "Preferred lifetime",
                    be_u32(bytes, 8).unwrap(),
                    option_offset + 8,
                    4,
                );
                layer.fields.push(
                    Field::new("Prefix", <[u8; 16]>::try_from(&bytes[16..32]).unwrap())
                        .at(option_offset + 16, 16),
                );
            }
            5 if option_len == 8 => {
                push(
                    layer,
                    "MTU",
                    be_u32(bytes, 4).unwrap(),
                    option_offset + 4,
                    4,
                );
            }
            _ => layer.fields.push(
                Field::new(nd_option_name(option[0]), bytes[2..].to_vec())
                    .at(option_offset + 2, option_len - 2),
            ),
        }
        options_offset += option_len;
        option_count += 1;
    }
    if options_offset < data.len() {
        return Err("Too many Neighbor Discovery options");
    }
    Ok(())
}

fn malformed(frame: &mut Frame, message: &str) {
    frame.protocol = Cow::Borrowed("Malformed");
    frame.info = message.to_owned();
}

fn push(
    layer: &mut Layer,
    name: impl Into<Cow<'static, str>>,
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

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn encode_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len().saturating_mul(4));
    for byte in bytes {
        let _ = write!(output, "\\x{byte:02x}");
    }
    output
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
        "DHCPv6" => Cow::Borrowed("DHCPv6"),
        "Transport Layer Security" => Cow::Borrowed("TLS"),
        "Secure Shell" => Cow::Borrowed("SSH"),
        "Simple Mail Transfer Protocol" => Cow::Borrowed("SMTP"),
        "Internet Message Access Protocol" => Cow::Borrowed("IMAP"),
        "Virtual eXtensible LAN" => Cow::Borrowed("VXLAN"),
        "Generic Security Services API" => Cow::Borrowed("GSSAPI"),
        "Network Time Protocol" => Cow::Borrowed("NTP"),
        "Trivial File Transfer Protocol" => Cow::Borrowed("TFTP"),
        "Session Initiation Protocol" => Cow::Borrowed("SIP"),
        "File Transfer Protocol" => Cow::Borrowed("FTP"),
        _ => application.name.clone(),
    }
}

fn ntp_mode(mode: u8) -> &'static str {
    match mode {
        0 => "Reserved",
        1 => "Symmetric active",
        2 => "Symmetric passive",
        3 => "Client",
        4 => "Server",
        5 => "Broadcast",
        6 => "Control message",
        _ => "Private use",
    }
}

fn tftp_opcode(opcode: u16) -> Option<&'static str> {
    match opcode {
        1 => Some("Read request"),
        2 => Some("Write request"),
        3 => Some("Data"),
        4 => Some("Acknowledgment"),
        5 => Some("Error"),
        6 => Some("Option acknowledgment"),
        _ => None,
    }
}

fn tftp_error_code(code: u16) -> &'static str {
    match code {
        0 => "Not defined",
        1 => "File not found",
        2 => "Access violation",
        3 => "Disk full or allocation exceeded",
        4 => "Illegal TFTP operation",
        5 => "Unknown transfer ID",
        6 => "File already exists",
        7 => "No such user",
        _ => "Unknown error",
    }
}

fn tftp_string(payload: &[u8], start: usize) -> Option<(String, usize)> {
    let tail = payload.get(start..)?;
    let length = tail.iter().position(|byte| *byte == 0)?;
    Some((
        String::from_utf8_lossy(&tail[..length]).into_owned(),
        length + 1,
    ))
}

fn decode_tftp_options(
    payload: &[u8],
    mut cursor: usize,
    offset: usize,
    layer: &mut Layer,
) -> Option<()> {
    while cursor < payload.len() {
        let (name, name_length) = tftp_string(payload, cursor)?;
        let value_start = cursor.checked_add(name_length)?;
        let (value, value_length) = tftp_string(payload, value_start)?;
        if name.is_empty() || value.is_empty() {
            return None;
        }
        layer.fields.push(
            Field::new(format!("Option: {name}"), value).at(offset + value_start, value_length - 1),
        );
        cursor = value_start.checked_add(value_length)?;
    }
    Some(())
}

fn sip_method(method: &str) -> Option<&str> {
    (!method.is_empty()
        && method
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.!%*+`'~".contains(&byte)))
    .then_some(method)
}

fn trim_ascii_end(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(0, |index| index + 1);
    &bytes[..end]
}

fn dhcpv6_message_type(message_type: u8) -> &'static str {
    match message_type {
        1 => "Solicit",
        2 => "Advertise",
        3 => "Request",
        4 => "Confirm",
        5 => "Renew",
        6 => "Rebind",
        7 => "Reply",
        8 => "Release",
        9 => "Decline",
        10 => "Reconfigure",
        11 => "Information-request",
        12 => "Relay-forward",
        13 => "Relay-reply",
        _ => "Unknown",
    }
}

fn dhcpv6_option_name(option: u16) -> &'static str {
    match option {
        1 => "Client identifier",
        2 => "Server identifier",
        3 => "Identity association",
        5 => "IA address",
        6 => "Option request",
        8 => "Elapsed time",
        14 => "Rapid commit",
        23 => "DNS recursive name server",
        24 => "Domain search list",
        25 => "Identity association for prefix delegation",
        _ => "DHCPv6 option",
    }
}

fn nd_option_name(option: u8) -> &'static str {
    match option {
        1 => "Source link-layer address",
        2 => "Target link-layer address",
        3 => "Prefix information",
        4 => "Redirected header",
        5 => "MTU",
        _ => "Neighbor Discovery option",
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

fn decode_dns_records(dns: &[u8], offset: usize, questions: u16, answers: u16, layer: &mut Layer) {
    let mut cursor = 12;
    for _ in 0..questions.min(64) {
        let Some((_, name_len)) = dns_name(dns, cursor) else {
            return;
        };
        let Some(next) = cursor
            .checked_add(name_len)
            .and_then(|next| next.checked_add(4))
        else {
            return;
        };
        if next > dns.len() {
            return;
        }
        cursor = next;
    }

    for index in 0..answers.min(64) {
        let Some((name, name_len)) = dns_name(dns, cursor) else {
            return;
        };
        let Some(fixed) = cursor.checked_add(name_len) else {
            return;
        };
        let Some(header) = dns.get(fixed..fixed + 10) else {
            return;
        };
        let kind = be_u16(header, 0).unwrap();
        let data_len = usize::from(be_u16(header, 8).unwrap());
        let data_start = fixed + 10;
        let Some(record_data) = dns.get(data_start..data_start + data_len) else {
            return;
        };
        let prefix = format!("Answer {}", index + 1);
        layer
            .fields
            .push(Field::new(format!("{prefix} name"), name).at(offset + cursor, name_len));
        layer.fields.push(
            Field::new(format!("{prefix} type"), dns_record_type(kind)).at(offset + fixed, 2),
        );
        layer.fields.push(
            Field::new(format!("{prefix} TTL"), be_u32(header, 4).unwrap() as u64)
                .at(offset + fixed + 4, 4),
        );
        let value = match kind {
            1 if data_len == 4 => {
                Ipv4Addr::from(<[u8; 4]>::try_from(record_data).unwrap()).to_string()
            }
            28 if data_len == 16 => {
                Ipv6Addr::from(<[u8; 16]>::try_from(record_data).unwrap()).to_string()
            }
            2 | 5 | 12 => dns_name(dns, data_start)
                .map(|(name, _)| name)
                .unwrap_or_else(|| format!("0x{}", encode_bytes(record_data))),
            15 if data_len >= 3 => {
                let exchange = dns_name(dns, data_start + 2)
                    .map(|(name, _)| name)
                    .unwrap_or_default();
                format!("{} {exchange}", be_u16(record_data, 0).unwrap())
            }
            16 => String::from_utf8_lossy(record_data).into_owned(),
            _ => format!("0x{}", encode_bytes(record_data)),
        };
        layer
            .fields
            .push(Field::new(format!("{prefix} data"), value).at(offset + data_start, data_len));
        cursor = data_start + data_len;
    }
}

fn decode_tls_client_hello(payload: &[u8], offset: usize, layer: &mut Layer) {
    let body_start = 9;
    let Some(session_len) = payload.get(body_start + 34).copied().map(usize::from) else {
        return;
    };
    let Some(cipher_len_offset) = (body_start + 35).checked_add(session_len) else {
        return;
    };
    let Some(cipher_len) = be_u16(payload, cipher_len_offset).map(usize::from) else {
        return;
    };
    let Some(compression_len_offset) = cipher_len_offset
        .checked_add(2)
        .and_then(|cursor| cursor.checked_add(cipher_len))
    else {
        return;
    };
    let Some(compression_len) = payload
        .get(compression_len_offset)
        .copied()
        .map(usize::from)
    else {
        return;
    };
    let Some(extensions_len_offset) = compression_len_offset
        .checked_add(1)
        .and_then(|cursor| cursor.checked_add(compression_len))
    else {
        return;
    };
    let Some(extensions_len) = be_u16(payload, extensions_len_offset).map(usize::from) else {
        return;
    };
    let Some(extensions_end) = extensions_len_offset
        .checked_add(2)
        .and_then(|cursor| cursor.checked_add(extensions_len))
        .filter(|end| *end <= payload.len())
    else {
        return;
    };
    let mut cursor = extensions_len_offset + 2;
    while cursor + 4 <= extensions_end {
        let kind = be_u16(payload, cursor).unwrap();
        let length = usize::from(be_u16(payload, cursor + 2).unwrap());
        let data_start = cursor + 4;
        let Some(data_end) = data_start
            .checked_add(length)
            .filter(|end| *end <= extensions_end)
        else {
            return;
        };
        let data = &payload[data_start..data_end];
        match kind {
            0 if data.len() >= 5 => {
                let list_len = usize::from(be_u16(data, 0).unwrap());
                if list_len + 2 <= data.len() {
                    let name_len = usize::from(be_u16(data, 3).unwrap());
                    if data[2] == 0
                        && let Some(name) = data.get(5..5 + name_len)
                    {
                        layer.fields.push(
                            Field::new("Server name", String::from_utf8_lossy(name).into_owned())
                                .at(offset + data_start + 5, name_len),
                        );
                    }
                }
            }
            16 if data.len() >= 3 => {
                let list_len = usize::from(be_u16(data, 0).unwrap());
                if list_len + 2 <= data.len() {
                    let protocol_len = usize::from(data[2]);
                    if let Some(protocol) = data.get(3..3 + protocol_len) {
                        layer.fields.push(
                            Field::new(
                                "Application protocol",
                                String::from_utf8_lossy(protocol).into_owned(),
                            )
                            .at(offset + data_start + 3, protocol_len),
                        );
                    }
                }
            }
            _ => {}
        }
        cursor = data_end;
    }
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
        assert_eq!(summarize_packet(&frame.raw_data, 1).protocol, "TLS");
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

    #[test]
    fn decodes_dhcpv6_options() {
        let payload = [
            1, 0x12, 0x34, 0x56, // Solicit and transaction ID
            0, 6, 0, 2, 0, 23, // Option request: DNS recursive name server
        ];
        let decoder = DhcpV6Decoder;
        let layer = decoder
            .decode(
                &payload,
                TransportInfo {
                    protocol: 17,
                    source_port: 546,
                    destination_port: 547,
                },
                8,
            )
            .unwrap();
        assert_eq!(layer.name, "DHCPv6");
        assert!(
            layer.fields.iter().any(|field| {
                field.name == "Message type" && field.value.to_string() == "Solicit"
            })
        );
        assert!(layer.fields.iter().any(|field| {
            field.name == "Option request" && field.value.to_string() == "DNS recursive name server"
        }));
    }

    #[test]
    fn decodes_vxlan_header_and_inner_ethernet() {
        let mut udp = vec![0; 8];
        udp[0..2].copy_from_slice(&40000_u16.to_be_bytes());
        udp[2..4].copy_from_slice(&4789_u16.to_be_bytes());
        let mut vxlan_payload = vec![0x08, 0, 0, 0, 0x12, 0x34, 0x56, 0];
        vxlan_payload.extend_from_slice(&[0; 12]);
        vxlan_payload.extend_from_slice(&0x0806_u16.to_be_bytes());
        vxlan_payload.extend_from_slice(&[0; 28]);
        let udp_length = (udp.len() + vxlan_payload.len()) as u16;
        udp[4..6].copy_from_slice(&udp_length.to_be_bytes());
        udp.extend_from_slice(&vxlan_payload);
        let mut frame = ipv4_frame(17, &udp);

        decode_frame(&mut frame, 1, &DecoderRegistry::new());

        assert!(
            frame
                .layers
                .iter()
                .any(|layer| layer.name == "Virtual eXtensible LAN")
        );
        assert!(frame.layers.iter().any(|layer| layer.name == "Ethernet II"));
        assert_eq!(frame.protocol, "ARP");
    }

    #[test]
    fn decodes_neighbor_discovery_target_and_link_layer_options() {
        let mut ndp = vec![0; 32];
        ndp[0] = 135;
        ndp[8..24].copy_from_slice(&[0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ndp[24..32].copy_from_slice(&[1, 1, 0, 1, 2, 3, 4, 5]);

        let decoded = decode_icmp(&ndp, 40, true).unwrap();

        assert_eq!(decoded.protocol, "NDP");
        assert_eq!(decoded.layer.name, "ICMPv6 Neighbor Discovery");
        assert!(decoded.layer.fields.iter().any(|field| {
            field.name == "Target address" && field.value.to_string() == "2001:db08::1"
        }));
        assert!(decoded.layer.fields.iter().any(|field| {
            field.name == "Source link-layer address"
                && field.value.to_string() == "00:01:02:03:04:05"
        }));
    }

    #[test]
    fn decodes_dns_answer_records_and_tls_client_hello_sni() {
        let mut dns = vec![0; 12];
        dns[0..2].copy_from_slice(&0x1234_u16.to_be_bytes());
        dns[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        dns[4..6].copy_from_slice(&1_u16.to_be_bytes());
        dns[6..8].copy_from_slice(&1_u16.to_be_bytes());
        dns.extend_from_slice(&[1, b'a', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        dns.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        dns.extend_from_slice(&60_u32.to_be_bytes());
        dns.extend_from_slice(&[0, 4, 192, 0, 2, 10]);
        let dns_layer = DnsDecoder
            .decode(
                &dns,
                TransportInfo {
                    protocol: 17,
                    source_port: 53,
                    destination_port: 40000,
                },
                42,
            )
            .unwrap();
        assert!(dns_layer.fields.iter().any(|field| {
            field.name == "Answer 1 data" && field.value.to_string() == "192.0.2.10"
        }));

        let mut hello = vec![22, 3, 3, 0, 0, 1, 0, 0, 0];
        hello.extend_from_slice(&[3, 3]);
        hello.extend_from_slice(&[0; 32]);
        hello.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
        let mut extensions = vec![0, 0, 0, 10, 0, 8, 0, 0, 5];
        extensions.extend_from_slice(b"a.com");
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);
        let record_length = (hello.len() - 5) as u16;
        hello[3..5].copy_from_slice(&record_length.to_be_bytes());
        let handshake_length = (hello.len() - 9) as u32;
        hello[6] = (handshake_length >> 16) as u8;
        hello[7] = (handshake_length >> 8) as u8;
        hello[8] = handshake_length as u8;
        let mut tls_layer = Layer::new("Transport Layer Security");
        decode_tls_client_hello(&hello, 100, &mut tls_layer);
        assert!(
            tls_layer
                .fields
                .iter()
                .any(|field| { field.name == "Server name" && field.value.to_string() == "a.com" })
        );
    }

    #[test]
    fn decodes_ssh_smtp_imap_and_gssapi_mechanism() {
        let cases = [
            (
                SshDecoder.decode(
                    b"SSH-2.0-OpenSSH_9.0\r\n",
                    TransportInfo {
                        protocol: 6,
                        source_port: 50_000,
                        destination_port: 22,
                    },
                    0,
                ),
                "Secure Shell",
            ),
            (
                SmtpDecoder.decode(
                    b"EHLO example.test\r\n",
                    TransportInfo {
                        protocol: 6,
                        source_port: 50_000,
                        destination_port: 25,
                    },
                    0,
                ),
                "Simple Mail Transfer Protocol",
            ),
            (
                ImapDecoder.decode(
                    b"A001 CAPABILITY\r\n",
                    TransportInfo {
                        protocol: 6,
                        source_port: 50_000,
                        destination_port: 143,
                    },
                    0,
                ),
                "Internet Message Access Protocol",
            ),
        ];
        for (layer, expected_name) in cases {
            assert_eq!(layer.unwrap().name, expected_name);
        }

        let oid = [
            0x60, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
        ];
        let layer = GssapiDecoder
            .decode(
                &oid,
                TransportInfo {
                    protocol: 6,
                    source_port: 389,
                    destination_port: 50_000,
                },
                12,
            )
            .unwrap();
        assert_eq!(layer.name, "Generic Security Services API");
        assert_eq!(layer.fields[0].value.to_string(), "Kerberos 5");
    }

    #[test]
    fn decodes_ntp_header_extensions_and_rejects_truncation() {
        let mut payload = vec![0; 52];
        payload[0] = 0x23;
        payload[1] = 2;
        payload[4..8].copy_from_slice(&0xffff_8000_u32.to_be_bytes());
        payload[16..20].copy_from_slice(&1_u32.to_be_bytes());
        payload[20..24].copy_from_slice(&2_u32.to_be_bytes());
        payload[48..50].copy_from_slice(&0x0102_u16.to_be_bytes());
        payload[50..52].copy_from_slice(&4_u16.to_be_bytes());
        let transport = TransportInfo {
            protocol: 17,
            source_port: 123,
            destination_port: 40_000,
        };
        let layer = NtpDecoder.decode(&payload, transport, 8).unwrap();

        assert!(
            layer
                .fields
                .iter()
                .any(|field| { field.name == "Version" && field.value.to_string() == "4" })
        );
        assert!(
            layer
                .fields
                .iter()
                .any(|field| { field.name == "Mode" && field.value.to_string() == "Client" })
        );
        assert!(
            layer.fields.iter().any(|field| {
                field.name == "Root delay" && field.value.to_string() == "-0.5000"
            })
        );
        assert!(layer.fields.iter().any(|field| {
            field.name == "Reference timestamp seconds" && field.value.to_string() == "1"
        }));
        assert!(
            layer.fields.iter().any(|field| {
                field.name == "Extension type" && field.value.to_string() == "258"
            })
        );
        assert!(NtpDecoder.decode(&payload[..47], transport, 8).is_none());
    }

    #[test]
    fn decodes_tftp_requests_data_and_rejects_incomplete_options() {
        let request = b"\0\x01firmware.bin\0octet\0blksize\01428\0";
        let transport = TransportInfo {
            protocol: 17,
            source_port: 40_000,
            destination_port: 69,
        };
        let layer = TftpDecoder.decode(request, transport, 8).unwrap();
        assert!(layer.fields.iter().any(|field| {
            field.name == "Filename" && field.value.to_string() == "firmware.bin"
        }));
        assert!(
            layer.fields.iter().any(|field| {
                field.name == "Transfer mode" && field.value.to_string() == "octet"
            })
        );
        assert!(
            layer.fields.iter().any(|field| {
                field.name == "Option: blksize" && field.value.to_string() == "1428"
            })
        );
        assert!(
            TftpDecoder
                .decode(b"\0\x01file\0octet\0blksize\0", transport, 8)
                .is_none()
        );

        let data = TftpDecoder
            .decode(b"\0\x03\0\x07abc", transport, 8)
            .unwrap();
        assert!(
            data.fields
                .iter()
                .any(|field| { field.name == "Block number" && field.value.to_string() == "7" })
        );
        assert!(
            data.fields
                .iter()
                .any(|field| field.name == "Data" && field.value.to_string() == "616263")
        );
    }

    #[test]
    fn decodes_sip_start_line_headers_and_content_length_body() {
        let payload = b"INVITE sip:a@example.test SIP/2.0\r\nVia: SIP/2.0/UDP host\r\nContent-Length: 4\r\nX-Trace: yes\r\n\r\ntestTRAIL";
        let transport = TransportInfo {
            protocol: 6,
            source_port: 40_000,
            destination_port: 5060,
        };
        let layer = SipDecoder.decode(payload, transport, 100).unwrap();
        assert!(
            layer
                .fields
                .iter()
                .any(|field| { field.name == "Method" && field.value.to_string() == "INVITE" })
        );
        assert!(layer.fields.iter().any(|field| {
            field.name == "Request URI" && field.value.to_string() == "sip:a@example.test"
        }));
        assert!(layer.fields.iter().any(|field| {
            field.name == "Header: Via" && field.value.to_string() == "SIP/2.0/UDP host"
        }));
        assert!(
            layer
                .fields
                .iter()
                .any(|field| { field.name == "Message body" && field.value.to_string() == "test" })
        );
        let truncated = b"OPTIONS sip:a@example.test SIP/2.0\r\nContent-Length: 6\r\n\r\nbody";
        assert!(SipDecoder.decode(truncated, transport, 100).is_none());
    }

    #[test]
    fn decodes_ftp_commands_and_server_responses() {
        let transport = TransportInfo {
            protocol: 6,
            source_port: 21,
            destination_port: 40_000,
        };
        let command = FtpDecoder
            .decode(b"RETR archive.tar\r\n", transport, 20)
            .unwrap();
        assert!(
            command
                .fields
                .iter()
                .any(|field| { field.name == "Command" && field.value.to_string() == "RETR" })
        );
        assert!(
            command.fields.iter().any(|field| {
                field.name == "Argument" && field.value.to_string() == "archive.tar"
            })
        );
        let response = FtpDecoder
            .decode(b"150 Opening data connection\r\n", transport, 20)
            .unwrap();
        assert!(
            response
                .fields
                .iter()
                .any(|field| { field.name == "Response code" && field.value.to_string() == "150" })
        );
    }

    #[test]
    fn decodes_ipv4_authentication_header_before_tcp() {
        let mut ah = vec![6, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2];
        let mut tcp = vec![0; 20];
        tcp[12] = 0x50;
        tcp.extend_from_slice(b"SSH-2.0-test\r\n");
        ah.extend_from_slice(&tcp);
        let mut frame = ipv4_frame(51, &ah);

        decode_frame(&mut frame, 1, &DecoderRegistry::new());

        assert!(
            frame
                .layers
                .iter()
                .any(|layer| layer.name == "Authentication Header")
        );
        assert_eq!(frame.protocol, "SSH");
    }
}
