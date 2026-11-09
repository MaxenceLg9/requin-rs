use analyzer::{
    parser::pcap::CaptureSummary,
    proto::{Address, PacketSummary},
};

#[derive(Clone, Debug)]
pub(super) enum FilterExpr {
    Protocol(String),
    Compare(String, FilterComparison, String),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Not(Box<Self>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FilterComparison {
    Equal,
    NotEqual,
    Greater,
    GreaterOrEqual,
    Less,
    LessOrEqual,
    Contains,
}

impl FilterExpr {
    pub(super) fn matches(&self, summary: &CaptureSummary) -> bool {
        match self {
            Self::Protocol(protocol) => protocol_matches(protocol, summary.packet),
            Self::Compare(field, comparison, value) => {
                let actual = filter_field_value(field, summary);
                compare_filter_values(actual.as_deref(), *comparison, value)
            }
            Self::And(left, right) => left.matches(summary) && right.matches(summary),
            Self::Or(left, right) => left.matches(summary) || right.matches(summary),
            Self::Not(expression) => !expression.matches(summary),
        }
    }
}

enum FilterToken {
    Word(String),
    Comparison(FilterComparison),
    And,
    Or,
    Not,
    LeftParen,
    RightParen,
}

pub(super) struct FilterParser {
    tokens: Vec<FilterToken>,
    cursor: usize,
}

impl FilterParser {
    pub(super) fn parse(input: &str) -> Result<FilterExpr, String> {
        let tokens = tokenize_filter(input)?;
        if tokens.is_empty() {
            return Err("Enter a display filter or clear the field.".to_owned());
        }
        let mut parser = Self { tokens, cursor: 0 };
        let expression = parser.parse_or()?;
        if parser.cursor != parser.tokens.len() {
            return Err("Unexpected token at the end of the display filter.".to_owned());
        }
        Ok(expression)
    }

    fn parse_or(&mut self) -> Result<FilterExpr, String> {
        let mut expression = self.parse_and()?;
        while self.take_logic_or() {
            expression = FilterExpr::Or(Box::new(expression), Box::new(self.parse_and()?));
        }
        Ok(expression)
    }

    fn parse_and(&mut self) -> Result<FilterExpr, String> {
        let mut expression = self.parse_unary()?;
        while self.take_logic_and() {
            expression = FilterExpr::And(Box::new(expression), Box::new(self.parse_unary()?));
        }
        Ok(expression)
    }

    fn parse_unary(&mut self) -> Result<FilterExpr, String> {
        if matches!(self.tokens.get(self.cursor), Some(FilterToken::Not)) {
            self.cursor += 1;
            return Ok(FilterExpr::Not(Box::new(self.parse_unary()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<FilterExpr, String> {
        if matches!(self.tokens.get(self.cursor), Some(FilterToken::LeftParen)) {
            self.cursor += 1;
            let expression = self.parse_or()?;
            if !matches!(self.tokens.get(self.cursor), Some(FilterToken::RightParen)) {
                return Err("Missing closing parenthesis in display filter.".to_owned());
            }
            self.cursor += 1;
            return Ok(expression);
        }
        let Some(FilterToken::Word(field)) = self.tokens.get(self.cursor) else {
            return Err("Expected a protocol or field name.".to_owned());
        };
        let field = field.clone();
        self.cursor += 1;
        if let Some(FilterToken::Comparison(comparison)) = self.tokens.get(self.cursor) {
            let comparison = *comparison;
            self.cursor += 1;
            let Some(FilterToken::Word(value)) = self.tokens.get(self.cursor) else {
                return Err(format!("Expected a value after {field}."));
            };
            let value = value.clone();
            self.cursor += 1;
            if !known_filter_field(&field) {
                return Err(format!("Unknown filter field: {field}"));
            }
            Ok(FilterExpr::Compare(
                field.to_ascii_lowercase(),
                comparison,
                value,
            ))
        } else if field.eq_ignore_ascii_case("and") || field.eq_ignore_ascii_case("or") {
            Err(format!("Expected a protocol or field before {field}."))
        } else {
            Ok(FilterExpr::Protocol(field))
        }
    }

    fn take_logic_and(&mut self) -> bool {
        if matches!(self.tokens.get(self.cursor), Some(FilterToken::And)) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    fn take_logic_or(&mut self) -> bool {
        if matches!(self.tokens.get(self.cursor), Some(FilterToken::Or)) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }
}

fn tokenize_filter(input: &str) -> Result<Vec<FilterToken>, String> {
    let chars = input.chars().collect::<Vec<_>>();
    let mut tokens = Vec::new();
    let mut cursor = 0;
    while cursor < chars.len() {
        let character = chars[cursor];
        if character.is_whitespace() {
            cursor += 1;
            continue;
        }
        match character {
            '(' => {
                tokens.push(FilterToken::LeftParen);
                cursor += 1;
                continue;
            }
            ')' => {
                tokens.push(FilterToken::RightParen);
                cursor += 1;
                continue;
            }
            '"' | '\'' => {
                let quote = character;
                cursor += 1;
                let mut value = String::new();
                while cursor < chars.len() && chars[cursor] != quote {
                    if chars[cursor] == '\\' && cursor + 1 < chars.len() {
                        cursor += 1;
                    }
                    value.push(chars[cursor]);
                    cursor += 1;
                }
                if cursor == chars.len() {
                    return Err("Unterminated quoted value in display filter.".to_owned());
                }
                cursor += 1;
                tokens.push(FilterToken::Word(value));
                continue;
            }
            '&' if chars.get(cursor + 1) == Some(&'&') => {
                tokens.push(FilterToken::And);
                cursor += 2;
                continue;
            }
            '|' if chars.get(cursor + 1) == Some(&'|') => {
                tokens.push(FilterToken::Or);
                cursor += 2;
                continue;
            }
            '!' if chars.get(cursor + 1) == Some(&'=') => {
                tokens.push(FilterToken::Comparison(FilterComparison::NotEqual));
                cursor += 2;
                continue;
            }
            '!' => {
                tokens.push(FilterToken::Not);
                cursor += 1;
                continue;
            }
            '=' if chars.get(cursor + 1) == Some(&'=') => {
                tokens.push(FilterToken::Comparison(FilterComparison::Equal));
                cursor += 2;
                continue;
            }
            '>' | '<' => {
                let greater = character == '>';
                let equal = chars.get(cursor + 1) == Some(&'=');
                tokens.push(FilterToken::Comparison(match (greater, equal) {
                    (true, true) => FilterComparison::GreaterOrEqual,
                    (true, false) => FilterComparison::Greater,
                    (false, true) => FilterComparison::LessOrEqual,
                    (false, false) => FilterComparison::Less,
                }));
                cursor += if equal { 2 } else { 1 };
                continue;
            }
            _ => {}
        }
        let start = cursor;
        while cursor < chars.len()
            && !chars[cursor].is_whitespace()
            && !matches!(chars[cursor], '(' | ')' | '!' | '=' | '>' | '<' | '&' | '|')
        {
            cursor += 1;
        }
        if start == cursor {
            return Err(format!(
                "Unexpected character in display filter: {character}"
            ));
        }
        let word = chars[start..cursor].iter().collect::<String>();
        match word.to_ascii_lowercase().as_str() {
            "and" => tokens.push(FilterToken::And),
            "or" => tokens.push(FilterToken::Or),
            "not" => tokens.push(FilterToken::Not),
            "contains" => tokens.push(FilterToken::Comparison(FilterComparison::Contains)),
            _ => tokens.push(FilterToken::Word(word)),
        }
    }
    Ok(tokens)
}

fn known_filter_field(field: &str) -> bool {
    matches!(
        field.to_ascii_lowercase().as_str(),
        "protocol"
            | "frame.protocol"
            | "frame.number"
            | "frame.len"
            | "frame.cap_len"
            | "frame.time"
            | "eth.src"
            | "eth.dst"
            | "ip.src"
            | "ip.dst"
            | "ipv4.src"
            | "ipv4.dst"
            | "ipv6.src"
            | "ipv6.dst"
            | "ip.ttl"
            | "ipv6.hlim"
            | "tcp.port"
            | "tcp.srcport"
            | "tcp.dstport"
            | "tcp.seq"
            | "tcp.ack"
            | "tcp.flags"
            | "tcp.flags.fin"
            | "tcp.flags.syn"
            | "tcp.flags.reset"
            | "tcp.flags.push"
            | "tcp.flags.ack"
            | "tcp.flags.urg"
            | "tcp.flags.ece"
            | "tcp.flags.cwr"
            | "tcp.window_size"
            | "udp.port"
            | "udp.srcport"
            | "udp.dstport"
            | "udp.length"
            | "icmp.type"
            | "icmp.code"
            | "icmpv6.type"
            | "icmpv6.code"
            | "ndp.type"
            | "ndp.code"
            | "port"
    )
}

fn protocol_matches(filter: &str, packet: PacketSummary) -> bool {
    if packet.protocol.eq_ignore_ascii_case(filter)
        || packet
            .transport
            .is_some_and(|value| value.eq_ignore_ascii_case(filter))
    {
        return true;
    }
    match filter.to_ascii_lowercase().as_str() {
        "ip" | "ipv4" => {
            packet.protocol != "ARP" && matches!(packet.source, Some(Address::Ipv4(_)))
        }
        "ipv6" => matches!(packet.source, Some(Address::Ipv6(_))),
        "eth" => packet.source_mac.is_some(),
        _ => false,
    }
}

fn filter_field_value(field: &str, packet: &CaptureSummary) -> Option<String> {
    let summary = packet.packet;
    let value = match field {
        "protocol" | "frame.protocol" => summary.protocol.to_owned(),
        "frame.number" => packet.number.to_string(),
        "frame.len" => packet.original_len.to_string(),
        "frame.cap_len" => packet.captured_len.to_string(),
        "frame.time" => {
            format!(
                "{}.{:09}",
                packet.timestamp.as_secs(),
                packet.timestamp.subsec_nanos()
            )
        }
        "eth.src" => Address::Ethernet(summary.source_mac?).format(),
        "eth.dst" => Address::Ethernet(summary.destination_mac?).format(),
        "ip.src" | "ipv4.src" if summary.protocol != "ARP" => match summary.source? {
            Address::Ipv4(address) => Address::Ipv4(address).format(),
            _ => return None,
        },
        "ip.dst" | "ipv4.dst" if summary.protocol != "ARP" => match summary.destination? {
            Address::Ipv4(address) => Address::Ipv4(address).format(),
            _ => return None,
        },
        "ipv6.src" => match summary.source? {
            Address::Ipv6(address) => Address::Ipv6(address).format(),
            _ => return None,
        },
        "ipv6.dst" => match summary.destination? {
            Address::Ipv6(address) => Address::Ipv6(address).format(),
            _ => return None,
        },
        "ip.ttl" => summary.ip_ttl?.to_string(),
        "ipv6.hlim" => summary.ipv6_hop_limit?.to_string(),
        "tcp.port" if summary.transport == Some("TCP") => {
            return Some(format!(
                "{}\0{}",
                summary.source_port?, summary.destination_port?
            ));
        }
        "tcp.srcport" if summary.transport == Some("TCP") => summary.source_port?.to_string(),
        "tcp.dstport" if summary.transport == Some("TCP") => summary.destination_port?.to_string(),
        "tcp.seq" => summary.tcp_sequence?.to_string(),
        "tcp.ack" => summary.tcp_acknowledgment?.to_string(),
        "tcp.flags" => summary.tcp_flags?.to_string(),
        "tcp.flags.fin" => (summary.tcp_flags? & 0x01 != 0).to_string(),
        "tcp.flags.syn" => (summary.tcp_flags? & 0x02 != 0).to_string(),
        "tcp.flags.reset" => (summary.tcp_flags? & 0x04 != 0).to_string(),
        "tcp.flags.push" => (summary.tcp_flags? & 0x08 != 0).to_string(),
        "tcp.flags.ack" => (summary.tcp_flags? & 0x10 != 0).to_string(),
        "tcp.flags.urg" => (summary.tcp_flags? & 0x20 != 0).to_string(),
        "tcp.flags.ece" => (summary.tcp_flags? & 0x40 != 0).to_string(),
        "tcp.flags.cwr" => (summary.tcp_flags? & 0x80 != 0).to_string(),
        "tcp.window_size" => summary.tcp_window?.to_string(),
        "udp.port" if summary.transport == Some("UDP") => {
            return Some(format!(
                "{}\0{}",
                summary.source_port?, summary.destination_port?
            ));
        }
        "udp.srcport" if summary.transport == Some("UDP") => summary.source_port?.to_string(),
        "udp.dstport" if summary.transport == Some("UDP") => summary.destination_port?.to_string(),
        "udp.length" => summary.udp_length?.to_string(),
        "icmp.type" | "icmpv6.type" | "ndp.type" => summary.icmp_type?.to_string(),
        "icmp.code" | "icmpv6.code" | "ndp.code" => summary.icmp_code?.to_string(),
        "port" => {
            return Some(format!(
                "{}\0{}",
                summary.source_port?, summary.destination_port?
            ));
        }
        _ => return None,
    };
    Some(value)
}

fn compare_filter_values(
    actual: Option<&str>,
    comparison: FilterComparison,
    expected: &str,
) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    let values = actual.split('\0').collect::<Vec<_>>();
    if comparison == FilterComparison::NotEqual {
        return values
            .iter()
            .all(|value| !compare_one_filter_value(value, FilterComparison::Equal, expected));
    }
    values
        .iter()
        .any(|value| compare_one_filter_value(value, comparison, expected))
}

fn compare_one_filter_value(actual: &str, comparison: FilterComparison, expected: &str) -> bool {
    if let (Ok(actual_number), Ok(expected_number)) =
        (actual.parse::<f64>(), expected.parse::<f64>())
    {
        return match comparison {
            FilterComparison::Equal => actual_number == expected_number,
            FilterComparison::NotEqual => actual_number != expected_number,
            FilterComparison::Greater => actual_number > expected_number,
            FilterComparison::GreaterOrEqual => actual_number >= expected_number,
            FilterComparison::Less => actual_number < expected_number,
            FilterComparison::LessOrEqual => actual_number <= expected_number,
            FilterComparison::Contains => false,
        };
    }
    let actual_lower = actual.to_ascii_lowercase();
    let expected_lower = expected.to_ascii_lowercase();
    let ordering = actual_lower.cmp(&expected_lower);
    match comparison {
        FilterComparison::Equal => ordering.is_eq(),
        FilterComparison::NotEqual => !ordering.is_eq(),
        FilterComparison::Greater => ordering.is_gt(),
        FilterComparison::GreaterOrEqual => !ordering.is_lt(),
        FilterComparison::Less => ordering.is_lt(),
        FilterComparison::LessOrEqual => !ordering.is_gt(),
        FilterComparison::Contains => actual_lower.contains(&expected_lower),
    }
}

pub(super) fn previous_char_boundary(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())]
        .char_indices()
        .next_back()
        .map_or(0, |(index, _)| index)
}

pub(super) fn next_char_boundary(text: &str, offset: usize) -> usize {
    let offset = offset.min(text.len());
    text[offset..]
        .char_indices()
        .nth(1)
        .map_or(text.len(), |(index, _)| offset + index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_packet() -> CaptureSummary {
        CaptureSummary {
            number: 12,
            timestamp: std::time::Duration::from_secs(3),
            original_len: 128,
            captured_len: 96,
            link_type: 1,
            packet: analyzer::proto::PacketSummary {
                source: Some(Address::Ipv4([192, 0, 2, 1])),
                destination: Some(Address::Ipv4([198, 51, 100, 8])),
                source_mac: Some([0; 6]),
                destination_mac: Some([0; 6]),
                protocol: "HTTP",
                transport: Some("TCP"),
                ip_ttl: Some(64),
                ipv6_hop_limit: None,
                tcp_sequence: Some(44),
                tcp_acknowledgment: Some(72),
                tcp_flags: Some(0x1a),
                tcp_window: Some(8192),
                udp_length: None,
                icmp_type: None,
                icmp_code: None,
                source_port: Some(51_234),
                destination_port: Some(443),
            },
        }
    }

    #[test]
    fn display_filter_matches_protocol_path_and_header_fields() {
        let packet = sample_packet();
        let filter = FilterParser::parse("tcp.port == 443 and ip.src == 192.0.2.1").unwrap();
        assert!(filter.matches(&packet));

        let filter = FilterParser::parse("not dns and tcp.flags.syn == true").unwrap();
        assert!(filter.matches(&packet));

        let filter = FilterParser::parse("frame.len >= 128 && tcp.window_size == 8192").unwrap();
        assert!(filter.matches(&packet));
    }

    #[test]
    fn display_filter_reports_invalid_fields_and_syntax() {
        assert!(FilterParser::parse("tcp.unknown == 1").is_err());
        assert!(FilterParser::parse("(tcp.port == 443").is_err());
        assert!(FilterParser::parse("tcp.port = 443").is_err());
    }
}
