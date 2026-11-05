use std::{
    borrow::Cow,
    fmt::{self, Display, Formatter},
    time::Duration,
};

use crate::parser::layer::Layer;

#[derive(Clone, Debug)]
pub struct Frame {
    pub number: u64,
    pub timestamp: Duration,
    pub original_len: u32,
    pub captured_len: u32,
    pub link_type: u16,
    pub raw_data: Vec<u8>,
    pub layers: Vec<Layer>,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub protocol: Cow<'static, str>,
    pub info: String,
}

impl Frame {
    pub fn new(
        number: u64,
        timestamp: Duration,
        original_len: u32,
        link_type: u16,
        raw_data: Vec<u8>,
    ) -> Self {
        let captured_len = u32::try_from(raw_data.len()).unwrap_or(u32::MAX);
        Self {
            number,
            timestamp,
            original_len,
            captured_len,
            link_type,
            raw_data,
            layers: Vec::with_capacity(4),
            source: None,
            destination: None,
            protocol: Cow::Borrowed("Unknown"),
            info: String::new(),
        }
    }

    pub fn hex_ascii(&self) -> String {
        let mut output = String::with_capacity(self.raw_data.len().saturating_mul(4));
        for (row, chunk) in self.raw_data.chunks(16).enumerate() {
            use std::fmt::Write;
            let _ = write!(output, "{:08x}  ", row * 16);
            for byte in chunk {
                let _ = write!(output, "{byte:02x} ");
            }
            for _ in chunk.len()..16 {
                output.push_str("   ");
            }
            output.push_str(" |");
            for byte in chunk {
                output.push(if byte.is_ascii_graphic() || *byte == b' ' {
                    char::from(*byte)
                } else {
                    '.'
                });
            }
            output.push_str("|\n");
        }
        output
    }
}

impl Display for Frame {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Frame {}: {} bytes captured, {} bytes on wire",
            self.number, self.captured_len, self.original_len
        )?;
        writeln!(f, "Timestamp: {:?}", self.timestamp)?;
        writeln!(f, "Protocol: {}", self.protocol)?;
        if let Some(source) = &self.source {
            writeln!(f, "Source: {source}")?;
        }
        if let Some(destination) = &self.destination {
            writeln!(f, "Destination: {destination}")?;
        }
        if !self.info.is_empty() {
            writeln!(f, "Info: {}", self.info)?;
        }
        for layer in &self.layers {
            write!(f, "{layer}")?;
        }
        Ok(())
    }
}
