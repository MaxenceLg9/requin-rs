use std::fmt::Write;

use crate::parser::{
    header::{NumberFormat, PCapHeader, TsFormat},
    layer::Layer,
};

pub struct Frame<'a> {
    layers: Vec<Layer<'a>>,
    ts_format: TsFormat,
    number_format: NumberFormat,
    timestamp_seconds: u32,
    timestamp_2: u32,
    original_pkt_len: u32,
    captured_pkt_len: u32,
}

impl<'a> Frame<'a> {
    pub fn new(
        header: &PCapHeader,
        timestamp_seconds: u32,
        timestamp_2: u32,
        original_pkt_len: u32,
        captured_pkt_len: u32,
    ) -> Self {
        Self {
            ts_format: header.ts_format,
            number_format: header.number_format,
            layers: Vec::new(),
            timestamp_2,
            timestamp_seconds,
            original_pkt_len,
            captured_pkt_len,
        }
    }

    pub fn to_string(&self) -> Result<String, std::fmt::Error> {
        let mut string = format!("Timestamp {}s ", self.timestamp_seconds);
        match self.ts_format {
            TsFormat::Nano => writeln!(&mut string, "{}ns", self.timestamp_2)?,
            TsFormat::Micro => writeln!(&mut string, "{}ms", self.timestamp_2)?,
        };
        writeln!(
            &mut string,
            "Captured {}/{} bytes",
            self.captured_pkt_len, self.original_pkt_len
        )?;
        for layer in self.layers.iter() {}
        Ok(string)
    }
}
