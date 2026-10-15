use std::fmt::{self, Display, Write};

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
}

impl<'a> Display for Frame<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Timestamp {}s ", self.timestamp_seconds)?;
        match self.ts_format {
            TsFormat::Nano => writeln!(f, "{}ns", self.timestamp_2)?,
            TsFormat::Micro => writeln!(f, "{}µs", self.timestamp_2)?,
        };
        writeln!(
            f,
            "Captured {}/{} bytes",
            self.captured_pkt_len, self.original_pkt_len
        )?;

        for layer in self.layers.iter() {}
        fmt::Result::Ok(())
    }
}
