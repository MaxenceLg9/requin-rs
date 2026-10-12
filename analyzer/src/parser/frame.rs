use std::{
    fmt::{Display, Formatter, Write},
    str::FromStr,
    time::Instant,
};

use crate::parser::{
    header::{NumberFormat, TsFormat},
    layer::Layer,
};

pub struct Frame<'a> {
    layers: Vec<Layer<'a>>,
    timestamp_seconds: u32,
    timestamp_2: u32,
}

impl<'a> Frame<'a> {
    pub fn to_string(
        &self,
        ts_format: &TsFormat,
        number_format: &NumberFormat,
    ) -> Result<String, std::fmt::Error> {
        let mut string = format!("Timestamp {}s", self.timestamp_seconds);
        match ts_format {
            TsFormat::Nano => writeln!(&mut string, "{}ns", self.timestamp_2)?,
            TsFormat::Micro => writeln!(&mut string, "{}ms", self.timestamp_2)?,
        };
        for layer in self.layers.iter() {}
        Ok(string)
    }
}
