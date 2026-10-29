use std::{
    fmt::{self, Display, Formatter},
    io::{
        Error,
        ErrorKind::{self, InvalidData},
    },
};

use crate::utils::traits::FromBytes;

#[derive(Clone, Copy)]
pub enum TsFormat {
    Nano,
    Micro,
}

#[derive(Clone, Copy)]
pub enum NumberFormat {
    BigEndian,
    LittleEndian,
}

pub struct PCapHeader {
    pub ts_format: TsFormat,
    pub number_format: NumberFormat,
    pub major_version: u16,
    pub minor_version: u16,
    pub snap_len: u32,
    pub link_type: u16,
}

impl PCapHeader {
    pub fn get_ts_format(bytes: &[u8]) -> Result<(TsFormat, NumberFormat), Error> {
        let ts_format_be: u32 = u32::from_be_bytes_ptr(bytes).expect("AA");
        let ts_format_le: u32 = u32::from_le_bytes_ptr(bytes).expect("BB");

        match ts_format_be {
            0xA1B23C4D => Ok((TsFormat::Nano, NumberFormat::BigEndian)),
            0xA1B2C3D4 => Ok((TsFormat::Micro, NumberFormat::BigEndian)),
            _ => match ts_format_le {
                0xA1B23C4D => Ok((TsFormat::Nano, NumberFormat::LittleEndian)),
                0xA1B2C3D4 => Ok((TsFormat::Micro, NumberFormat::LittleEndian)),
                _ => Err(Error::new(InvalidData, "Cannot parse the format")),
            },
        }
    }
}

impl Display for PCapHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("PCap Header\n")?;
        match self.ts_format {
            TsFormat::Nano => f.write_str("Timestamp format: seconds; nanoseconds\n")?,
            TsFormat::Micro => f.write_str("Timestamp format: seconds; microseconds\n")?,
        }
        match self.number_format {
            NumberFormat::LittleEndian => f.write_str("Number format: LittleEndian\n")?,
            NumberFormat::BigEndian => f.write_str("Number format: BigEndian\n")?,
        }
        writeln!(f, "Version: {}.{}", self.major_version, self.minor_version)?;
        writeln!(f, "SnapLen: {}", self.snap_len)?;
        writeln!(f, "LinkType: {}", self.link_type)
    }
}
