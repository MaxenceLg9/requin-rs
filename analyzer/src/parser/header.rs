use std::fmt::Write;
use std::{
    fmt::{self, Display, Formatter},
    io::{Error, ErrorKind},
    str::FromStr,
};

use crate::utils::byte_reader::BytesReader;
use crate::utils::mmap_reader::FromBytes;

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
    pub fn new(header: &[u8; 24]) -> Result<PCapHeader, Error> {
        let mut reader = BytesReader::new(header);
        if header.len() < 24 {
            Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "The size of the header should be 24 but is {}",
                    header.len()
                ),
            );
        }
        // let slice = reader.read_as_le::<u32, 4>()?;
        let slice = reader.read_slice::<4>()?;
        let (ts_format, number_format) = Self::get_ts_format(slice)?;
        let major_version = reader.read_as_le::<u16, 2>()?;
        let minor_version = reader.read_as_le::<u16, 2>()?;
        let _ = reader.read_slice::<4>()?;
        let snap_len = reader.read_as_le::<u32, 4>()?;
        let fcs = reader.read_slice::<2>()?;
        let link_type = reader.read_as_le::<u16, 2>()?;
        Ok(PCapHeader {
            ts_format,
            number_format,
            major_version,
            minor_version,
            snap_len,
            link_type,
        })
    }

    pub fn get_ts_format(bytes: &[u8]) -> Result<(TsFormat, NumberFormat), Error> {
        let ts_format_be: u32 = u32::from_be_bytes_ptr(bytes)?;
        let ts_format_le: u32 = u32::from_le_bytes_ptr(bytes)?;

        match ts_format_be {
            0xA1B23C4D => std::io::Result::Ok((TsFormat::Nano, NumberFormat::BigEndian)),
            0xA1B2C3D4 => Result::Ok((TsFormat::Micro, NumberFormat::BigEndian)),
            _ => match ts_format_le {
                0xA1B23C4D => Result::Ok((TsFormat::Nano, NumberFormat::LittleEndian)),
                0xA1B2C3D4 => Result::Ok((TsFormat::Micro, NumberFormat::LittleEndian)),
                _ => Err(Error::new(
                    ErrorKind::InvalidData,
                    "Cannot parse timestamp format of the header",
                )),
            },
        }
    }
}

impl Display for PCapHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut string = String::from_str("PCap Header\n").unwrap();
        match self.ts_format {
            TsFormat::Nano => writeln!(&mut string, "Timestamp format: seconds; nanoseconds")?,
            TsFormat::Micro => writeln!(&mut string, "Timestamp format: seconds; milliseconds")?,
        }
        match self.number_format {
            NumberFormat::LittleEndian => writeln!(&mut string, "Number format: LittleEndian")?,
            NumberFormat::BigEndian => writeln!(&mut string, "Number format: BigEndian")?,
        }
        writeln!(
            &mut string,
            "Version: {}.{}",
            self.major_version, self.minor_version
        )?;
        writeln!(&mut string, "SnapLen: {}", self.snap_len)?;
        writeln!(&mut string, "LinkType: {}", self.link_type)?;
        f.write_str(&string)
    }
}
