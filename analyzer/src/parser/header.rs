use std::fmt::Write;
use std::{
    fmt::{self, Display, Formatter},
    io::{Error, ErrorKind},
    str::FromStr,
};

use crate::utils::byte_reader::BytesReader;

pub struct PCapHeader {
    ts_nano: bool,
    major_version: u16,
    minor_version: u16,
    snap_len: u32,
    link_type: u16,
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
        let slice = reader.read_as::<u32, 4>()?;
        let ts_nano = match slice {
            0xA1B23C4D => true,
            0xA1B2C3D4 => false,
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "Magic bytes should be 0xA1B23C4D or 0xA1B2C3D4 but is {:x}",
                        slice
                    ),
                ));
            }
        };
        let major_version = reader.read_as::<u16, 2>()?;
        let minor_version = reader.read_as::<u16, 2>()?;
        let _ = reader.read_slice::<4>()?;
        let snap_len = reader.read_as::<u32, 4>()?;
        let fcs = reader.read_slice::<2>()?;
        let link_type = reader.read_as::<u16, 2>()?;
        Ok(PCapHeader {
            ts_nano,
            major_version,
            minor_version,
            snap_len,
            link_type,
        })
    }
}

impl Display for PCapHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut string = String::from_str("PCap Header\n").unwrap();
        match self.ts_nano {
            true => writeln!(&mut string, "Timestamp fmt: seconds + nanoseconds")?,
            false => writeln!(&mut string, "Timestamp fmt: seconds + milliseconds")?,
        }
        writeln!(
            &mut string,
            "Version {}.{}",
            self.major_version, self.minor_version
        )?;
        writeln!(&mut string, "SnapLen {}", self.snap_len)?;
        writeln!(&mut string, "LinkType {}", self.link_type)?;
        f.write_str(&string)
    }
}
