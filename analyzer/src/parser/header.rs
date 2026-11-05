use std::fmt::{self, Display, Formatter};
use std::io::{Error, ErrorKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TsFormat {
    Nano,
    Micro,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NumberFormat {
    BigEndian,
    LittleEndian,
}

impl NumberFormat {
    pub(crate) fn read_u16(self, bytes: &[u8]) -> Option<u16> {
        let bytes: [u8; 2] = bytes.get(..2)?.try_into().ok()?;
        Some(match self {
            Self::BigEndian => u16::from_be_bytes(bytes),
            Self::LittleEndian => u16::from_le_bytes(bytes),
        })
    }

    pub(crate) fn read_u32(self, bytes: &[u8]) -> Option<u32> {
        let bytes: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
        Some(match self {
            Self::BigEndian => u32::from_be_bytes(bytes),
            Self::LittleEndian => u32::from_le_bytes(bytes),
        })
    }
}

#[derive(Clone, Debug)]
pub struct PCapHeader {
    pub ts_format: TsFormat,
    pub number_format: NumberFormat,
    pub major_version: u16,
    pub minor_version: u16,
    pub snap_len: u32,
    pub link_type: u16,
}

impl PCapHeader {
    pub fn parse(bytes: &[u8; 24]) -> Result<Self, Error> {
        let (ts_format, number_format) = match &bytes[..4] {
            [0xa1, 0xb2, 0xc3, 0xd4] => (TsFormat::Micro, NumberFormat::BigEndian),
            [0xd4, 0xc3, 0xb2, 0xa1] => (TsFormat::Micro, NumberFormat::LittleEndian),
            [0xa1, 0xb2, 0x3c, 0x4d] => (TsFormat::Nano, NumberFormat::BigEndian),
            [0x4d, 0x3c, 0xb2, 0xa1] => (TsFormat::Nano, NumberFormat::LittleEndian),
            _ => return Err(Error::new(ErrorKind::InvalidData, "invalid pcap magic")),
        };
        let version = |start| number_format.read_u16(&bytes[start..]).unwrap();
        let snap_len = number_format.read_u32(&bytes[16..]).unwrap();
        let link_type = number_format.read_u32(&bytes[20..]).unwrap();
        let link_type = u16::try_from(link_type & 0xffff)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "unsupported pcap link type"))?;

        if snap_len == 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "pcap snap length is zero",
            ));
        }

        Ok(Self {
            ts_format,
            number_format,
            major_version: version(4),
            minor_version: version(6),
            snap_len,
            link_type,
        })
    }

    pub fn get_ts_format(bytes: &[u8]) -> Option<(TsFormat, NumberFormat)> {
        let bytes: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
        match bytes {
            [0xa1, 0xb2, 0xc3, 0xd4] => Some((TsFormat::Micro, NumberFormat::BigEndian)),
            [0xd4, 0xc3, 0xb2, 0xa1] => Some((TsFormat::Micro, NumberFormat::LittleEndian)),
            [0xa1, 0xb2, 0x3c, 0x4d] => Some((TsFormat::Nano, NumberFormat::BigEndian)),
            [0x4d, 0x3c, 0xb2, 0xa1] => Some((TsFormat::Nano, NumberFormat::LittleEndian)),
            _ => None,
        }
    }
}

impl Display for PCapHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "PCAP Header")?;
        writeln!(
            f,
            "Timestamp format: {}",
            match self.ts_format {
                TsFormat::Nano => "nanoseconds",
                TsFormat::Micro => "microseconds",
            }
        )?;
        writeln!(f, "Byte order: {:?}", self.number_format)?;
        writeln!(f, "Version: {}.{}", self.major_version, self.minor_version)?;
        writeln!(f, "Snap length: {}", self.snap_len)?;
        write!(f, "Link type: {}", self.link_type)
    }
}
