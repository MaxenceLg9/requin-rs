use std::{
    fmt::{self, Display, Formatter},
    fs::File,
    io::{Error, ErrorKind},
};

use crate::{
    parser::{frame::Frame, header::PCapHeader},
    utils::mmap_reader::MmapReader,
    utils::traits::FromBytes,
};
use memmap2::Mmap;

pub struct PCapStream<'a> {
    frames: Vec<Frame<'a>>,
    header: PCapHeader,
    reader: MmapReader,
}

impl<'a> PCapStream<'a> {
    pub fn new(filepath: &str) -> Result<PCapStream<'a>, Error> {
        let file = File::open(filepath)?;

        let map = unsafe { Mmap::map(&file)? }; // file must not be modified while mapped
        map.advise(memmap2::Advice::Sequential)?;
        let mut mmap_reader = MmapReader::new(map);

        Ok(PCapStream {
            frames: Vec::new(),
            header: Self::parse_header(&mut mmap_reader)?,
            reader: mmap_reader,
        })
    }

    fn parse_header(reader: &mut MmapReader) -> Result<PCapHeader, Error> {
        // let (ts_format, number_format) = PCapHeader::get_ts_format(reader.read_slice::<4>()?)?;
        // let major_version = reader.read_as_le::<u16, 2>()?;
        // let minor_version = reader.read_as_le::<u16, 2>()?;
        // let _ = reader.read_slice::<4>()?;
        // let _ = reader.read_slice::<4>()?;
        // let snap_len = reader.read_as_le::<u32, 4>()?;
        // let fcs = reader.read_slice::<2>()?;
        // let link_type = reader.read_as_le::<u16, 2>()?;

        let buffer = reader.read_slice::<24>()?;
        let (ts_format, number_format) = PCapHeader::get_ts_format(&buffer[0..4])?;

        let major_version = u16::from_be_bytes_ptr(&buffer[4..6])?;
        let minor_version = u16::from_be_bytes_ptr(&buffer[6..8])?;

        let snap_len = u32::from_be_bytes_ptr(&buffer[16..20])?;
        let fcs = &buffer[20..22];
        let link_type = u16::from_be_bytes_ptr(&buffer[22..24])?;
        Ok(PCapHeader {
            ts_format,
            number_format,
            major_version,
            minor_version,
            snap_len,
            link_type,
        })
    }

    pub fn get_header(&self) -> &PCapHeader {
        &self.header
    }

    pub fn parse_next(&mut self) -> Result<Frame<'a>, Error> {
        match self.header.number_format {
            super::header::NumberFormat::LittleEndian => self.parse_little_endian(),
            super::header::NumberFormat::BigEndian => self.parse_big_endian(),
        }
    }

    pub fn add_next(&mut self) -> Result<&Frame<'a>, Error> {
        let frame = match self.header.number_format {
            super::header::NumberFormat::LittleEndian => self.parse_little_endian(),
            super::header::NumberFormat::BigEndian => self.parse_big_endian(),
        };
        self.frames.push(frame?);
        self.frames
            .last()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "There is no last in the vector"))
    }

    fn parse_big_endian(&mut self) -> Result<Frame<'a>, Error> {
        // let buff = self.reader.read_slice::<16>().ok()?;
        let timestamp_seconds = self.reader.read_as_be::<u32, 4>()?;
        let timestamp_2 = self.reader.read_as_be::<u32, 4>()?;
        let captured_pkt_len = self.reader.read_as_be::<u32, 4>()?;
        let original_pkt_len = self.reader.read_as_be::<u32, 4>()?;
        Ok(Frame::new(
            &self.header,
            timestamp_seconds,
            timestamp_2,
            original_pkt_len,
            captured_pkt_len,
        ))
    }

    fn parse_little_endian(&mut self) -> Result<Frame<'a>, Error> {
        // let func = |buff: &[u8]| Some(u32::from_le_bytes(buff.try_into().ok()?));
        let timestamp_seconds = self.reader.read_as_le::<u32, 4>()?;
        let timestamp_2 = self.reader.read_as_le::<u32, 4>()?;
        let captured_pkt_len = self.reader.read_as_le::<u32, 4>()?;
        let original_pkt_len = self.reader.read_as_le::<u32, 4>()?;

        // let f_header = self.reader.read_slice::<16>()?;
        // let timestamp_seconds = func(&f_header[0..4])?;
        // let timestamp_2 = func(&f_header[4..8])?;
        // let captured_pkt_len = func(&f_header[8..12])?;
        // let original_pkt_len = func(&f_header[12..16])?;

        let _data = self
            .reader
            .read_raw(captured_pkt_len as usize)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "Cannot read"))?;
        Ok(Frame::new(
            &self.header,
            timestamp_seconds,
            timestamp_2,
            original_pkt_len,
            captured_pkt_len,
        ))
    }
}

impl<'a> Display for PCapStream<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("PCap File\n")?;
        writeln!(f, "Size: {}", self.reader.len())?;
        writeln!(f, "Header: {}", self.header)?;
        f.write_str("Frames:")?;
        for layer in self.frames.iter() {
            writeln!(f, "{}", layer)?;
        }
        fmt::Result::Ok(())
    }
}
