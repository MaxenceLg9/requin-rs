use std::{
    fmt::{self, Display, Formatter, Write},
    fs::File,
    io::{Error, ErrorKind, Seek},
    str::FromStr,
};

use memmap2::Mmap;

use crate::{
    parser::{frame::Frame, header::PCapHeader},
    utils::mmap_reader::MmapReader,
};

pub struct PCapStream<'a> {
    frames: Vec<Frame<'a>>,
    header: PCapHeader,
    size: usize,
    reader: MmapReader,
    index: usize,
}

impl<'a> PCapStream<'a> {
    pub fn new(filepath: &str) -> Result<PCapStream<'a>, Error> {
        let file = File::open(filepath)?;

        let map = unsafe { Mmap::map(&file)? }; // file must not be modified while mapped
        let size = map.len();
        let mut mmap_reader = MmapReader::new(map);

        let header = mmap_reader.read_slice::<24>().ok_or_else(|| {
            Error::new(ErrorKind::InvalidData, "Cannot get 24 bytes for the header")
        })?;

        Ok(PCapStream {
            frames: Vec::new(),
            header: PCapHeader::new(header)
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Cannot parse header"))?,
            size,
            index: 24,
            reader: mmap_reader,
        })
    }

    pub fn get_header(&self) -> &PCapHeader {
        &self.header
    }

    pub fn parse_next(&mut self) -> Option<&Frame<'a>> {
        match self.header.number_format {
            super::header::NumberFormat::LittleEndian => self.parse_little_endian(),
            super::header::NumberFormat::BigEndian => self.parse_big_endian(),
        }
    }

    fn parse_big_endian(&mut self) -> Option<&Frame<'a>> {
        // let buff = self.reader.read_slice::<16>().ok()?;
        let timestamp_seconds = self.reader.read_as_be::<u32, 4>()?;
        let timestamp_2 = self.reader.read_as_be::<u32, 4>()?;
        let captured_pkt_len = self.reader.read_as_be::<u32, 4>()?;
        let original_pkt_len = self.reader.read_as_be::<u32, 4>()?;
        self.frames.push(Frame::new(
            &self.header,
            timestamp_seconds,
            timestamp_2,
            original_pkt_len,
            captured_pkt_len,
        ));
        self.frames.last()
    }

    fn parse_little_endian(&mut self) -> Option<&Frame<'a>> {
        let timestamp_seconds = self.reader.read_as_le::<u32, 4>()?;
        let timestamp_2 = self.reader.read_as_le::<u32, 4>()?;
        let captured_pkt_len = self.reader.read_as_le::<u32, 4>()?;
        let original_pkt_len = self.reader.read_as_le::<u32, 4>()?;

        let data = self.reader.read_raw(captured_pkt_len as usize)?;
        self.frames.push(Frame::new(
            &self.header,
            timestamp_seconds,
            timestamp_2,
            original_pkt_len,
            captured_pkt_len,
        ));
        self.frames.last()
    }
}

impl<'a> Display for PCapStream<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("PCap File\n")?;
        writeln!(f, "Size: {}", self.size)?;
        writeln!(f, "Header: {}", self.header)?;
        f.write_str("Frames:")?;
        for layer in self.frames.iter() {
            writeln!(f, "{}", layer)?;
        }
        fmt::Result::Ok(())
    }
}
