use std::io::Error;

use crate::utils::mmap_reader::FromBytes;

pub struct BytesReader<'a> {
    bytes: &'a [u8],
}

impl<'a> BytesReader<'a> {
    pub fn new(buff: &'a [u8]) -> BytesReader<'a> {
        Self { bytes: buff }
    }

    pub fn read_slice<const N: usize>(&mut self) -> Result<&'a [u8; N], Error> {
        let (chunk, remaining) = self
            .bytes
            .split_first_chunk::<N>()
            .ok_or(Error::other("Cannot read 0..4 bytes from pcap header"))?;
        self.bytes = remaining;
        Ok(chunk)
    }

    pub fn read_as_le<T: FromBytes, const N: usize>(&mut self) -> Result<T, Error> {
        T::from_le_bytes_ptr(self.read_slice::<N>()?)
    }

    pub fn read_as_be<T: FromBytes, const N: usize>(&mut self) -> Result<T, Error> {
        T::from_be_bytes_ptr(self.read_slice::<N>()?)
    }
}
