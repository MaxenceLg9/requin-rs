use std::{
    fs::File,
    io::{
        Error,
        ErrorKind::{self, InvalidInput},
        Read, Seek,
    },
};

use memmap2::Mmap;

use crate::utils::traits::FromBytes;

pub struct FileReader {
    buffer: Vec<u8>,
    file: File,
    index: usize,
    len: usize,
}

impl FileReader {
    pub fn new(mut file: File) -> Result<FileReader, Error> {
        let mut buffer = Vec::new();
        buffer.resize(2_usize.pow(27), 0);
        file.read(&mut buffer)?;
        let len = file.seek(std::io::SeekFrom::End(0))? as usize;
        Ok(Self {
            buffer,
            file,
            index: 0,
            len,
        })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    fn read(&mut self) {
        self.file.read(&mut self.buffer);
    }

    pub fn get_slice<const N: usize>(&self, index: usize) -> Option<&[u8; N]> {
        self.buffer.get(index..index + N)?.try_into().ok()
    }

    pub fn read_slice<const N: usize>(&mut self) -> Option<&[u8; N]> {
        if self.len() - self.index < N {
            return None;
        }
        // println!("Len {}", self.buffer.len());
        let chunk = self.buffer.get(self.index..)?.first_chunk::<N>()?;
        self.index += N;

        Some(chunk)
    }

    pub fn read_raw(&mut self, n: usize) -> Option<&[u8]> {
        let temp = self.buffer.get(self.index..self.index + n);
        self.index += n;
        temp
    }

    pub fn reset(&mut self) {
        self.index = 24
    }

    pub fn read_as_le<T: FromBytes, const N: usize>(&mut self) -> Option<T> {
        T::from_le_bytes_ptr(self.read_slice::<N>()?)
    }

    pub fn read_as_be<T: FromBytes, const N: usize>(&mut self) -> Option<T> {
        T::from_be_bytes_ptr(self.read_slice::<N>()?)
    }
}
