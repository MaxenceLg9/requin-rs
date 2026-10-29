use std::io::{
    Error,
    ErrorKind::{self, InvalidInput},
};

use memmap2::Mmap;

use crate::utils::traits::FromBytes;

pub struct MmapReader {
    mmap: Mmap,
    index: usize,
}

impl MmapReader {
    pub fn new(mmap: Mmap) -> MmapReader {
        Self { mmap, index: 0 }
    }

    pub fn len(&self) -> usize {
        self.mmap.len()
    }

    pub fn get_slice<const N: usize>(&self, index: usize) -> Option<&[u8; N]> {
        self.mmap.get(index..index + N)?.try_into().ok()
    }

    pub fn read_slice<const N: usize>(&mut self) -> Result<&[u8; N], Error> {
        if self.mmap.len() - self.index < N {
            return Err(Error::new(ErrorKind::NotFound, "Not enough data to read"));
        }
        let temp = self
            .mmap
            .get(self.index..self.index + N)
            .ok_or_else(|| Error::new(InvalidInput, "Cannot slice the array"))?
            .try_into()
            .map_err(|e| Error::other(format!("{}, {}, {}", file!(), line!(), e)));
        self.index += N;

        temp
    }

    pub fn read_raw(&mut self, n: usize) -> Option<&[u8]> {
        let temp = self.mmap.get(self.index..self.index + n);
        self.index += n;
        temp
    }

    pub fn reset(&mut self) {
        self.index = 24
    }

    pub fn read_as_le<T: FromBytes, const N: usize>(&mut self) -> Result<T, Error> {
        T::from_le_bytes_ptr(self.read_slice::<N>()?)
    }

    pub fn read_as_be<T: FromBytes, const N: usize>(&mut self) -> Result<T, Error> {
        T::from_be_bytes_ptr(self.read_slice::<N>()?)
    }
}
