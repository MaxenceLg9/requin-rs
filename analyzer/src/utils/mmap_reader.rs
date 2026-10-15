use std::{
    io::{Error, ErrorKind},
    range::Range,
    slice::SliceIndex,
};

use memmap2::Mmap;

pub struct MmapReader {
    mmap: Mmap,
    index: usize,
}

impl MmapReader {
    pub fn new(mmap: Mmap) -> MmapReader {
        Self { mmap, index: 0 }
    }

    // pub fn get_slice<const N: usize>(&self, index: usize) -> Result<&[u8; N], Error> {
    //     self.mmap
    //         .get(index..index + N)
    //         .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Not enough data"))?
    //         .try_into()
    //         .map_err(|e| Error::other(e))
    // }

    pub fn get_slice<const N: usize>(&self, index: usize) -> Option<&[u8; N]> {
        self.mmap.get(index..index + N)?.try_into().ok()
    }

    // pub fn read_slice<const N: usize>(&mut self) -> Result<&[u8; N], Error> {
    //     self.index += N;
    //     let temp = self.get_slice::<N>(self.index - N);
    //     temp
    // }

    pub fn read_slice<const N: usize>(&mut self) -> Option<&[u8; N]> {
        self.index += N;
        let temp = self.get_slice::<N>(self.index - N);
        temp
    }

    pub fn read_raw(&mut self, n: usize) -> Option<&[u8]> {
        let temp = self.mmap.get(self.index..self.index + n);
        self.index += n;
        temp
    }

    //     pub fn read_as_le<T: FromBytes, const N: usize>(&mut self) -> Result<T, Error> {
    //         T::from_le_bytes_ptr(self.read_slice::<N>()?)
    //     }
    //
    //     pub fn read_as_be<T: FromBytes, const N: usize>(&mut self) -> Result<T, Error> {
    //         T::from_be_bytes_ptr(self.read_slice::<N>()?)
    //     }

    pub fn read_as_le<T: FromBytes, const N: usize>(&mut self) -> Option<T> {
        T::from_le_bytes_ptr(self.read_slice::<N>()?)
    }

    pub fn read_as_be<T: FromBytes, const N: usize>(&mut self) -> Option<T> {
        T::from_be_bytes_ptr(self.read_slice::<N>()?)
    }
}

// macro_rules! impl_from_bytes {
//     ($($t:ty),*) => {$(
//         impl FromBytes for $t {
//             const SIZE: usize = std::mem::size_of::<$t>();
//             fn from_le_bytes_ptr(b: &[u8]) -> Result<Self,Error> { Ok(Self::from_le_bytes(b.try_into().map_err(Error::other)?)) }
//             fn from_be_bytes_ptr(b: &[u8]) -> Result<Self,Error> { Ok(Self::from_be_bytes(b.try_into().map_err(Error::other)?)) }
//         }
//     )*};
// }

macro_rules! impl_from_bytes {
    ($($t:ty),*) => {$(
        impl FromBytes for $t {
            const SIZE: usize = std::mem::size_of::<$t>();
            fn from_le_bytes_ptr(b: &[u8]) -> Option<Self> { Some(Self::from_le_bytes(b.try_into().ok()?)) }
            fn from_be_bytes_ptr(b: &[u8]) -> Option<Self> { Some(Self::from_be_bytes(b.try_into().ok()?)) }
        }
    )*};
}

impl_from_bytes!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, f32, f64);
//
// pub trait FromBytes: Sized {
//     const SIZE: usize;
//     fn from_le_bytes_ptr(bytes: &[u8]) -> Result<Self, Error>;
//     fn from_be_bytes_ptr(bytes: &[u8]) -> Result<Self, Error>;
// }

pub trait FromBytes: Sized {
    const SIZE: usize;
    fn from_le_bytes_ptr(bytes: &[u8]) -> Option<Self>;
    fn from_be_bytes_ptr(bytes: &[u8]) -> Option<Self>;
}
