use std::io::Error;

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
        String::new().parse::<u16>();
        self.bytes = remaining;
        Ok(chunk)
    }

    pub fn read_as<T: FromBytes, const N: usize>(&mut self) -> Result<T, Error> {
        T::from_le(self.read_slice::<N>()?)
    }
}

pub trait FromBytes: Sized {
    const SIZE: usize;
    fn from_le(bytes: &[u8]) -> Result<Self, Error>;
    fn from_be(bytes: &[u8]) -> Result<Self, Error>;
}

macro_rules! impl_from_bytes {
    ($($t:ty),*) => {$(
        impl FromBytes for $t {
            const SIZE: usize = std::mem::size_of::<$t>();
            fn from_le(b: &[u8]) -> Result<Self,Error> { Ok(Self::from_le_bytes(b.try_into().map_err(Error::other)?)) }
            fn from_be(b: &[u8]) -> Result<Self,Error> { Ok(Self::from_be_bytes(b.try_into().map_err(Error::other)?)) }
        }
    )*};
}

impl_from_bytes!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, f32, f64);
