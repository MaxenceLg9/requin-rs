use std::io::{Error, ErrorKind};

macro_rules! impl_from_bytes {
    ($($t:ty),*) => {$(
        impl FromBytes for $t {
            const SIZE: usize = std::mem::size_of::<$t>();
            fn from_le_bytes_ptr(b: &[u8]) -> Option<Self> { Some(Self::from_le_bytes(b.try_into().ok()?)) }
            fn from_be_bytes_ptr(b: &[u8]) -> Option<Self> { Some(Self::from_be_bytes(b.try_into().ok()?)) }
            fn from_le_bytes_ptr_offset(bytes: &[u8], offset : usize) -> Option<Self> {
                let bytes : &[u8] = &bytes[offset..Self::SIZE + offset];
                Self::from_le_bytes_ptr(bytes)
            }
            fn from_be_bytes_ptr_offset(bytes: &[u8], offset : usize) -> Option<Self> {
                let bytes : &[u8] = &bytes[offset..Self::SIZE + offset];
                Self::from_be_bytes_ptr(bytes)
            }
        }
    )*};
}

impl_from_bytes!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, f32, f64);

pub trait FromBytes: Sized {
    const SIZE: usize;
    fn from_le_bytes_ptr(bytes: &[u8]) -> Option<Self>;
    fn from_be_bytes_ptr(bytes: &[u8]) -> Option<Self>;
    fn from_le_bytes_ptr_offset(bytes: &[u8], offset: usize) -> Option<Self>;
    fn from_be_bytes_ptr_offset(bytes: &[u8], offset: usize) -> Option<Self>;
}
