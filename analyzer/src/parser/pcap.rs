use std::{
    fmt::{self, Display, Formatter, Write},
    fs::File,
    io::{Error, ErrorKind, Read, Seek},
    str::FromStr,
};

use crate::parser::{frame::Frame, header::PCapHeader};

pub struct PCap<'a> {
    frames: Vec<Frame<'a>>,
    header: PCapHeader,
    size: u64,
}

impl<'a> PCap<'a> {
    pub fn new(filepath: &'a str) -> Result<PCap<'a>, Error> {
        let mut file = File::open(filepath)?;
        let size = file.seek(std::io::SeekFrom::End(0))?;
        let _ = file.seek(std::io::SeekFrom::Start(0));
        if size < 24 {
            Error::new(
                ErrorKind::InvalidInput,
                format!("The size of the header should be 24 but is {}", size),
            );
        }
        let mut buff: [u8; 1024] = [0; 1024];
        let _ = file.read(&mut buff)?;
        let header = buff.first_chunk::<24>().ok_or(ErrorKind::InvalidData)?;
        Ok(PCap {
            frames: Vec::new(),
            header: PCapHeader::new(header)?,
            size: size,
        })
    }

    pub fn get(&self, index: usize) -> Option<&Frame<'a>> {
        self.frames.get(index)
    }

    pub fn parse_next(&self) -> Option<&Frame<'a>> {
        None
    }
}

impl<'a> Display for PCap<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut string = String::from_str("PCap File\n").unwrap();
        writeln!(&mut string, "Size: {}", self.size)?;
        writeln!(&mut string, "Header: {}", self.header)?;
        writeln!(&mut string, "Frames:\n")?;
        for layer in self.frames.iter() {
            writeln!(
                &mut string,
                "{}",
                layer.to_string(&self.header.ts_format, &self.header.number_format)?
            )?;
        }
        f.write_str(&string)
    }
}
