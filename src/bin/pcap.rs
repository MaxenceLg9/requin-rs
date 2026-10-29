use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use std::env;
use std::fs::File;
use std::io::Error;
use std::time::Instant;

pub fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err(Error::other("File missing"));
    }
    let filepath = args[1].as_str();
    let file = File::open(filepath).unwrap();
    let time = Instant::now();

    let mut num_blocks = 0;
    let mut reader = LegacyPcapReader::new(65536, file).expect("PcapNGReader");
    loop {
        match reader.next() {
            Ok((offset, _block)) => {
                num_blocks += 1;
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().unwrap();
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
    let now = Instant::now();
    let ns = now.duration_since(time).as_nanos();
    println!(
        "Read {} packets in {}ms, average of {}ns",
        num_blocks,
        ns / 1_000_000,
        ns as f64 / num_blocks as f64
    );
    Ok(())
}
