use analyzer::parser::pcap::PCapStream;
use std::env;
use std::io::Write;
use std::io::{BufWriter, Error};
use std::time::Instant;

fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err(Error::other("File missing"));
    }
    let filepath = args[1].as_str();

    let mut pcap = PCapStream::new(filepath)?;
    println!("{}", pcap);
    let time = Instant::now();

    let stdout = std::io::stdout().lock();
    let mut out = BufWriter::new(stdout);
    let mut i = 0;
    loop {
        match pcap.parse_next() {
            Some(_frame) => {
                // writeln!(out, "{}", frame)?;
                i += 1;
            }
            None => {
                pcap.reset();
                if i > 100 {
                    break;
                }
            }
        }
    }
    let now = Instant::now();
    let ns = now.duration_since(time).as_nanos();
    println!(
        "Read {} packets in {}ms, average of {}ns",
        i,
        ns / 1_000_000,
        ns as f64 / i as f64
    );
    out.flush()?;
    // PcapNGReader
    Ok(())
}
