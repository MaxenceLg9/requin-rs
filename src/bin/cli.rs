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
            Ok(_frame) => {
                // writeln!(out, "{}", frame)?;
                i += 1;
            }
            Err(e) => {
                let now = Instant::now();
                let ns = now.duration_since(time).as_nanos();
                println!("Got error {}, returning", e);
                println!(
                    "Read {} packets in {}ns, average of {}ns",
                    i,
                    ns,
                    ns as f64 / i as f64
                );
                break;
            }
        }
    }

    out.flush()?;
    // PcapNGReader
    Ok(())
}
