use analyzer::parser::header::PCapHeader;
use analyzer::parser::pcap::PCapStream;
use rtshark;
use std::env;
use std::io::Error;
use std::time::Instant;

fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
    let filepath = args[1].as_str();

    let mut pcap = PCapStream::new(filepath)?;
    let time = Instant::now();
    println!("{}", pcap);
    println!("{}", pcap.parse_next().unwrap().to_string().unwrap());
    let mut i = 0;
    loop {
        match pcap.parse_next() {
            Some(frame) => {
                println!("{}", frame.to_string().unwrap());
                i += 1;
            }
            None => {
                let now = Instant::now();
                let ns = now.duration_since(time).as_nanos();
                println!("Got none returning");
                println!(
                    "Read {} packets in {}ns, average of {}",
                    i,
                    ns,
                    ns as f64 / i as f64
                );
                break;
            }
        }
    }
    // PcapNGReader
    Ok(())
}
