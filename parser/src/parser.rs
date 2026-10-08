use std::{fs::File, io::Error, time::Instant};

struct PCap<'a> {
    layers: Vec<Layer<'a>>,
}

struct Frame<'a> {
    layers: Vec<Layer<'a>>,
    timestamp: Instant,
}

struct Layer<'a> {
    name: &'static str,
    metadatas: Vec<Metadata<'a>>,
}

struct Metadata<'a> {
    name: &'static str,
    data: &'a [u8],
}

fn read_pcap(filepath: &'static str) -> Result<PCap, Error> {
    let file = File::open(filepath)?;

    Ok(PCap { layers: Vec::new() })
}
