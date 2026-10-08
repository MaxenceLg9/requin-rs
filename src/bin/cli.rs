use rtshark;
use std::env;
use std::io::Error;

fn main() {
    let args: Vec<String> = env::args().collect();
    let filepath = args[1].as_str();
    // let cert_path = args[2].as_str();
    // Creates a builder with needed tshark parameters
    //
    // Creates a builder with needed tshark parameters
    let builder = rtshark::RTSharkBuilder::builder().input_path(filepath);

    // Start a new TShark process
    let mut rtshark = match builder.spawn() {
        Err(err) => {
            eprintln!("Error running tshark: {err}");
            return;
        }
        Ok(rtshark) => rtshark,
    };

    // read packets until the end of the PCAP file
    while let Some(packet) = rtshark.read().unwrap_or_else(|e| {
        eprintln!("Error parsing TShark output: {e}");
        None
    }) {
        for layer in packet {
            println!("Layer: {}", layer.name());
            for metadata in layer {
                println!("\t{} : {}", metadata.name(), metadata.value());
            }
        }
    }
}
