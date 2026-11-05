use analyzer::parser::pcap::PCapStream;
use std::{
    env,
    io::{self, BufWriter, Error, Write},
    time::Instant,
};

fn main() -> Result<(), Error> {
    let mut filepath = None;
    let mut text_output = false;
    let mut plugins = Vec::new();
    let mut plugin_directories = Vec::new();
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--text" | "-t" => text_output = true,
            "--help" | "-h" => {
                println!(
                    "Usage: cli [--text] [--plugin <library>]... [--plugins-dir <directory>] <capture-file>"
                );
                return Ok(());
            }
            "--plugin" => plugins.push(
                arguments
                    .next()
                    .ok_or_else(|| Error::other("--plugin requires a library path"))?,
            ),
            "--plugins-dir" => plugin_directories.push(
                arguments
                    .next()
                    .ok_or_else(|| Error::other("--plugins-dir requires a directory path"))?,
            ),
            _ if filepath.is_none() => filepath = Some(argument),
            _ => return Err(Error::other("unexpected extra argument")),
        }
    }
    let filepath = filepath.ok_or_else(|| Error::other("capture file missing"))?;
    let mut capture = PCapStream::new(&filepath)?;
    for directory in plugin_directories {
        let loaded = capture.load_plugins_from_dir(&directory)?;
        eprintln!("Loaded {loaded} plugin(s) from {directory}");
    }
    for plugin in plugins {
        capture.load_plugin(&plugin)?;
        eprintln!("Loaded plugin {plugin}");
    }
    let start = Instant::now();
    let mut count = 0_u64;

    if text_output {
        let stdout = io::stdout().lock();
        let mut output = BufWriter::new(stdout);
        while capture
            .with_next_frame(|frame| writeln!(output, "{frame}"))?
            .transpose()?
            .is_some()
        {
            count += 1;
        }
        output.flush()?;
    } else {
        while capture.parse_next_summary()?.is_some() {
            count += 1;
        }
    }

    let elapsed = start.elapsed();
    let average_ns = if count == 0 {
        0.0
    } else {
        elapsed.as_nanos() as f64 / count as f64
    };
    eprintln!(
        "Read {count} packets in {}ms, average of {average_ns:.1}ns",
        elapsed.as_millis()
    );
    Ok(())
}
