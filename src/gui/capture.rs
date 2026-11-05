use std::{
    env,
    fs::File,
    io::{BufReader, Error, ErrorKind},
    path::{Path, PathBuf},
};

use analyzer::parser::{
    frame::Frame,
    pcap::{CaptureReader, CaptureSummary},
};

const MAX_INDEXED_PACKETS: usize = 100_000;

pub(super) struct Arguments {
    pub(super) capture: Option<PathBuf>,
    pub(super) plugins: Vec<PathBuf>,
    pub(super) plugin_directories: Vec<PathBuf>,
}

pub(super) struct CaptureData {
    pub(super) packets: Vec<CaptureSummary>,
    pub(super) total_packets: u64,
}

pub(super) fn load_capture(
    path: &Path,
    plugins: &[PathBuf],
    plugin_directories: &[PathBuf],
) -> Result<CaptureData, Error> {
    let mut reader = CaptureReader::from_reader(BufReader::new(File::open(path)?))?;
    for directory in plugin_directories {
        reader.decoders_mut().load_plugins_from_dir(directory)?;
    }
    for plugin in plugins {
        reader.decoders_mut().load_plugin(plugin)?;
    }
    let mut packets = Vec::new();
    let mut total_packets = 0;
    while let Some(packet) = reader.next_summary()? {
        total_packets += 1;
        if packets.len() < MAX_INDEXED_PACKETS {
            packets.push(packet);
        }
    }
    Ok(CaptureData {
        packets,
        total_packets,
    })
}

pub(super) fn load_frame(
    path: &Path,
    number: u64,
    plugins: &[PathBuf],
    plugin_directories: &[PathBuf],
) -> Result<Frame, Error> {
    let mut reader = CaptureReader::from_reader(BufReader::new(File::open(path)?))?;
    for directory in plugin_directories {
        reader.decoders_mut().load_plugins_from_dir(directory)?;
    }
    for plugin in plugins {
        reader.decoders_mut().load_plugin(plugin)?;
    }
    for _ in 1..number {
        reader.next_summary()?.ok_or_else(|| {
            Error::new(ErrorKind::UnexpectedEof, "selected packet no longer exists")
        })?;
    }
    reader
        .next_frame()?
        .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "selected packet no longer exists"))
}

pub(super) fn parse_arguments() -> Result<Option<Arguments>, Error> {
    let mut args = env::args().skip(1);
    let mut capture = None;
    let mut plugins = Vec::new();
    let mut plugin_directories = Vec::new();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "-h" | "--help" => {
                println!(
                    "Usage: gui [capture-file] [--plugin <library>]... [--plugins-dir <directory>]..."
                );
                return Ok(None);
            }
            "--plugin" => plugins
                .push(PathBuf::from(args.next().ok_or_else(|| {
                    Error::other("--plugin requires a library path")
                })?)),
            "--plugins-dir" => plugin_directories
                .push(PathBuf::from(args.next().ok_or_else(|| {
                    Error::other("--plugins-dir requires a directory path")
                })?)),
            _ if capture.is_none() => capture = Some(PathBuf::from(argument)),
            _ => return Err(Error::other("unexpected extra argument")),
        }
    }
    Ok(Some(Arguments {
        capture,
        plugins,
        plugin_directories,
    }))
}
