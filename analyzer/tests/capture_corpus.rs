use std::{
    collections::BTreeMap,
    fs,
    io::{Error, ErrorKind},
    path::{Path, PathBuf},
};

use analyzer::parser::pcap::CaptureReader;

fn capture_files(directory: &Path) -> Vec<PathBuf> {
    let mut files = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()))
        .map(|entry| entry.expect("cannot read capture directory entry").path())
        .filter(|path| {
            path.is_file()
                && path.extension().is_some_and(|extension| {
                    matches!(extension.to_str(), Some("pcap" | "pcapng" | "cap"))
                })
        })
        .collect::<Vec<_>>();
    files.sort();
    files
}

fn parse_expectations(path: &Path) -> Result<BTreeMap<String, u64>, Error> {
    let text = fs::read_to_string(path)?;
    let mut expectations = BTreeMap::new();
    for (line_number, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                format!("{}:{}: expected key=value", path.display(), line_number + 1),
            )
        })?;
        let value = value.trim().parse::<u64>().map_err(|error| {
            Error::new(
                ErrorKind::InvalidData,
                format!("{}:{}: {error}", path.display(), line_number + 1),
            )
        })?;
        expectations.insert(key.trim().to_owned(), value);
    }
    Ok(expectations)
}

#[test]
fn supplied_capture_corpus_matches_sidecar_expectations() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/captures");
    for capture_path in capture_files(&directory) {
        let expectation_path = capture_path.with_extension("expect");
        let expectations = parse_expectations(&expectation_path).unwrap_or_else(|error| {
            panic!(
                "missing or invalid expectations for {}: {error}",
                capture_path.display()
            )
        });
        let file = fs::File::open(&capture_path).expect("cannot open supplied capture");
        let mut reader = CaptureReader::from_reader(file).expect("cannot parse capture header");
        let mut frame_count = 0;
        let mut protocols = BTreeMap::<String, u64>::new();
        while let Some(summary) = reader.next_summary().expect("capture parse failed") {
            frame_count += 1;
            *protocols
                .entry(summary.packet.protocol.to_owned())
                .or_default() += 1;
        }
        assert_eq!(
            expectations.get("frames"),
            Some(&frame_count),
            "{} frame count",
            capture_path.display()
        );
        for (key, expected) in &expectations {
            if let Some(protocol) = key.strip_prefix("protocol.") {
                assert_eq!(
                    protocols.get(protocol).copied().unwrap_or_default(),
                    *expected,
                    "{} protocol {protocol}",
                    capture_path.display()
                );
            }
        }
    }
}
