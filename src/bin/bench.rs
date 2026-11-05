use analyzer::{parser::pcap::CaptureReader, proto::summarize_packet};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::io::Cursor;

const CAPTURE: &[u8] = include_bytes!("../../rsasnakeoil2.cap");

fn bench(c: &mut Criterion) {
    let mut preload = CaptureReader::from_reader(Cursor::new(CAPTURE)).unwrap();
    let link_type = preload.pcap_header().unwrap().link_type;
    let mut packets = Vec::new();
    while let Some(frame) = preload.next_frame().unwrap() {
        packets.push(frame.raw_data);
    }

    let mut capture = CaptureReader::from_reader(Cursor::new(CAPTURE)).unwrap();
    let mut summary_capture = CaptureReader::from_reader(Cursor::new(CAPTURE)).unwrap();
    let mut packet_index = 0;

    let mut g = c.benchmark_group("parse");
    g.throughput(Throughput::Elements(1));
    g.bench_function("packet-list-summary", |b| {
        b.iter(|| {
            let summary = summarize_packet(&packets[packet_index], link_type);
            packet_index = (packet_index + 1) % packets.len();
            std::hint::black_box(summary);
        })
    });
    g.bench_function("pcap-stream-summary", |b| {
        b.iter(|| {
            let summary = summary_capture.next_summary().unwrap();
            if summary.is_none() {
                summary_capture = CaptureReader::from_reader(Cursor::new(CAPTURE)).unwrap();
            }
            std::hint::black_box(summary);
        })
    });
    g.bench_function("pcap-frame-decode", |b| {
        b.iter(|| {
            let frame = capture.next_frame().unwrap();
            if frame.is_none() {
                capture = CaptureReader::from_reader(Cursor::new(CAPTURE)).unwrap();
            }
            std::hint::black_box(frame);
        })
    });
    g.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
