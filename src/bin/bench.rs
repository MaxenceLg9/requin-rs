use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

fn bench(c: &mut Criterion) {
    let file = std::fs::File::open("capture.pcap").unwrap();
    let map = unsafe { memmap2::Mmap::map(&file).unwrap() };
    let n = open_records(&map).unwrap().count() as u64;

    let mut g = c.benchmark_group("parse");
    g.throughput(Throughput::Elements(n));
    g.bench_function("pcap+tcp", |b| {
        b.iter(|| {
            for (_, _, frame) in open_records(&map).unwrap() {
                black_box(parse_frame(frame));
            }
        })
    });
    g.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
