use analyzer::parser::pcap::PCapStream;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

fn bench(c: &mut Criterion) {
    let mut pcap = PCapStream::new("rsasnakeoil2.cap").unwrap();

    let mut g = c.benchmark_group("parse");
    g.throughput(Throughput::Elements(57));
    g.bench_function("pcap+tcp", |b| {
        b.iter(|| {
            pcap.parse_next();
        })
    });
    g.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
