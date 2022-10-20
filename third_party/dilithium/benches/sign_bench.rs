// Benchmarks for key generation and signing with Dilithium.
// cargo criterion --features std

extern crate core;
extern crate criterion;
extern crate dilithium;
extern crate rng256;

use core::time::Duration;
use criterion::*;
use dilithium::sign::SecKey;
use rng256::Rng256;

const SAMPLE_SIZE: usize = 1000;
const MEASUREMENT_TIME: Duration = Duration::from_secs(10);

fn bench_sk(c: &mut Criterion) {
    let mut rng = rng256::ThreadRng256 {};

    c.bench_function("gensk", |b| {
        b.iter_batched(
            || {},
            |_| {
                SecKey::gensk(&mut rng);
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_pk(c: &mut Criterion) {
    let mut rng = rng256::ThreadRng256 {};

    c.bench_function("genpk", |b| {
        b.iter_batched(
            || SecKey::gensk(&mut rng),
            |sk| {
                sk.genpk();
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_sign(c: &mut Criterion) {
    const MESSAGE_LENGTH: usize = 64;
    let mut rng = rng256::ThreadRng256 {};

    c.bench_function("sign", |b| {
        b.iter_batched(
            || {
                let sk = SecKey::gensk(&mut rng);
                let mut message = [0; MESSAGE_LENGTH];
                rng.fill_bytes(&mut message);
                (sk, message)
            },
            |(sk, message)| {
                sk.sign(&message);
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(SAMPLE_SIZE).measurement_time(MEASUREMENT_TIME);
    targets = bench_sk, bench_pk, bench_sign
}
criterion_main!(benches);
