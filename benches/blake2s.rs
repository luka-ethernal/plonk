// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//

// Copyright (c) DUSK NETWORK. All rights reserved.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use dusk_bls12_381::BlsScalar;
use dusk_plonk::circuit::{self, Circuit, VerifierData};
// Using prelude until PP is available on regular import path
use dusk_plonk::constraint_system::StandardComposer;
use dusk_plonk::error::Error;
use dusk_plonk::prelude::{PublicParameters, CommitKey};
use dusk_plonk::proof_system::{Prover, Proof, ProverKey};

fn blake2s_preprocess(ck: &CommitKey, n: usize) {
    let mut prover = Prover::new(b"preprocessing");

    // 256 bits of zeros
    let message_bytes: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    // blake2s hash of 256-bits of zeros
    let hash_bytes: [u8; 32] = [
        0x32, 0x0b, 0x5e, 0xa9, 0x9e, 0x65, 0x3b, 0xc2, 0xb5, 0x93, 0xdb, 0x41, 0x30, 0xd1,
        0x0a, 0x4e, 0xfd, 0x3a, 0x0b, 0x4c, 0xc2, 0xe1, 0xa6, 0x67, 0x2b, 0x67, 0x8d, 0x71,
        0xdf, 0xbd, 0x33, 0xad,
    ];

    let mut message_vars = [prover.cs.zero_var; 32];
    for i in 0..32 {
        message_vars[i] = prover.cs.add_input(BlsScalar::from(message_bytes[i] as u64));
    }

    let hash_vars = prover.cs.blake2s_256(message_vars);

    prover.preprocess(ck).unwrap();
}

fn blake2s_prove(ck: &CommitKey, n: usize, prover: &mut Prover) {
    let proof = prover.prove(ck).unwrap();
}

fn bench(c: &mut Criterion) {
    let n = 2usize.pow(13);

    use std::fs::File;
    use std::io::Read;
    
    let mut f = File::open("setup2to17").unwrap();
    let mut setup_bytes = Vec::new();
    f.read_to_end(&mut setup_bytes).unwrap();

    let public_parameters = unsafe {
        PublicParameters::from_slice_unchecked(&setup_bytes)
    };

    // Commit Key
    let (ck, _) = public_parameters.trim(2*n).unwrap();

    c.bench_function("Blake2s preprocessing", |b| b.iter(|| blake2s_preprocess(&ck, n)));

    // Create a prover struct
    let mut prover = Prover::new(b"blake2s");
    prover.preprocess(&ck).unwrap();

    c.bench_function("Blake2s proving", |b| b.iter(|| blake2s_prove(&ck, n, &mut prover)));

}
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench
}
criterion_main!(benches);
