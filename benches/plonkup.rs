// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.
extern crate criterion;

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use dusk_bls12_381::BlsScalar;
use dusk_plonk::circuit::{self, Circuit, VerifierData};
// Using prelude until PP is available on regular import path
use dusk_plonk::constraint_system::StandardComposer;
use dusk_plonk::error::Error;
use dusk_plonk::prelude::{PublicParameters, CommitKey};
use dusk_plonk::proof_system::{Prover, Proof, ProverKey};

fn plonkup_preprocess(ck: &CommitKey, n: usize) {
    // Create a prover struct
    let mut prover = Prover::new(b"preprocessing");

    prover.mut_cs().lookup_table.insert_multi_mul(0, 3);

    let output = prover.mut_cs().lookup_table.lookup(
        BlsScalar::from(2),
        BlsScalar::from(3),
        BlsScalar::one(),
    );

    let two = prover.mut_cs()
        .add_witness_to_circuit_description(BlsScalar::from(2));
    let three = prover.mut_cs()
        .add_witness_to_circuit_description(BlsScalar::from(3));
    let result = prover.mut_cs()
        .add_witness_to_circuit_description(output.unwrap());
    let one = prover.mut_cs()
        .add_witness_to_circuit_description(BlsScalar::one());

    for i in 0..(n/2) {
        prover.mut_cs()
        .plookup_gate(two, three, result, Some(one), BlsScalar::one());

        prover.mut_cs().big_add(
            (BlsScalar::one(), two),
            (BlsScalar::one(), three),
            None,
            BlsScalar::zero(),
            Some(BlsScalar::zero()),
        );
    }

    prover.preprocess(ck).unwrap();
}

fn plonkup_preprocess_and_prove(ck: &CommitKey, n: usize) {
        // Create a prover struct
        let mut prover = Prover::new(b"proving");

        prover.mut_cs().lookup_table.insert_multi_mul(0, 3);
    
        let output = prover.mut_cs().lookup_table.lookup(
            BlsScalar::from(2),
            BlsScalar::from(3),
            BlsScalar::one(),
        );
    
        let two = prover.mut_cs()
            .add_witness_to_circuit_description(BlsScalar::from(2));
        let three = prover.mut_cs()
            .add_witness_to_circuit_description(BlsScalar::from(3));
        let result = prover.mut_cs()
            .add_witness_to_circuit_description(output.unwrap());
        let one = prover.mut_cs()
            .add_witness_to_circuit_description(BlsScalar::one());
    
        for i in 0..(n/2) {
            prover.mut_cs()
            .plookup_gate(two, three, result, Some(one), BlsScalar::one());
    
            prover.mut_cs().big_add(
                (BlsScalar::one(), two),
                (BlsScalar::one(), three),
                None,
                BlsScalar::zero(),
                Some(BlsScalar::zero()),
            );
        }
    
        let public_inputs = prover.mut_cs().construct_dense_pi_vec();
    
    prover.preprocess(&ck).unwrap();

    let proof = prover.prove(ck).unwrap();
}

fn bench(c: &mut Criterion) {
    let n = 2usize.pow(14);

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

    c.bench_function("Preprocessing", |b| b.iter(|| plonkup_preprocess(&ck, n)));

    c.bench_function("Proving", |b| b.iter(|| plonkup_preprocess_and_prove(&ck, n)));

}
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench
}
criterion_main!(benches);
