// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use dusk_bls12_381::BlsScalar;
use crate::circuit::{self, Circuit, VerifierData};
// Using prelude until PP is available on regular import path
use crate::constraint_system::StandardComposer;
use crate::fft::EvaluationDomain;
use crate::error::Error;
use crate::prelude::{PublicParameters, CommitKey};
use crate::proof_system::{Prover, Proof, ProverKey};
use alloc::vec::Vec;

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

fn padding_and_prepping(prover: &Prover) {
    let domain = EvaluationDomain::new(core::cmp::max(
        prover.cs.circuit_size(),
        prover.cs.lookup_table.0.len(),
    )).unwrap();

    // Since the caller is passing a pre-processed circuit
    // We assume that the Transcript has been seeded with the preprocessed
    // Commitments
    let mut transcript = prover.preprocessed_transcript.clone();

    // 1. Compute witness Polynomials
    //
    // Convert Variables to BlsScalars padding them to the
    // correct domain size.
    let pad = vec![BlsScalar::zero(); domain.size() - prover.cs.w_l.len()];
    let w_l_scalar = &[&prover.to_scalars(&prover.cs.w_l)[..], &pad].concat();
    let w_r_scalar = &[&prover.to_scalars(&prover.cs.w_r)[..], &pad].concat();
    let w_o_scalar = &[&prover.to_scalars(&prover.cs.w_o)[..], &pad].concat();
    let w_4_scalar = &[&prover.to_scalars(&prover.cs.w_4)[..], &pad].concat();

    // make sure q_lookup is also the right size for constructing f
    let padded_q_lookup = [&prover.cs.q_lookup[..], &pad].concat();

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

    // Create a prover struct
    let mut prover = Prover::new(b"padding_prepping");

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

    prover.preprocess(&ck).unwrap();

    c.bench_function("Padding and Prepping Wires", |b| b.iter(|| padding_and_prepping(&prover)));

}
///
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench
}
criterion_main!(benches);