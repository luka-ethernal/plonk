use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use dusk_bls12_381::BlsScalar;
use dusk_plonk::circuit::{self, Circuit, VerifierData};
// Using prelude until PP is available on regular import path
use dusk_plonk::constraint_system::{StandardComposer, blake2s_4bit::*};
use dusk_plonk::error::Error;
use dusk_plonk::prelude::{PublicParameters, CommitKey, OpeningKey};
use dusk_plonk::proof_system::{Prover, Proof, ProverKey, Verifier};

fn blake2s_prover_preprocess(ck: &CommitKey, n: usize) {
    let mut prover = Prover::new(b"prover_preprocessing");

    // generate blake2s 4-bit lookup table
    prover.cs.append_lookup_table(&generate_blake_table());

    // prover's secret preimage
    let preimage = BlsScalar::zero();

    // blake2s hash of 256-bits of zeros
    let hash_bytes: [u8; 64] = [
        0x32, 0x0b, 0x5e, 0xa9, 0x9e, 0x65, 0x3b, 0xc2, 0xb5, 0x93, 0xdb, 0x41, 0x30,
        0xd1, 0x0a, 0x4e, 0xfd, 0x3a, 0x0b, 0x4c, 0xc2, 0xe1, 0xa6, 0x67, 0x2b, 0x67,
        0x8d, 0x71, 0xdf, 0xbd, 0x33, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let hash = hash_bytes.iter().rev().fold(BlsScalar::zero(), |acc, x| BlsScalar::from(256)*acc + BlsScalar::from(*x as u64));
    
    prover.cs.blake2s_preimage(preimage, hash);

    prover.preprocess(ck).unwrap();
}

fn blake2s_verifier_preprocess(ck: &CommitKey) {
    let mut verifier = Verifier::new(b"verifier_preprocessing");

    // generate blake2s 4-bit lookup table
    verifier.cs.append_lookup_table(&generate_blake_table());

    // prover's secret preimage
    let preimage = BlsScalar::zero();

    // blake2s hash of 256-bits of zeros
    let hash_bytes: [u8; 64] = [
        0x32, 0x0b, 0x5e, 0xa9, 0x9e, 0x65, 0x3b, 0xc2, 0xb5, 0x93, 0xdb, 0x41, 0x30,
        0xd1, 0x0a, 0x4e, 0xfd, 0x3a, 0x0b, 0x4c, 0xc2, 0xe1, 0xa6, 0x67, 0x2b, 0x67,
        0x8d, 0x71, 0xdf, 0xbd, 0x33, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let hash = hash_bytes.iter().rev().fold(BlsScalar::zero(), |acc, x| BlsScalar::from(256)*acc + BlsScalar::from(*x as u64));
    
    verifier.cs.blake2s_preimage(preimage, hash);

    verifier.preprocess(ck).unwrap();
}

fn blake2s_prove(ck: &CommitKey, n: usize, prover: &mut Prover) {
    let proof = prover.prove(ck).unwrap();
}

fn blake2s_verify(proof: &Proof, vk: &OpeningKey, public_inputs: &[BlsScalar], verifier: &mut Verifier) {
    verifier.verify(proof, vk, public_inputs);
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
    let (ck, vk) = public_parameters.trim(n).unwrap();

    c.bench_function("Prover Preprocessing", |b| b.iter(|| blake2s_prover_preprocess(&ck, n)));

    // Create a prover struct
    let mut prover = Prover::new(b"blake2s");

    // prover's secret preimage
    let preimage = BlsScalar::zero();

    // blake2s hash of 256-bits of zeros
    let hash_bytes: [u8; 64] = [
        0x32, 0x0b, 0x5e, 0xa9, 0x9e, 0x65, 0x3b, 0xc2, 0xb5, 0x93, 0xdb, 0x41, 0x30,
        0xd1, 0x0a, 0x4e, 0xfd, 0x3a, 0x0b, 0x4c, 0xc2, 0xe1, 0xa6, 0x67, 0x2b, 0x67,
        0x8d, 0x71, 0xdf, 0xbd, 0x33, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let hash = hash_bytes.iter().rev().fold(BlsScalar::zero(), |acc, x| BlsScalar::from(256)*acc + BlsScalar::from(*x as u64));

    prover.cs.append_lookup_table(&generate_blake_table());

    prover.cs.blake2s_preimage(preimage, hash);

    prover.preprocess(&ck).unwrap();

    let public_inputs = prover.cs.construct_dense_pi_vec();

    let proof = prover.prove(&ck).unwrap();

    c.bench_function("Proving", |b| b.iter(|| blake2s_prove(&ck, n, &mut prover)));

    let mut verifier = Verifier::new(b"blake2s");

    // Add lookup table to the composer
    verifier.cs.append_lookup_table(&generate_blake_table());

    verifier.cs.blake2s_preimage(preimage, hash);

    // Preprocess circuit
    verifier.preprocess(&ck).unwrap();

    c.bench_function("Verifier Preprocessing", |b| b.iter(|| blake2s_verifier_preprocess(&ck)));

    c.bench_function("Verifying", |b| b.iter(|| blake2s_verify(&proof, &vk, &public_inputs, &mut verifier)));
}
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench
}
criterion_main!(benches);
