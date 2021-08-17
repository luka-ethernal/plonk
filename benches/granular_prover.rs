// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion,
};
use dusk_bls12_381::BlsScalar;
use dusk_plonk::circuit::{self, Circuit, VerifierData};
// Using prelude until PP is available on regular import path
use dusk_plonk::commitment_scheme::kzg10::Commitment;
use dusk_plonk::constraint_system::StandardComposer;
use dusk_plonk::error::Error;
use dusk_plonk::fft::{EvaluationDomain, Polynomial};
use dusk_plonk::plookup::MultiSet;
use dusk_plonk::prelude::{CommitKey, PublicParameters};
use dusk_plonk::proof_system::{
    linearisation_poly, quotient_poly, Proof, Prover, ProverKey,
};
use dusk_plonk::transcript::TranscriptProtocol;
use merlin::Transcript;

fn plonkup_preprocess(ck: &CommitKey, n: usize) {
    // Create a prover struct
    let mut prover = Prover::new(b"preprocessing");

    prover.mut_cs().lookup_table.insert_multi_mul(0, 3);

    let output = prover.mut_cs().lookup_table.lookup(
        BlsScalar::from(2),
        BlsScalar::from(3),
        BlsScalar::one(),
    );

    let two = prover
        .mut_cs()
        .add_witness_to_circuit_description(BlsScalar::from(2));
    let three = prover
        .mut_cs()
        .add_witness_to_circuit_description(BlsScalar::from(3));
    let result = prover
        .mut_cs()
        .add_witness_to_circuit_description(output.unwrap());
    let one = prover
        .mut_cs()
        .add_witness_to_circuit_description(BlsScalar::one());

    for i in 0..(n / 2) {
        prover.mut_cs().plookup_gate(
            two,
            three,
            result,
            Some(one),
            BlsScalar::one(),
        );

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
    ))
    .unwrap();

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

fn wire_ffts(
    domain: EvaluationDomain,
    w_l_scalar: &Vec<BlsScalar>,
    w_r_scalar: &Vec<BlsScalar>,
    w_o_scalar: &Vec<BlsScalar>,
    w_4_scalar: &Vec<BlsScalar>,
) {
    // Witnesses are now in evaluation form, convert them to coefficients
    // So that we may commit to them
    let w_l_poly = Polynomial::from_coefficients_vec(domain.ifft(w_l_scalar));
    let w_r_poly = Polynomial::from_coefficients_vec(domain.ifft(w_r_scalar));
    let w_o_poly = Polynomial::from_coefficients_vec(domain.ifft(w_o_scalar));
    let w_4_poly = Polynomial::from_coefficients_vec(domain.ifft(w_4_scalar));
}

fn wire_commitments(
    ck: &CommitKey,
    w_l_poly: &Polynomial,
    w_r_poly: &Polynomial,
    w_o_poly: &Polynomial,
    w_4_poly: &Polynomial,
) {
    // Commit to witness polynomials
    let w_l_poly_commit = ck.commit(&w_l_poly);
    let w_r_poly_commit = ck.commit(&w_r_poly);
    let w_o_poly_commit = ck.commit(&w_o_poly);
    let w_4_poly_commit = ck.commit(&w_4_poly);
}

fn compress_table(prover_key: &ProverKey, zeta: BlsScalar) {
    // Compress table into vector of single elements
    let compressed_t_multiset = MultiSet::compress_four_arity(
        [
            &prover_key.lookup.table_1.0,
            &prover_key.lookup.table_2.0,
            &prover_key.lookup.table_3.0,
            &prover_key.lookup.table_4.0,
        ],
        zeta,
    );
}

fn compute_table_poly(
    domain: EvaluationDomain,
    compressed_t_multiset: &MultiSet,
) {
    // Compute table poly
    let table_poly = Polynomial::from_coefficients_vec(
        domain.ifft(&compressed_t_multiset.0.as_slice()),
    );
}

fn compute_table_f(
    w_l_scalar: &Vec<BlsScalar>,
    w_r_scalar: &Vec<BlsScalar>,
    w_o_scalar: &Vec<BlsScalar>,
    w_4_scalar: &Vec<BlsScalar>,
    padded_q_lookup: &Vec<BlsScalar>,
    compressed_t_multiset: &MultiSet,
) {
    // Compute table f
    // When q_lookup[i] is zero the wire value is replaced with a dummy
    // value Currently set as the first row of the public table
    // If q_lookup is one the wire values are preserved
    let f_1_scalar = w_l_scalar
        .iter()
        .zip(padded_q_lookup)
        .map(|(w, s)| {
            w * s + (BlsScalar::one() - s) * compressed_t_multiset.0[0]
        })
        .collect::<Vec<BlsScalar>>();
    let f_2_scalar = w_r_scalar
        .iter()
        .zip(padded_q_lookup)
        .map(|(w, s)| w * s)
        .collect::<Vec<BlsScalar>>();
    let f_3_scalar = w_o_scalar
        .iter()
        .zip(padded_q_lookup)
        .map(|(w, s)| w * s)
        .collect::<Vec<BlsScalar>>();
    let f_4_scalar = w_4_scalar
        .iter()
        .zip(padded_q_lookup)
        .map(|(w, s)| w * s)
        .collect::<Vec<BlsScalar>>();
}

fn compress_queries(
    f_1_scalar: &Vec<BlsScalar>,
    f_2_scalar: &Vec<BlsScalar>,
    f_3_scalar: &Vec<BlsScalar>,
    f_4_scalar: &Vec<BlsScalar>,
    zeta: BlsScalar,
) {
    // Compress all wires into a single vector
    let compressed_f_multiset = MultiSet::compress_four_arity(
        [
            &MultiSet::from(&f_1_scalar[..]),
            &MultiSet::from(&f_2_scalar[..]),
            &MultiSet::from(&f_3_scalar[..]),
            &MultiSet::from(&f_4_scalar[..]),
        ],
        zeta,
    );
}

fn compute_query_poly(
    domain: EvaluationDomain,
    compressed_f_multiset: &MultiSet,
) {
    // Compute long query poly
    let f_poly = Polynomial::from_coefficients_vec(
        domain.ifft(&compressed_f_multiset.0.as_slice()),
    );
}

fn commit_to_query(commit_key: &CommitKey, f_poly: &Polynomial) {
    // Commit to query polynomial
    let f_poly_commit = commit_key.commit(&f_poly);
}

fn compute_plonk_perm(
    prover: &Prover,
    prover_key: &ProverKey,
    domain: EvaluationDomain,
    w_l_scalar: &Vec<BlsScalar>,
    w_r_scalar: &Vec<BlsScalar>,
    w_o_scalar: &Vec<BlsScalar>,
    w_4_scalar: &Vec<BlsScalar>,
    beta: BlsScalar,
    gamma: BlsScalar,
) {
    let z_poly = Polynomial::from_coefficients_slice(
        &prover.cs.perm.compute_permutation_poly(
            &domain,
            (&w_l_scalar, &w_r_scalar, &w_o_scalar, &w_4_scalar),
            &beta,
            &gamma,
            (
                &prover_key.permutation.left_sigma.0,
                &prover_key.permutation.right_sigma.0,
                &prover_key.permutation.out_sigma.0,
                &prover_key.permutation.fourth_sigma.0,
            ),
        ),
    );
}

fn commit_wire_perm(commit_key: &CommitKey, z_poly: &Polynomial) {
    // Commit to permutation polynomial
    //
    let z_poly_commit = commit_key.commit(z_poly);
}

fn compute_pi_poly(domain: EvaluationDomain, prover: &Prover) {
    // 3. Compute public inputs polynomial
    let pi_poly = Polynomial::from_coefficients_vec(
        domain.ifft(&prover.cs.construct_dense_pi_vec()),
    );
}

fn conc_and_sort(
    compressed_t_multiset: &MultiSet,
    compressed_f_multiset: &MultiSet,
) {
    // Compute s, as the sorted and concatenated version of f and t
    let s = compressed_t_multiset
        .sorted_concat(&compressed_f_multiset)
        .unwrap();
}

fn halve_alternating(s: &MultiSet) {
    // Compute first and second halves of s, as h_1 and h_2
    let (h_1, h_2) = s.halve_alternating();
}

fn compute_h1_h2_poly(
    domain: EvaluationDomain,
    h_1: &MultiSet,
    h_2: &MultiSet,
) {
    // Compute h polys
    let h_1_poly =
        Polynomial::from_coefficients_vec(domain.ifft(&h_1.0.as_slice()));
    let h_2_poly =
        Polynomial::from_coefficients_vec(domain.ifft(&h_2.0.as_slice()));
}

fn commit_h1_h2_poly(
    commit_key: &CommitKey,
    h_1_poly: &Polynomial,
    h_2_poly: &Polynomial,
) {
    // Commit to h polys
    let h_1_poly_commit = commit_key.commit(&h_1_poly).unwrap();
    let h_2_poly_commit = commit_key.commit(&h_2_poly).unwrap();
}

fn compute_lookup_perm(
    domain: EvaluationDomain,
    prover: &Prover,
    compressed_f_multiset: &MultiSet,
    compressed_t_multiset: &MultiSet,
    h_1: &MultiSet,
    h_2: &MultiSet,
    delta: BlsScalar,
    epsilon: BlsScalar,
) {
    // Compute lookup permutation poly
    let p_poly = Polynomial::from_coefficients_slice(
        &prover.cs.perm.compute_lookup_permutation_poly(
            &domain,
            &compressed_f_multiset.0,
            &compressed_t_multiset.0,
            &h_1.0,
            &h_2.0,
            &delta,
            &epsilon,
        ),
    );
}

fn commit_lookup_perm_poly(commit_key: &CommitKey, p_poly: &Polynomial) {
    // Commit to permutation polynomial
    //
    let p_poly_commit = commit_key.commit(&p_poly).unwrap();
}

fn compute_quotient_poly(
    domain: EvaluationDomain,
    prover_key: &ProverKey,
    z_poly: &Polynomial,
    p_poly: &Polynomial,
    w_l_poly: &Polynomial,
    w_r_poly: &Polynomial,
    w_o_poly: &Polynomial,
    w_4_poly: &Polynomial,
    f_poly: &Polynomial,
    table_poly: &Polynomial,
    h_1_poly: &Polynomial,
    h_2_poly: &Polynomial,
    pi_poly: &Polynomial,
    alpha: BlsScalar,
    beta: BlsScalar,
    gamma: BlsScalar,
    delta: BlsScalar,
    epsilon: BlsScalar,
    zeta: BlsScalar,
    range_sep_challenge: BlsScalar,
    logic_sep_challenge: BlsScalar,
    fixed_base_sep_challenge: BlsScalar,
    var_base_sep_challenge: BlsScalar,
    lookup_sep_challenge: BlsScalar,
) {
    let t_poly = quotient_poly::compute(
        &domain,
        &prover_key,
        &z_poly,
        &p_poly,
        (&w_l_poly, &w_r_poly, &w_o_poly, &w_4_poly),
        &f_poly,
        &table_poly,
        &h_1_poly,
        &h_2_poly,
        &pi_poly,
        &(
            alpha,
            beta,
            gamma,
            delta,
            epsilon,
            zeta,
            range_sep_challenge,
            logic_sep_challenge,
            fixed_base_sep_challenge,
            var_base_sep_challenge,
            lookup_sep_challenge,
        ),
    )
    .unwrap();
}

fn split_quotient(size: usize, prover: &Prover, t_poly: &Polynomial) {
    let (t_1_poly, t_2_poly, t_3_poly, t_4_poly) =
        prover.split_tx_poly(size, &t_poly);
}

fn commit_quotient_pieces(
    commit_key: &CommitKey,
    t_1_poly: &Polynomial,
    t_2_poly: &Polynomial,
    t_3_poly: &Polynomial,
    t_4_poly: &Polynomial,
) {
    // Commit to splitted quotient polynomial
    let t_1_commit = commit_key.commit(&t_1_poly).unwrap();
    let t_2_commit = commit_key.commit(&t_2_poly).unwrap();
    let t_3_commit = commit_key.commit(&t_3_poly).unwrap();
    let t_4_commit = commit_key.commit(&t_4_poly).unwrap();
}

fn compute_linearization(
    domain: &EvaluationDomain,
    prover_key: &ProverKey,
    alpha: BlsScalar,
    beta: BlsScalar,
    gamma: BlsScalar,
    delta: BlsScalar,
    epsilon: BlsScalar,
    zeta: BlsScalar,
    range_sep_challenge: BlsScalar,
    logic_sep_challenge: BlsScalar,
    fixed_base_sep_challenge: BlsScalar,
    var_base_sep_challenge: BlsScalar,
    lookup_sep_challenge: BlsScalar,
    z_challenge: BlsScalar,
    w_l_poly: &Polynomial,
    w_r_poly: &Polynomial,
    w_o_poly: &Polynomial,
    w_4_poly: &Polynomial,
    t_poly: &Polynomial,
    z_poly: &Polynomial,
    f_poly: &Polynomial,
    h_1_poly: &Polynomial,
    h_2_poly: &Polynomial,
    table_poly: &Polynomial,
    p_poly: &Polynomial,
) {
    let (lin_poly, evaluations) = linearisation_poly::compute(
        &domain,
        &prover_key,
        &(
            alpha,
            beta,
            gamma,
            delta,
            epsilon,
            zeta,
            range_sep_challenge,
            logic_sep_challenge,
            fixed_base_sep_challenge,
            var_base_sep_challenge,
            lookup_sep_challenge,
            z_challenge,
        ),
        &w_l_poly,
        &w_r_poly,
        &w_o_poly,
        &w_4_poly,
        &t_poly,
        &z_poly,
        &f_poly,
        &h_1_poly,
        &h_2_poly,
        &table_poly,
        &p_poly,
    );
}

fn compute_quotient_opening_poly(
    n: usize,
    t_1_poly: &Polynomial,
    t_2_poly: &Polynomial,
    t_3_poly: &Polynomial,
    t_4_poly: &Polynomial,
    z_challenge: BlsScalar,
) {
    // 5. Compute Openings using KZG10
    //
    // We merge the quotient polynomial using the `z_challenge` so the SRS
    // is linear in the circuit size `n`
    let quot = Prover::compute_quotient_opening_poly(
        n,
        &t_1_poly,
        &t_2_poly,
        &t_3_poly,
        &t_4_poly,
        &z_challenge,
    );
}

fn compute_aggregate_witness(
    commit_key: &CommitKey,
    quot: Polynomial,
    lin_poly: Polynomial,
    w_l_poly: Polynomial,
    w_r_poly: Polynomial,
    w_o_poly: Polynomial,
    w_4_poly: Polynomial,
    left_sigma: Polynomial,
    right_sigma: Polynomial,
    out_sigma: Polynomial,
    f_poly: Polynomial,
    h_1_poly: Polynomial,
    h_2_poly: Polynomial,
    table_poly: Polynomial,
    z_challenge: BlsScalar,
    transcript: &mut Transcript,
) {
    // Compute aggregate witness to polynomials evaluated at the evaluation
    // challenge `z`
    let aggregate_witness = commit_key.compute_aggregate_witness(
        &[
            quot,
            lin_poly,
            w_l_poly,
            w_r_poly,
            w_o_poly,
            w_4_poly,
            left_sigma,
            right_sigma,
            out_sigma,
            f_poly,
            h_1_poly,
            h_2_poly,
            table_poly,
        ],
        &z_challenge,
        transcript,
    );
}

fn commit_aggregate_witness(
    commit_key: &CommitKey,
    aggregate_witness: &Polynomial,
) {
    let w_z_comm = commit_key.commit(&aggregate_witness).unwrap();
}

fn compute_shifted_aggregate_witness(
    commit_key: &CommitKey,
    z_poly: Polynomial,
    w_l_poly: Polynomial,
    w_r_poly: Polynomial,
    w_4_poly: Polynomial,
    h_1_poly: Polynomial,
    p_poly: Polynomial,
    table_poly: Polynomial,
    z_challenge: BlsScalar,
    group_gen: BlsScalar,
    transcript: &mut Transcript,
) {
    // Compute aggregate witness to polynomials evaluated at the shifted
    // evaluation challenge
    let shifted_aggregate_witness = commit_key.compute_aggregate_witness(
        &[
            z_poly, w_l_poly, w_r_poly, w_4_poly, h_1_poly, p_poly, table_poly,
        ],
        &(z_challenge * group_gen),
        transcript,
    );
}

fn commit_shifted_aggregate_witness(
    commit_key: &CommitKey,
    shifted_aggregate_witness: &Polynomial,
) {
    let w_zx_comm = commit_key.commit(&shifted_aggregate_witness).unwrap();
}

fn bench(c: &mut Criterion) {
    let n = 2usize.pow(12);

    use std::fs::File;
    use std::io::Read;

    let mut f = File::open("setup2to17").unwrap();
    let mut setup_bytes = Vec::new();
    f.read_to_end(&mut setup_bytes).unwrap();

    let public_parameters =
        unsafe { PublicParameters::from_slice_unchecked(&setup_bytes) };

    // Commit Key
    let (ck, _) = public_parameters.trim(2 * n).unwrap();

    c.bench_function("Preprocessing", |b| {
        b.iter(|| plonkup_preprocess(&ck, n))
    });

    // Create a prover struct
    let mut prover = Prover::new(b"padding_prepping");

    prover.mut_cs().lookup_table.insert_multi_mul(0, 3);

    let output = prover.mut_cs().lookup_table.lookup(
        BlsScalar::from(2),
        BlsScalar::from(3),
        BlsScalar::one(),
    );

    let two = prover
        .mut_cs()
        .add_witness_to_circuit_description(BlsScalar::from(2));
    let three = prover
        .mut_cs()
        .add_witness_to_circuit_description(BlsScalar::from(3));
    let result = prover
        .mut_cs()
        .add_witness_to_circuit_description(output.unwrap());
    let one = prover
        .mut_cs()
        .add_witness_to_circuit_description(BlsScalar::one());

    for i in 0..(n / 2) {
        prover.mut_cs().plookup_gate(
            two,
            three,
            result,
            Some(one),
            BlsScalar::one(),
        );

        prover.mut_cs().big_add(
            (BlsScalar::one(), two),
            (BlsScalar::one(), three),
            None,
            BlsScalar::zero(),
            Some(BlsScalar::zero()),
        );
    }

    prover.preprocess(&ck).unwrap();

    let prover_key = prover.prover_key.as_ref().unwrap();

    c.bench_function("Padding and Prepping Wires", |b| {
        b.iter(|| padding_and_prepping(&prover))
    });

    let domain = EvaluationDomain::new(core::cmp::max(
        prover.cs.circuit_size(),
        prover.cs.lookup_table.0.len(),
    ))
    .unwrap();

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

    c.bench_function("Wire FFTs", |b| {
        b.iter(|| {
            wire_ffts(domain, w_l_scalar, w_r_scalar, w_o_scalar, w_4_scalar)
        })
    });

    // Witnesses are now in evaluation form, convert them to coefficients
    // So that we may commit to them
    let w_l_poly = Polynomial::from_coefficients_vec(domain.ifft(w_l_scalar));
    let w_r_poly = Polynomial::from_coefficients_vec(domain.ifft(w_r_scalar));
    let w_o_poly = Polynomial::from_coefficients_vec(domain.ifft(w_o_scalar));
    let w_4_poly = Polynomial::from_coefficients_vec(domain.ifft(w_4_scalar));

    c.bench_function("Wire Commitments", |b| {
        b.iter(|| {
            wire_commitments(&ck, &w_l_poly, &w_r_poly, &w_o_poly, &w_4_poly)
        })
    });

    // Commit to witness polynomials
    let w_l_poly_commit = ck.commit(&w_l_poly).unwrap();
    let w_r_poly_commit = ck.commit(&w_r_poly).unwrap();
    let w_o_poly_commit = ck.commit(&w_o_poly).unwrap();
    let w_4_poly_commit = ck.commit(&w_4_poly).unwrap();

    /* ----- THIS PORTION NOT BENCHED ----- */
    // Add witness polynomial commitments to transcript
    transcript.append_commitment(b"w_l", &w_l_poly_commit);
    transcript.append_commitment(b"w_r", &w_r_poly_commit);
    transcript.append_commitment(b"w_o", &w_o_poly_commit);
    transcript.append_commitment(b"w_4", &w_4_poly_commit);

    // Generate table compression factor
    let zeta = transcript.challenge_scalar(b"zeta");
    /* ------------------------------------ */

    c.bench_function("Compress Lookup Table", |b| {
        b.iter(|| compress_table(&prover_key, zeta))
    });

    // Compress table into vector of single elements
    let compressed_t_multiset = MultiSet::compress_four_arity(
        [
            &prover_key.lookup.table_1.0,
            &prover_key.lookup.table_2.0,
            &prover_key.lookup.table_3.0,
            &prover_key.lookup.table_4.0,
        ],
        zeta,
    );

    c.bench_function("Compute Lookup Table Polynomial", |b| {
        b.iter(|| compute_table_poly(domain, &compressed_t_multiset))
    });

    // Compute table poly
    let table_poly = Polynomial::from_coefficients_vec(
        domain.ifft(&compressed_t_multiset.0.as_slice()),
    );

    c.bench_function("Compute Query Table", |b| {
        b.iter(|| {
            compute_table_f(
                &w_l_scalar,
                &w_r_scalar,
                &w_o_scalar,
                &w_4_scalar,
                &padded_q_lookup,
                &compressed_t_multiset,
            )
        })
    });

    // Compute table f
    // When q_lookup[i] is zero the wire value is replaced with a dummy
    // value Currently set as the first row of the public table
    // If q_lookup is one the wire values are preserved
    let f_1_scalar = w_l_scalar
        .iter()
        .zip(&padded_q_lookup)
        .map(|(w, s)| {
            w * s + (BlsScalar::one() - s) * compressed_t_multiset.0[0]
        })
        .collect::<Vec<BlsScalar>>();
    let f_2_scalar = w_r_scalar
        .iter()
        .zip(&padded_q_lookup)
        .map(|(w, s)| w * s)
        .collect::<Vec<BlsScalar>>();
    let f_3_scalar = w_o_scalar
        .iter()
        .zip(&padded_q_lookup)
        .map(|(w, s)| w * s)
        .collect::<Vec<BlsScalar>>();
    let f_4_scalar = w_4_scalar
        .iter()
        .zip(&padded_q_lookup)
        .map(|(w, s)| w * s)
        .collect::<Vec<BlsScalar>>();

    c.bench_function("Compress Queries", |b| {
        b.iter(|| {
            compress_queries(
                &f_1_scalar,
                &f_2_scalar,
                &f_3_scalar,
                &f_4_scalar,
                zeta,
            )
        })
    });

    // Compress all wires into a single vector
    let compressed_f_multiset = MultiSet::compress_four_arity(
        [
            &MultiSet::from(&f_1_scalar[..]),
            &MultiSet::from(&f_2_scalar[..]),
            &MultiSet::from(&f_3_scalar[..]),
            &MultiSet::from(&f_4_scalar[..]),
        ],
        zeta,
    );

    c.bench_function("Compute Query Polynomial", |b| {
        b.iter(|| compute_query_poly(domain, &compressed_f_multiset))
    });

    // Compute long query poly
    let f_poly = Polynomial::from_coefficients_vec(
        domain.ifft(&compressed_f_multiset.0.as_slice()),
    );

    c.bench_function("Commit to Query Polynomial", |b| {
        b.iter(|| commit_to_query(&ck, &f_poly))
    });

    // Commit to query polynomial
    let f_poly_commit = ck.commit(&f_poly).unwrap();

    /* ----- NOT BENCHMARKED ----- */
    // Add f_poly commitment to transcript
    transcript.append_commitment(b"f", &f_poly_commit);
    /* --------------------------- */

    // 2. Compute permutation polynomial
    //
    //
    // Compute permutation challenges; `beta`, `gamma`, `delta` and
    // `epsilon`.
    let beta = transcript.challenge_scalar(b"beta");
    transcript.append_scalar(b"beta", &beta);
    let gamma = transcript.challenge_scalar(b"gamma");
    let delta = transcript.challenge_scalar(b"delta");
    let epsilon = transcript.challenge_scalar(b"epsilon");
    /* ---------------------------- */

    c.bench_function("Compute Wire Permutation Polynomial", |b| {
        b.iter(|| {
            compute_plonk_perm(
                &prover, prover_key, domain, w_l_scalar, w_r_scalar,
                w_o_scalar, w_4_scalar, beta, gamma,
            )
        })
    });

    let z_poly = Polynomial::from_coefficients_slice(
        &prover.cs.perm.compute_permutation_poly(
            &domain,
            (&w_l_scalar, &w_r_scalar, &w_o_scalar, &w_4_scalar),
            &beta,
            &gamma,
            (
                &prover_key.permutation.left_sigma.0,
                &prover_key.permutation.right_sigma.0,
                &prover_key.permutation.out_sigma.0,
                &prover_key.permutation.fourth_sigma.0,
            ),
        ),
    );

    c.bench_function("Commit to Wire Permutation Polynomial", |b| {
        b.iter(|| commit_to_query(&ck, &z_poly))
    });

    // Commit to permutation polynomial
    //
    let z_poly_commit = ck.commit(&z_poly).unwrap();

    /* ----- NOT BENCHED ----- */
    // Add commitment to permutation polynomial to transcript
    transcript.append_commitment(b"z", &z_poly_commit);
    /* ----------------------- */

    c.bench_function("Compute Public Inputs Polynomial", |b| {
        b.iter(|| compute_pi_poly(domain, &prover))
    });

    // 3. Compute public inputs polynomial
    let pi_poly = Polynomial::from_coefficients_vec(
        domain.ifft(&prover.cs.construct_dense_pi_vec()),
    );

    /* ----- NOT BENCHED ----- */
    // Compute evaluation challenge; `z`
    let z_challenge = transcript.challenge_scalar(b"z_challenge");
    /* ----------------------- */

    c.bench_function("Concatenate and Sort", |b| {
        b.iter(|| conc_and_sort(&compressed_t_multiset, &compressed_f_multiset))
    });

    // Compute s, as the sorted and concatenated version of f and t
    let s = compressed_t_multiset
        .sorted_concat(&compressed_f_multiset)
        .unwrap();

    c.bench_function("Halve multiset", |b| b.iter(|| halve_alternating(&s)));

    // Compute first and second halves of s, as h_1 and h_2
    let (h_1, h_2) = s.halve_alternating();

    c.bench_function("Compute h1 h2 polynomials", |b| {
        b.iter(|| compute_h1_h2_poly(domain, &h_1, &h_2))
    });

    // Compute h polys
    let h_1_poly =
        Polynomial::from_coefficients_vec(domain.ifft(&h_1.0.as_slice()));
    let h_2_poly =
        Polynomial::from_coefficients_vec(domain.ifft(&h_2.0.as_slice()));

    c.bench_function("Commit to h1 h2 polynomials", |b| {
        b.iter(|| commit_h1_h2_poly(&ck, &h_1_poly, &h_2_poly))
    });

    // Commit to h polys
    let h_1_poly_commit = ck.commit(&h_1_poly).unwrap();
    let h_2_poly_commit = ck.commit(&h_2_poly).unwrap();

    // Add h polynomials to transcript
    transcript.append_commitment(b"h1", &h_1_poly_commit);
    transcript.append_commitment(b"h2", &h_2_poly_commit);

    c.bench_function("Compute lookup permutation polynomial", |b| {
        b.iter(|| {
            compute_lookup_perm(
                domain,
                &prover,
                &compressed_f_multiset,
                &compressed_t_multiset,
                &h_1,
                &h_2,
                delta,
                epsilon,
            )
        })
    });

    // Compute lookup permutation poly
    let p_poly = Polynomial::from_coefficients_slice(
        &prover.cs.perm.compute_lookup_permutation_poly(
            &domain,
            &compressed_f_multiset.0,
            &compressed_t_multiset.0,
            &h_1.0,
            &h_2.0,
            &delta,
            &epsilon,
        ),
    );

    c.bench_function("Commit to lookup permutation polynomial", |b| {
        b.iter(|| commit_lookup_perm_poly(&ck, &p_poly))
    });

    // Commit to permutation polynomial
    //
    let p_poly_commit = ck.commit(&p_poly).unwrap();

    /* ----- NOT BENCHMARKED ----- */
    // Add permutation polynomial commitment to transcript
    transcript.append_commitment(b"p", &p_poly_commit);
    /* --------------------------- */

    // 4. Compute quotient polynomial
    //
    // Compute quotient challenge; `alpha`
    let alpha = transcript.challenge_scalar(b"alpha");
    let range_sep_challenge =
        transcript.challenge_scalar(b"range separation challenge");
    let logic_sep_challenge =
        transcript.challenge_scalar(b"logic separation challenge");
    let fixed_base_sep_challenge =
        transcript.challenge_scalar(b"fixed base separation challenge");
    let var_base_sep_challenge =
        transcript.challenge_scalar(b"variable base separation challenge");
    let lookup_sep_challenge = transcript.challenge_scalar(b"lookup challenge");
    /* ---------------------------- */

    c.bench_function("Compute quotient polynomial", |b| {
        b.iter(|| {
            compute_quotient_poly(
                domain,
                &prover_key,
                &z_poly,
                &p_poly,
                &w_l_poly,
                &w_r_poly,
                &w_o_poly,
                &w_4_poly,
                &f_poly,
                &table_poly,
                &h_1_poly,
                &h_2_poly,
                &pi_poly,
                alpha,
                beta,
                gamma,
                delta,
                epsilon,
                zeta,
                range_sep_challenge,
                logic_sep_challenge,
                fixed_base_sep_challenge,
                var_base_sep_challenge,
                lookup_sep_challenge,
            )
        })
    });

    let t_poly = quotient_poly::compute(
        &domain,
        &prover_key,
        &z_poly,
        &p_poly,
        (&w_l_poly, &w_r_poly, &w_o_poly, &w_4_poly),
        &f_poly,
        &table_poly,
        &h_1_poly,
        &h_2_poly,
        &pi_poly,
        &(
            alpha,
            beta,
            gamma,
            delta,
            epsilon,
            zeta,
            range_sep_challenge,
            logic_sep_challenge,
            fixed_base_sep_challenge,
            var_base_sep_challenge,
            lookup_sep_challenge,
        ),
    )
    .unwrap();

    c.bench_function("Split quotient polynomial", |b| {
        b.iter(|| split_quotient(domain.size(), &prover, &t_poly))
    });

    // Split quotient polynomial into 4 degree `n` polynomials
    let (t_1_poly, t_2_poly, t_3_poly, t_4_poly) =
        prover.split_tx_poly(domain.size(), &t_poly);

    c.bench_function("Commit to splitted polynomials", |b| {
        b.iter(|| {
            commit_quotient_pieces(
                &ck, &t_1_poly, &t_2_poly, &t_3_poly, &t_4_poly,
            )
        })
    });

    // Commit to splitted quotient polynomial
    let t_1_commit = ck.commit(&t_1_poly).unwrap();
    let t_2_commit = ck.commit(&t_2_poly).unwrap();
    let t_3_commit = ck.commit(&t_3_poly).unwrap();
    let t_4_commit = ck.commit(&t_4_poly).unwrap();

    /* ----- NOT BENCHMARKED ----- */
    // Add quotient polynomial commitments to transcript
    transcript.append_commitment(b"t_1", &t_1_commit);
    transcript.append_commitment(b"t_2", &t_2_commit);
    transcript.append_commitment(b"t_3", &t_3_commit);
    transcript.append_commitment(b"t_4", &t_4_commit);
    /* --------------------------- */

    c.bench_function("Compute linearization polynomial", |b| {
        b.iter(|| {
            compute_linearization(
                &domain,
                &prover_key,
                alpha,
                beta,
                gamma,
                delta,
                epsilon,
                zeta,
                range_sep_challenge,
                logic_sep_challenge,
                fixed_base_sep_challenge,
                var_base_sep_challenge,
                lookup_sep_challenge,
                z_challenge,
                &w_l_poly,
                &w_r_poly,
                &w_o_poly,
                &w_4_poly,
                &t_poly,
                &z_poly,
                &f_poly,
                &h_1_poly,
                &h_2_poly,
                &table_poly,
                &p_poly,
            )
        })
    });

    let (lin_poly, evaluations) = linearisation_poly::compute(
        &domain,
        &prover_key,
        &(
            alpha,
            beta,
            gamma,
            delta,
            epsilon,
            zeta,
            range_sep_challenge,
            logic_sep_challenge,
            fixed_base_sep_challenge,
            var_base_sep_challenge,
            lookup_sep_challenge,
            z_challenge,
        ),
        &w_l_poly,
        &w_r_poly,
        &w_o_poly,
        &w_4_poly,
        &t_poly,
        &z_poly,
        &f_poly,
        &h_1_poly,
        &h_2_poly,
        &table_poly,
        &p_poly,
    );

    /* ----- NOT BENCHMARKED ----- */
    // Add evaluations to transcript
    transcript.append_scalar(b"a_eval", &evaluations.proof.a_eval);
    transcript.append_scalar(b"b_eval", &evaluations.proof.b_eval);
    transcript.append_scalar(b"c_eval", &evaluations.proof.c_eval);
    transcript.append_scalar(b"d_eval", &evaluations.proof.d_eval);
    transcript.append_scalar(b"a_next_eval", &evaluations.proof.a_next_eval);
    transcript.append_scalar(b"b_next_eval", &evaluations.proof.b_next_eval);
    transcript.append_scalar(b"d_next_eval", &evaluations.proof.d_next_eval);
    transcript
        .append_scalar(b"left_sig_eval", &evaluations.proof.left_sigma_eval);
    transcript
        .append_scalar(b"right_sig_eval", &evaluations.proof.right_sigma_eval);
    transcript
        .append_scalar(b"out_sig_eval", &evaluations.proof.out_sigma_eval);
    transcript.append_scalar(b"q_arith_eval", &evaluations.proof.q_arith_eval);
    transcript.append_scalar(b"q_c_eval", &evaluations.proof.q_c_eval);
    transcript.append_scalar(b"q_l_eval", &evaluations.proof.q_l_eval);
    transcript.append_scalar(b"q_r_eval", &evaluations.proof.q_r_eval);
    transcript
        .append_scalar(b"q_lookup_eval", &evaluations.proof.q_lookup_eval);
    transcript.append_scalar(b"perm_eval", &evaluations.proof.perm_eval);
    transcript.append_scalar(
        b"lookup_perm_eval",
        &evaluations.proof.lookup_perm_eval,
    );
    transcript.append_scalar(b"h_1_eval", &evaluations.proof.h_1_eval);
    transcript
        .append_scalar(b"h_1_next_eval", &evaluations.proof.h_1_next_eval);
    transcript.append_scalar(b"h_2_eval", &evaluations.proof.h_2_eval);
    transcript.append_scalar(b"t_eval", &evaluations.quot_eval);
    transcript.append_scalar(b"r_eval", &evaluations.proof.lin_poly_eval);
    /* --------------------------- */

    c.bench_function("Compute quotient opening poly", |b| {
        b.iter(|| {
            compute_quotient_opening_poly(
                domain.size(),
                &t_1_poly,
                &t_2_poly,
                &t_3_poly,
                &t_4_poly,
                z_challenge,
            )
        })
    });

    // 5. Compute Openings using KZG10
    //
    // We merge the quotient polynomial using the `z_challenge` so the SRS
    // is linear in the circuit size `n`
    let quot = Prover::compute_quotient_opening_poly(
        domain.size(),
        &t_1_poly,
        &t_2_poly,
        &t_3_poly,
        &t_4_poly,
        &z_challenge,
    );

    // Compute aggregate witness to polynomials evaluated at the evaluation
    // challenge `z`
    let aggregate_witness = ck.compute_aggregate_witness(
        &[
            quot.clone(),
            lin_poly.clone(),
            w_l_poly.clone(),
            w_r_poly.clone(),
            w_o_poly.clone(),
            w_4_poly.clone(),
            prover_key.permutation.left_sigma.0.clone(),
            prover_key.permutation.right_sigma.0.clone(),
            prover_key.permutation.out_sigma.0.clone(),
            f_poly.clone(),
            h_1_poly.clone(),
            h_2_poly.clone(),
            table_poly.clone(),
        ],
        &z_challenge,
        &mut transcript,
    );

    c.bench_function("Compute aggregate witness", |b| {
        b.iter(|| {
            compute_aggregate_witness(
                &ck,
                quot.clone(),
                lin_poly.clone(),
                w_l_poly.clone(),
                w_r_poly.clone(),
                w_o_poly.clone(),
                w_4_poly.clone(),
                prover_key.permutation.left_sigma.0.clone(),
                prover_key.permutation.right_sigma.0.clone(),
                prover_key.permutation.out_sigma.0.clone(),
                f_poly.clone(),
                h_1_poly.clone(),
                h_2_poly.clone(),
                table_poly.clone(),
                z_challenge,
                &mut transcript,
            )
        })
    });

    let w_z_comm = ck.commit(&aggregate_witness).unwrap();

    c.bench_function("Commit to aggregate witness", |b| {
        b.iter(|| commit_aggregate_witness(&ck, &aggregate_witness))
    });

    // Compute aggregate witness to polynomials evaluated at the shifted
    // evaluation challenge
    let shifted_aggregate_witness = ck.compute_aggregate_witness(
        &[
            z_poly.clone(),
            w_l_poly.clone(),
            w_r_poly.clone(),
            w_4_poly.clone(),
            h_1_poly.clone(),
            p_poly.clone(),
            table_poly.clone(),
        ],
        &(z_challenge * domain.group_gen),
        &mut transcript,
    );

    c.bench_function("Compute shifted aggregate witness", |b| {
        b.iter(|| {
            compute_shifted_aggregate_witness(
                &ck,
                z_poly.clone(),
                w_l_poly.clone(),
                w_r_poly.clone(),
                w_4_poly.clone(),
                h_1_poly.clone(),
                p_poly.clone(),
                table_poly.clone(),
                z_challenge,
                domain.group_gen,
                &mut transcript,
            )
        })
    });

    let w_zx_comm = ck.commit(&shifted_aggregate_witness).unwrap();

    c.bench_function("Commit to shifted aggregate witness", |b| {
        b.iter(|| {
            commit_shifted_aggregate_witness(&ck, &shifted_aggregate_witness)
        })
    });
}

///
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench
}
criterion_main!(benches);
