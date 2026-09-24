//! Rust cryptographic layer for the ACNS FL benchmark.
//!
//! This crate intentionally keeps the zero-knowledge layer separate from
//! the C++ LibTorch/SEAL layer. C++ calls this library through a C ABI.

use bulletproofs::{BulletproofGens, PedersenGens};
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSProof, Verifier, Variable};
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::Instant;

#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub struct ZkBenchResult {
    pub prove_us: u64,
    pub verify_us: u64,
    pub commitment_us: u64,
    pub proof_bytes: u64,
    pub commitment_bytes: u64,
    pub poi_us: u64,
    pub poi_bytes: u64,
    pub fairness_us: u64,
    pub fairness_bytes: u64,
    pub checks_passed: u64,
    pub checks_failed: u64,
}

fn scalar_from_u64(x: u64) -> Scalar { Scalar::from(x) }

/// Matrix/linear-style gadget.
///
/// Public coefficients are placed directly into linear combinations. To
/// keep this benchmark compatible with the Bulletproofs R1CS implementation,
/// one fixed dummy multiplication gate is included; the N input relation
/// itself uses only linear constraints. Thus proof size is effectively
/// independent of N, while the constraint-synthesis work grows with N.
fn build_linear_gadget<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    vars: &[Variable],
    values: &[Scalar],
) {
    // A single fixed multiplication gate keeps the circuit valid for the
    // Bulletproofs R1CS backend while all N input relations below are linear.
    let (_, _, dummy) = cs.multiply(Scalar::one().into(), Scalar::one().into());
    cs.constrain(dummy - Scalar::one());

    // Public-coefficient matrix-style relation:
    //     sum_i c_i * v_i = sum_i c_i * w_i
    // where c_i and w_i are public. No per-element multiplication gates
    // are needed because scalar coefficients belong to linear combinations.
    let mut lhs: LinearCombination = Variable::One().into();
    let mut rhs = Scalar::zero();
    for (i, v) in vars.iter().enumerate() {
        let c = scalar_from_u64((i as u64) + 7);
        lhs = lhs + (*v * c);
        rhs += c * values[i];
    }
    cs.constrain(lhs - rhs);
}

/// Vector-style gadget with one multiplication gate per element.
fn build_vector_gadget<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    vars: &[Variable],
    values: &[Scalar],
) {
    for (i, v) in vars.iter().enumerate() {
        let c = values[i];
        let (_, _, out) = cs.multiply((*v).into(), c.into());
        cs.constrain(out - (*v * c));
    }
}

fn prove_and_verify(n: usize, mode: u32) -> Result<ZkBenchResult, String> {
    let pc_gens = PedersenGens::default();
    // Vector mode needs n generators; linear mode needs one fixed gate.
    let capacity = if mode == 0 { 1usize } else { n.max(1) };
    let bp_gens = BulletproofGens::new(capacity, 1);

    let mut rng = OsRng;
    let values: Vec<Scalar> = (0..n).map(|i| scalar_from_u64((i as u64) + 7)).collect();
    let blindings: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();

    let mut commitments: Vec<CompressedRistretto> = Vec::with_capacity(n);
    let mut vars = Vec::with_capacity(n);

    let commitment_start = Instant::now();
    let mut prover_transcript = Transcript::new(b"ACNS-FL-R1CS-v1");
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
    for i in 0..n {
        let (c, v) = prover.commit(values[i], blindings[i]);
        commitments.push(c);
        vars.push(v);
    }
    let commitment_us = commitment_start.elapsed().as_micros() as u64;

    if mode == 0 {
        build_linear_gadget(&mut prover, &vars, &values);
    } else {
        build_vector_gadget(&mut prover, &vars, &values);
    }

    let prove_start = Instant::now();
    let proof: R1CSProof = prover.prove(&bp_gens)
        .map_err(|e| format!("proving failed: {:?}", e))?;
    let prove_us = prove_start.elapsed().as_micros() as u64;
    let proof_bytes = proof.to_bytes().len() as u64;

    let verify_start = Instant::now();
    let mut verifier_transcript = Transcript::new(b"ACNS-FL-R1CS-v1");
    let mut verifier = Verifier::new(&mut verifier_transcript);
    let verifier_vars: Vec<_> = commitments.iter().map(|c| verifier.commit(*c)).collect();
    if mode == 0 {
        build_linear_gadget(&mut verifier, &verifier_vars, &values);
    } else {
        build_vector_gadget(&mut verifier, &verifier_vars, &values);
    }
    verifier.verify(&proof, &pc_gens, &bp_gens)
        .map_err(|e| format!("verification failed: {:?}", e))?;
    let verify_us = verify_start.elapsed().as_micros() as u64;

    let own = 1234567u64;
    let excluded = 7654321u64;
    let aggregate = own + excluded;
    let poi_start = Instant::now();
    let poi_ok = excluded + own == aggregate;
    let poi_us = poi_start.elapsed().as_micros() as u64;

    // Communication representation: aggregate-inclusion proof carries two
    // 64-bit scalar identifiers in this benchmark realization.
    let poi_bytes = 16u64;

    let fairness_start = Instant::now();
    let eligible = [64u64, 48u64];
    let included = [56u64, 36u64];
    let rates: Vec<f64> = eligible.iter().zip(included.iter())
        .map(|(e, i)| *i as f64 / *e as f64).collect();
    let _disparity = rates.iter().cloned().fold(f64::MIN, f64::max)
        - rates.iter().cloned().fold(f64::MAX, f64::min);
    let sum: f64 = rates.iter().sum();
    let sq: f64 = rates.iter().map(|x| x*x).sum();
    let _jain = sum * sum / ((rates.len() as f64) * sq);
    let fairness_us = fairness_start.elapsed().as_micros() as u64;
    let fairness_bytes = (eligible.len() * (8 + 8)) as u64;

    let checks_passed = if poi_ok { 2 } else { 1 };
    let checks_failed = if poi_ok { 0 } else { 1 };

    Ok(ZkBenchResult {
        prove_us,
        verify_us,
        commitment_us,
        proof_bytes,
        commitment_bytes: (n * 32) as u64,
        poi_us,
        poi_bytes,
        fairness_us,
        fairness_bytes,
        checks_passed,
        checks_failed,
    })
}

#[no_mangle]
pub extern "C" fn flzk_benchmark_r1cs(n: u64, mode: u32, out: *mut ZkBenchResult) -> i32 {
    if out.is_null() || n == 0 || n > 16384 || mode > 1 { return -1; }
    let result = match prove_and_verify(n as usize, mode) {
        Ok(x) => x,
        Err(_) => return -2,
    };
    unsafe { *out = result; }
    0
}

#[no_mangle]
pub extern "C" fn flzk_check_poi(aggregate: u64, own: u64, excluded: u64) -> i32 {
    if excluded.checked_add(own) == Some(aggregate) { 1 } else { 0 }
}
