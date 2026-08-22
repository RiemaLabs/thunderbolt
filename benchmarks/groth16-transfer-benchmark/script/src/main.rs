use std::fmt;
use std::time::{Duration, Instant};

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use clap::Parser;
use rand::thread_rng;
use serde::Serialize;
use transfer_compare_lib::transfer_step;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "10")]
    iterations: usize,

    #[arg(long, default_value = "1000000")]
    padding_muls: usize,

    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct StageSummary {
    total_secs: f64,
    average_secs: f64,
    min_secs: f64,
    max_secs: f64,
}

#[derive(Clone, Debug, Serialize)]
struct Report {
    iterations: usize,
    padding_muls: usize,
    constraints: usize,
    setup_secs: f64,
    prove: StageSummary,
    verify: StageSummary,
    total: StageSummary,
}

#[derive(Clone, Debug, Default)]
struct Acc {
    total: Duration,
    min: Duration,
    max: Duration,
    count: usize,
}

impl Acc {
    fn record(&mut self, d: Duration) {
        if self.count == 0 {
            self.min = d;
            self.max = d;
        } else {
            self.min = self.min.min(d);
            self.max = self.max.max(d);
        }
        self.total += d;
        self.count += 1;
    }

    fn finish(&self) -> StageSummary {
        StageSummary {
            total_secs: self.total.as_secs_f64(),
            average_secs: if self.count == 0 {
                0.0
            } else {
                self.total.as_secs_f64() / self.count as f64
            },
            min_secs: self.min.as_secs_f64(),
            max_secs: self.max.as_secs_f64(),
        }
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "groth16 single-transfer benchmark")?;
        writeln!(f, "iterations: {}", self.iterations)?;
        writeln!(f, "padding mul constraints: {}", self.padding_muls)?;
        writeln!(f, "constraints: {}", self.constraints)?;
        writeln!(f, "setup: {:.3} ms", self.setup_secs * 1e3)?;
        writeln!(f, "stage          avg (ms)   min (ms)   max (ms)   total (ms)")?;
        writeln!(f, "---------------------------------------------------------")?;
        writeln!(
            f,
            "prove        {:>9.3} {:>10.3} {:>10.3} {:>11.3}",
            self.prove.average_secs * 1e3,
            self.prove.min_secs * 1e3,
            self.prove.max_secs * 1e3,
            self.prove.total_secs * 1e3
        )?;
        writeln!(
            f,
            "verify       {:>9.3} {:>10.3} {:>10.3} {:>11.3}",
            self.verify.average_secs * 1e3,
            self.verify.min_secs * 1e3,
            self.verify.max_secs * 1e3,
            self.verify.total_secs * 1e3
        )?;
        writeln!(
            f,
            "total        {:>9.3} {:>10.3} {:>10.3} {:>11.3}",
            self.total.average_secs * 1e3,
            self.total.min_secs * 1e3,
            self.total.max_secs * 1e3,
            self.total.total_secs * 1e3
        )?;
        Ok(())
    }
}

#[derive(Clone)]
struct TransferCircuit {
    holder_secret: u64,
    refresh: u64,
    committee_share: u64,
    padding_muls: usize,
    next_holder: u64,
    next_committee: u64,
    invariant_before: u64,
    invariant_after: u64,
}

impl TransferCircuit {
    fn from_values(holder_secret: u64, refresh: u64, committee_share: u64, padding_muls: usize) -> Self {
        let public_values = transfer_step(holder_secret, refresh, committee_share);
        Self {
            holder_secret,
            refresh,
            committee_share,
            padding_muls,
            next_holder: public_values.next_holder,
            next_committee: public_values.next_committee,
            invariant_before: public_values.invariant_before,
            invariant_after: public_values.invariant_after,
        }
    }

    fn public_inputs(&self) -> Vec<Fr> {
        vec![
            Fr::from(self.next_holder),
            Fr::from(self.next_committee),
            Fr::from(self.invariant_before),
            Fr::from(self.invariant_after),
        ]
    }
}

impl ConstraintSynthesizer<Fr> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let holder_secret = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(self.holder_secret)))?;
        let refresh = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(self.refresh)))?;
        let committee_share = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(self.committee_share)))?;

        let next_holder = FpVar::<Fr>::new_input(cs.clone(), || Ok(Fr::from(self.next_holder)))?;
        let next_committee = FpVar::<Fr>::new_input(cs.clone(), || Ok(Fr::from(self.next_committee)))?;
        let invariant_before = FpVar::<Fr>::new_input(cs.clone(), || Ok(Fr::from(self.invariant_before)))?;
        let invariant_after = FpVar::<Fr>::new_input(cs.clone(), || Ok(Fr::from(self.invariant_after)))?;

        let computed_next_holder = &holder_secret + &refresh;
        let computed_next_committee = &committee_share - &refresh;
        let computed_invariant_before = &holder_secret + &committee_share;
        let computed_invariant_after = &computed_next_holder + &computed_next_committee;

        // Synthetic padding to make the Groth16 benchmark exercise a substantially larger
        // constraint system than the bare transfer-step semantics alone.
        let pad_multiplier = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(3u64)))?;
        let mut pad_acc = &computed_invariant_before + &computed_invariant_after;
        for _ in 0..self.padding_muls {
            pad_acc = &pad_acc * &pad_multiplier;
        }
        let _ = pad_acc;

        computed_next_holder.enforce_equal(&next_holder)?;
        computed_next_committee.enforce_equal(&next_committee)?;
        computed_invariant_before.enforce_equal(&invariant_before)?;
        computed_invariant_after.enforce_equal(&invariant_after)?;
        computed_invariant_before.enforce_equal(&computed_invariant_after)?;

        Ok(())
    }
}

fn constraint_count(circuit: &TransferCircuit) -> usize {
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit
        .clone()
        .generate_constraints(cs.clone())
        .expect("constraint generation should succeed");
    cs.num_constraints()
}

fn main() {
    let args = Args::parse();
    let mut rng = thread_rng();

    let setup_circuit = TransferCircuit::from_values(11, 101, 10_000, args.padding_muls);
    let constraints = constraint_count(&setup_circuit);
    let setup_start = Instant::now();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut rng).expect("setup failed");
    let pvk = Groth16::<Bn254>::process_vk(&vk).expect("process vk failed");
    let setup_secs = setup_start.elapsed().as_secs_f64();

    let mut prove_acc = Acc::default();
    let mut verify_acc = Acc::default();
    let mut total_acc = Acc::default();

    for i in 0..args.iterations {
        let total_start = Instant::now();
        let holder_secret = 11_u64 + i as u64;
        let refresh = 101_u64 + (i as u64 % 97);
        let committee_share = 10_000_u64 + i as u64;
        let circuit = TransferCircuit::from_values(holder_secret, refresh, committee_share, args.padding_muls);
        let public_inputs = circuit.public_inputs();

        let prove_start = Instant::now();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).expect("prove failed");
        prove_acc.record(prove_start.elapsed());

        let verify_start = Instant::now();
        let verified =
            Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof).expect("verify failed");
        assert!(verified, "proof should verify");
        verify_acc.record(verify_start.elapsed());

        total_acc.record(total_start.elapsed());
    }

    let report = Report {
        iterations: args.iterations,
        padding_muls: args.padding_muls,
        constraints,
        setup_secs,
        prove: prove_acc.finish(),
        verify: verify_acc.finish(),
        total: total_acc.finish(),
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).expect("json encode failed"));
    } else {
        println!("{report}");
    }
}
