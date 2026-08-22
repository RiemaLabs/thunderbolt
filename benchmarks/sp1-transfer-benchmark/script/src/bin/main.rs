use std::fmt;
use std::time::{Duration, Instant};

use clap::Parser;
use libpaillier::{unknown_order::BigNumber, Ciphertext, DecryptionKey, EncryptionKey, Nonce};
use serde::Serialize;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};
use transfer_compare_lib::{prove_full_relation, FullBenchmarkInput, FullBenchmarkPublicValues};

const TRANSFER_COMPARE_ELF: Elf = include_elf!("transfer-compare-program");

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    #[arg(long, default_value = "10")]
    iterations: usize,

    #[arg(long, default_value = "3072")]
    paillier_bits: usize,

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
    paillier_bits: usize,
    execute: Option<StageSummary>,
    prove: Option<StageSummary>,
    verify: Option<StageSummary>,
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
            average_secs: if self.count == 0 { 0.0 } else { self.total.as_secs_f64() / self.count as f64 },
            min_secs: self.min.as_secs_f64(),
            max_secs: self.max.as_secs_f64(),
        }
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "sp1 invoice+transfer Paillier benchmark")?;
        writeln!(f, "iterations: {}", self.iterations)?;
        writeln!(f, "paillier bits: {}", self.paillier_bits)?;
        writeln!(f, "stage          avg (ms)   min (ms)   max (ms)   total (ms)")?;
        writeln!(f, "---------------------------------------------------------")?;
        if let Some(exec) = &self.execute {
            writeln!(f, "execute      {:>9.3} {:>10.3} {:>10.3} {:>11.3}", exec.average_secs * 1e3, exec.min_secs * 1e3, exec.max_secs * 1e3, exec.total_secs * 1e3)?;
        }
        if let Some(prove) = &self.prove {
            writeln!(f, "prove        {:>9.3} {:>10.3} {:>10.3} {:>11.3}", prove.average_secs * 1e3, prove.min_secs * 1e3, prove.max_secs * 1e3, prove.total_secs * 1e3)?;
        }
        if let Some(verify) = &self.verify {
            writeln!(f, "verify       {:>9.3} {:>10.3} {:>10.3} {:>11.3}", verify.average_secs * 1e3, verify.min_secs * 1e3, verify.max_secs * 1e3, verify.total_secs * 1e3)?;
        }
        writeln!(f, "total        {:>9.3} {:>10.3} {:>10.3} {:>11.3}", self.total.average_secs * 1e3, self.total.min_secs * 1e3, self.total.max_secs * 1e3, self.total.total_secs * 1e3)?;
        Ok(())
    }
}

fn ensure_non_negative(label: &str, value: &BigNumber) {
    assert!(value >= &BigNumber::zero(), "{label} must be non-negative");
}

fn validate_nonce(pk: &EncryptionKey, nonce: &Nonce) {
    ensure_non_negative("Paillier nonce", nonce);
    assert!(!nonce.is_zero(), "Paillier nonce must be non-zero");
    assert!(nonce < pk.n(), "Paillier nonce must be smaller than N");
    assert_eq!(nonce.gcd(pk.n()), BigNumber::one(), "Paillier nonce must lie in Z_N*");
}

fn random_nonce_in_group(pk: &EncryptionKey) -> Nonce {
    loop {
        let candidate = Nonce::random(pk.n());
        if !candidate.is_zero() && candidate < *pk.n() && candidate.gcd(pk.n()) == BigNumber::one() {
            return candidate;
        }
    }
}

fn paillier_generator(pk: &EncryptionKey) -> BigNumber {
    pk.n() + BigNumber::one()
}

fn compose_ciphertext(pk: &EncryptionKey, exponent: &BigNumber, nonce: &Nonce) -> Ciphertext {
    ensure_non_negative("Paillier exponent", exponent);
    validate_nonce(pk, nonce);
    let g_term = paillier_generator(pk).modpow(exponent, pk.nn());
    let n_term = nonce.modpow(pk.n(), pk.nn());
    g_term.modmul(&n_term, pk.nn())
}

fn add_ciphertexts(pk: &EncryptionKey, left: &Ciphertext, right: &Ciphertext) -> Ciphertext {
    left.modmul(right, pk.nn())
}

fn combine_response_nonce(pk: &EncryptionKey, commitment_nonce: &Nonce, witness_nonce: &Nonce, challenge: &BigNumber) -> Nonce {
    validate_nonce(pk, commitment_nonce);
    validate_nonce(pk, witness_nonce);
    ensure_non_negative("Fiat-Shamir challenge", challenge);
    let witness_term = witness_nonce.modpow(challenge, pk.n());
    let response = commitment_nonce.modmul(&witness_term, pk.n());
    validate_nonce(pk, &response);
    response
}

fn deterministic_big_number(seed: u64, iteration: usize) -> BigNumber {
    BigNumber::from(seed + iteration as u64)
}

fn to_fixed(value: &BigNumber, width_bytes: usize) -> Vec<u8> {
    let bytes = value.to_bytes();
    assert!(bytes.len() <= width_bytes, "value does not fit in fixed benchmark encoding");
    let mut out = vec![0u8; width_bytes];
    out[width_bytes - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn paillier_keypair(bits: usize) -> (DecryptionKey, EncryptionKey) {
    assert!(bits % 2 == 0, "Paillier modulus bits must be even");
    let prime_bits = bits / 2;
    let p = BigNumber::prime(prime_bits);
    let mut q = BigNumber::prime(prime_bits);
    while p == q {
        q = BigNumber::prime(prime_bits);
    }
    let sk = DecryptionKey::with_primes_unchecked(&p, &q).expect("failed to construct Paillier keypair");
    let pk = EncryptionKey::from(&sk);
    (sk, pk)
}

fn prepare_input(iteration: usize, paillier_bits: usize) -> FullBenchmarkInput {
    let width_bytes = paillier_bits / 8;
    let ciphertext_bytes = width_bytes * 2;

    let (_bob_sk, bob_pk) = paillier_keypair(paillier_bits);
    let (_committee_sk, committee_pk) = paillier_keypair(paillier_bits);

    let refresh = deterministic_big_number(17, iteration);
    let holder_secret = deterministic_big_number(33, iteration);

    let bob_nonce = random_nonce_in_group(&bob_pk);
    let committee_nonce = random_nonce_in_group(&committee_pk);
    let ct_b = compose_ciphertext(&bob_pk, &refresh, &bob_nonce);
    let ct_c = compose_ciphertext(&committee_pk, &refresh, &committee_nonce);

    let alpha_invoice = deterministic_big_number(49, iteration);
    let beta_bob = random_nonce_in_group(&bob_pk);
    let beta_committee = random_nonce_in_group(&committee_pk);
    let a_b = compose_ciphertext(&bob_pk, &alpha_invoice, &beta_bob);
    let a_c = compose_ciphertext(&committee_pk, &alpha_invoice, &beta_committee);
    let challenge_invoice = deterministic_big_number(65, iteration);
    let z_invoice = alpha_invoice.clone() + challenge_invoice.clone() * refresh.clone();
    let tau_b = combine_response_nonce(&bob_pk, &beta_bob, &bob_nonce, &challenge_invoice);
    let tau_c = combine_response_nonce(&committee_pk, &beta_committee, &committee_nonce, &challenge_invoice);

    let holder_nonce = random_nonce_in_group(&bob_pk);
    let holder_component = compose_ciphertext(&bob_pk, &holder_secret, &holder_nonce);
    let next_holder_ciphertext = add_ciphertexts(&bob_pk, &holder_component, &ct_b);
    let alpha_transfer = deterministic_big_number(81, iteration);
    let beta_transfer = random_nonce_in_group(&bob_pk);
    let a_t = compose_ciphertext(&bob_pk, &alpha_transfer, &beta_transfer);
    let challenge_transfer = deterministic_big_number(97, iteration);
    let z_transfer = alpha_transfer.clone() + challenge_transfer.clone() * holder_secret.clone();
    let tau_transfer = combine_response_nonce(&bob_pk, &beta_transfer, &holder_nonce, &challenge_transfer);

    FullBenchmarkInput {
        modulus_bits: paillier_bits,
        invoice: transfer_compare_lib::InvoicePaillierInput {
            bob_modulus: to_fixed(bob_pk.n(), width_bytes),
            committee_modulus: to_fixed(committee_pk.n(), width_bytes),
            bob_ciphertext: to_fixed(&ct_b, ciphertext_bytes),
            committee_ciphertext: to_fixed(&ct_c, ciphertext_bytes),
            a_bob: to_fixed(&a_b, ciphertext_bytes),
            a_committee: to_fixed(&a_c, ciphertext_bytes),
            challenge: to_fixed(&challenge_invoice, width_bytes),
            z: to_fixed(&z_invoice, width_bytes),
            tau_bob: to_fixed(&tau_b, width_bytes),
            tau_committee: to_fixed(&tau_c, width_bytes),
        },
        transfer: transfer_compare_lib::TransferPaillierInput {
            bob_modulus: to_fixed(bob_pk.n(), width_bytes),
            invoice_ciphertext: to_fixed(&ct_b, ciphertext_bytes),
            next_holder_ciphertext: to_fixed(&next_holder_ciphertext, ciphertext_bytes),
            a_ciphertext: to_fixed(&a_t, ciphertext_bytes),
            challenge: to_fixed(&challenge_transfer, width_bytes),
            z: to_fixed(&z_transfer, width_bytes),
            tau: to_fixed(&tau_transfer, width_bytes),
        },
    }
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();
    if args.execute == args.prove {
        eprintln!("Specify exactly one of --execute or --prove");
        std::process::exit(1);
    }

    let client = ProverClient::from_env();
    let mut execute_acc = Acc::default();
    let mut prove_acc = Acc::default();
    let mut verify_acc = Acc::default();
    let mut total_acc = Acc::default();

    let proving_key = if args.prove {
        Some(client.setup(TRANSFER_COMPARE_ELF).expect("failed to setup SP1 program"))
    } else {
        None
    };

    for i in 0..args.iterations {
        let total_start = Instant::now();
        let input = prepare_input(i, args.paillier_bits);

        let mut stdin = SP1Stdin::new();
        stdin.write(&input);

        let expected = prove_full_relation(&input);

        if args.execute {
            let exec_start = Instant::now();
            let (output, _report) = client.execute(TRANSFER_COMPARE_ELF, stdin).run().expect("execute failed");
            execute_acc.record(exec_start.elapsed());
            let public_values = FullBenchmarkPublicValues::from_bytes(output.as_slice());
            assert_eq!(public_values, expected);
        } else {
            let pk = proving_key.as_ref().unwrap();
            let prove_start = Instant::now();
            let proof = client.prove(pk, stdin).run().expect("prove failed");
            prove_acc.record(prove_start.elapsed());
            let verify_start = Instant::now();
            client.verify(&proof, pk.verifying_key(), None).expect("verify failed");
            verify_acc.record(verify_start.elapsed());
        }

        total_acc.record(total_start.elapsed());
    }

    let report = Report {
        iterations: args.iterations,
        paillier_bits: args.paillier_bits,
        execute: if args.execute { Some(execute_acc.finish()) } else { None },
        prove: if args.prove { Some(prove_acc.finish()) } else { None },
        verify: if args.prove { Some(verify_acc.finish()) } else { None },
        total: total_acc.finish(),
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).expect("json encode failed"));
    } else {
        println!("{report}");
    }
}
