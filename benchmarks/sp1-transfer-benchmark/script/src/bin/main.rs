use std::fmt;
use std::time::{Duration, Instant};

use clap::Parser;
use serde::Serialize;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1Stdin,
};
use transfer_compare_lib::{transfer_step, TransferPublicValues};

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
        writeln!(f, "sp1 single-transfer benchmark")?;
        writeln!(f, "iterations: {}", self.iterations)?;
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
        let holder_secret = 11_u64 + i as u64;
        let refresh = 101_u64 + (i as u64 % 97);
        let committee_share = 10_000_u64 + i as u64;

        let mut stdin = SP1Stdin::new();
        stdin.write(&holder_secret);
        stdin.write(&refresh);
        stdin.write(&committee_share);

        let expected = transfer_step(holder_secret, refresh, committee_share);

        if args.execute {
            let exec_start = Instant::now();
            let (output, _report) = client.execute(TRANSFER_COMPARE_ELF, stdin).run().expect("execute failed");
            execute_acc.record(exec_start.elapsed());
            let public_values = TransferPublicValues::from_bytes(output.as_slice());
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
