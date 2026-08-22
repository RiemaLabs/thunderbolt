use thunderbolt_mock::benchmark::{run_single_committee_benchmark, SingleCommitteeBenchmarkConfig};

fn main() {
    let iterations = std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100);

    let report = run_single_committee_benchmark(SingleCommitteeBenchmarkConfig { iterations })
        .expect("single-committee benchmark should complete successfully");

    println!("{report}");
}
