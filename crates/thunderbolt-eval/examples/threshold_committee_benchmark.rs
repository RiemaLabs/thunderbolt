use std::path::PathBuf;

use thunderbolt_mock::threshold_committee::{
    run_threshold_committee_suite, CommitteeShape, ThresholdCommitteeBenchmarkConfig,
};

fn parse_committee_shape(value: &str) -> Option<CommitteeShape> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    if let Some((threshold, committee_size)) = value.split_once("-of-") {
        let threshold = threshold.trim().parse::<usize>().ok()?;
        let committee_size = committee_size.trim().parse::<usize>().ok()?;
        return CommitteeShape::new(threshold, committee_size).ok();
    }

    let committee_size = value.parse::<usize>().ok()?;
    let threshold = (2 * committee_size).div_ceil(3);
    CommitteeShape::new(threshold, committee_size).ok()
}

fn main() {
    let mut iterations = 5usize;
    let mut committee_shapes = Vec::new();
    let mut csv_path = PathBuf::from("artifacts/threshold-committee-benchmark.csv");
    let mut fanout = 4usize;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--sizes" || arg == "--shapes" || arg == "--committees" {
            let value = args.next().expect("shape flag requires a comma-separated value");
            committee_shapes = value
                .split(',')
                .filter_map(parse_committee_shape)
                .collect();
        } else if arg == "--csv" {
            csv_path = PathBuf::from(args.next().expect("--csv requires a file path"));
        } else if arg == "--fanout" {
            fanout = args
                .next()
                .expect("--fanout requires a value")
                .parse()
                .expect("--fanout must be a positive integer");
        } else if let Ok(value) = arg.parse::<usize>() {
            iterations = value;
        }
    }

    let report = run_threshold_committee_suite(ThresholdCommitteeBenchmarkConfig {
        iterations,
        committee_shapes,
        fanout,
        ..ThresholdCommitteeBenchmarkConfig::default()
    })
    .expect("threshold committee benchmark should complete successfully");

    println!("{report}");
    report
        .write_csv(&csv_path)
        .expect("threshold committee benchmark should write CSV successfully");
    println!("csv written to {}", csv_path.display());
}
