use std::env;
use std::fs::OpenOptions;
use std::hint::black_box;
use std::io::Write as _;
use std::path::Path;
use std::time::Instant;

use chacha20::ChaCha20Rng;
use rand_core::{Rng as _, SeedableRng as _};
use zeroize::Zeroizing;

use crate::tests::secret_key;
use crate::types::EncryptionNonce3072;
use crate::{
    Ciphertext3072, Encryption3072, PublicExponent3072, PublicKey3072, SecretPlaintext3072, SecretPlaintextBytes3072,
    MODULUS_BYTES,
};

const RUN_ENV: &str = "THUNDERBOLT_CT_RUN";
const SAMPLES_ENV: &str = "THUNDERBOLT_CT_SAMPLES";
const WARMUP_ENV: &str = "THUNDERBOLT_CT_WARMUP";
const SEED_ENV: &str = "THUNDERBOLT_CT_SEED";
const CSV_DIR_ENV: &str = "THUNDERBOLT_CT_CSV_DIR";
const DEFAULT_SAMPLES: usize = 512;
const DEFAULT_WARMUP: usize = 32;
const SIGNAL_T: f64 = 10.0;

#[test]
#[ignore = "opt-in statistical experiment; set THUNDERBOLT_CT_RUN=1"]
fn timing_decrypt_welch_t_experiment() {
    let Some(config) = TimingConfig::load(0x44, "decrypt") else {
        return;
    };
    let fixture_key = secret_key();
    let keys = [
        fixture_key
            .decryption_key_for_timing_test(0)
            .expect("primary timing-test decryption key"),
        fixture_key
            .decryption_key_for_timing_test(1)
            .expect("equivalent timing-test decryption key"),
    ];
    let public_key = keys[0].public_key();
    let plaintext = plaintext(public_key, 0x_0123_4567_89ab_cdef);
    let mut encryption_rng = ChaCha20Rng::from_seed([0x91; 32]);
    let fixed_ciphertext = public_key
        .encrypt_with_rng_for_test(&plaintext, &mut encryption_rng)
        .expect("fixed timing-test ciphertext")
        .ciphertext()
        .clone();

    let primary_result = keys[0]
        .decrypt(&fixed_ciphertext)
        .expect("primary timing-test decryption");
    let alternate_result = keys[1]
        .decrypt(&fixed_ciphertext)
        .expect("alternate timing-test decryption");
    assert_eq!(
        primary_result.to_secret_bytes().as_ref(),
        alternate_result.to_secret_bytes().as_ref()
    );

    let mut order_rng = ChaCha20Rng::from_seed(config.seed);
    for class in shuffled_balanced_classes(config.warmup, &mut order_rng) {
        let key = black_box(&keys[class]);
        let result = key
            .decrypt(black_box(&fixed_ciphertext))
            .expect("timing-test warmup decryption");
        black_box(&result);
    }

    let mut classes = [OnlineStats::default(), OnlineStats::default()];
    let mut sample_log = Vec::with_capacity(config.samples);
    for class in shuffled_balanced_classes(config.samples, &mut order_rng) {
        let key = black_box(&keys[class]);
        let start = Instant::now();
        let result = key
            .decrypt(black_box(&fixed_ciphertext))
            .expect("timing-test measured decryption");
        black_box(&result);
        let elapsed_ns = start.elapsed().as_secs_f64() * 1_000_000_000.0;
        classes[class].record(elapsed_ns);
        sample_log.push((class, elapsed_ns));
    }

    write_sample_csv("decrypt", &config, fixed_ciphertext.fingerprint(), &sample_log)
        .expect("decrypt timing sample CSV");
    report("decrypt", &config, fixed_ciphertext.fingerprint(), classes).expect("finite decrypt Welch statistics");
}

#[test]
#[ignore = "opt-in statistical experiment; set THUNDERBOLT_CT_RUN=1"]
fn timing_proof_response_welch_t_experiment() {
    let Some(config) = TimingConfig::load(0x50, "proof_response") else {
        return;
    };
    let public_key = secret_key().public_key();
    let challenge = PublicExponent3072::from_bytes([0x2b]).expect("fixed public challenge");
    let mut ciphertext_rng = ChaCha20Rng::from_seed([0x92; 32]);
    let statement_ciphertext = public_key
        .encrypt_with_rng_for_test(&plaintext(public_key, 37), &mut ciphertext_rng)
        .expect("fixed statement ciphertext")
        .ciphertext()
        .clone();
    let commitment_ciphertext = public_key
        .encrypt_with_rng_for_test(&plaintext(public_key, 41), &mut ciphertext_rng)
        .expect("fixed commitment ciphertext")
        .ciphertext()
        .clone();

    let mut order_rng = ChaCha20Rng::from_seed(config.seed);
    let mut secret_rng = ChaCha20Rng::from_seed(domain_seed(config.seed, 0xa5));
    for class in shuffled_balanced_classes(config.warmup, &mut order_rng) {
        let (statement, commitment) = proof_openings(
            public_key,
            &statement_ciphertext,
            &commitment_ciphertext,
            class,
            &mut secret_rng,
        );
        let result = public_key
            .consume_proof_openings(statement, commitment, &challenge)
            .expect("timing-test proof warmup");
        black_box(&result);
    }

    let classes_order = shuffled_balanced_classes(config.samples, &mut order_rng);
    let prepared = classes_order
        .into_iter()
        .map(|class| {
            let (statement, commitment) = proof_openings(
                public_key,
                &statement_ciphertext,
                &commitment_ciphertext,
                class,
                &mut secret_rng,
            );
            (class, statement, commitment)
        })
        .collect::<Vec<_>>();

    let mut classes = [OnlineStats::default(), OnlineStats::default()];
    let mut sample_log = Vec::with_capacity(config.samples);
    for (class, statement, commitment) in prepared {
        let start = Instant::now();
        let result = public_key
            .consume_proof_openings(statement, commitment, black_box(&challenge))
            .expect("timing-test measured proof response");
        black_box(&result);
        let elapsed_ns = start.elapsed().as_secs_f64() * 1_000_000_000.0;
        classes[class].record(elapsed_ns);
        sample_log.push((class, elapsed_ns));
    }

    write_sample_csv(
        "proof_response",
        &config,
        statement_ciphertext.fingerprint(),
        &sample_log,
    )
    .expect("proof-response timing sample CSV");
    report("proof_response", &config, statement_ciphertext.fingerprint(), classes)
        .expect("finite proof-response Welch statistics");
}

fn proof_openings(
    public_key: &PublicKey3072,
    statement_ciphertext: &Ciphertext3072,
    commitment_ciphertext: &Ciphertext3072,
    class: usize,
    secret_rng: &mut ChaCha20Rng,
) -> (Encryption3072, Encryption3072) {
    let (statement_nonce, commitment_nonce) = if class == 0 {
        (nonce(public_key, 5), nonce(public_key, 3))
    } else {
        (
            public_key.sample_nonce_for_test(secret_rng),
            public_key.sample_nonce_for_test(secret_rng),
        )
    };
    let statement = public_key
        .opening_for_timing_test(statement_ciphertext, statement_nonce)
        .expect("key-bound statement opening");
    let commitment = public_key
        .opening_for_timing_test(commitment_ciphertext, commitment_nonce)
        .expect("key-bound commitment opening");
    (statement, commitment)
}

fn plaintext(public_key: &PublicKey3072, value: u64) -> SecretPlaintext3072 {
    public_key
        .plaintext_from_secret_bytes(
            SecretPlaintextBytes3072::left_pad(Zeroizing::new(value.to_be_bytes()))
                .expect("fixed timing-test plaintext width"),
        )
        .expect("timing-test plaintext below N")
}

fn nonce(public_key: &PublicKey3072, value: u64) -> EncryptionNonce3072 {
    let mut bytes = Zeroizing::new([0_u8; MODULUS_BYTES]);
    bytes[MODULUS_BYTES - 8..].copy_from_slice(&value.to_be_bytes());
    public_key
        .encryption_nonce_from_secret_bytes_for_test(bytes)
        .expect("fixed timing-test nonce")
}

#[derive(Clone, Copy)]
struct TimingConfig {
    samples: usize,
    warmup: usize,
    seed: [u8; 32],
}

impl TimingConfig {
    fn load(domain: u8, operation: &str) -> Option<Self> {
        if env::var(RUN_ENV).as_deref() != Ok("1") {
            eprintln!("CT_EXPERIMENT operation={operation} status=skipped reason=set_{RUN_ENV}_to_1");
            return None;
        }
        let samples = read_even_count(SAMPLES_ENV, DEFAULT_SAMPLES, 20, 100_000);
        let warmup = read_even_count(WARMUP_ENV, DEFAULT_WARMUP, 2, 10_000);
        let seed = domain_seed(read_seed(), domain);
        Some(Self { samples, warmup, seed })
    }
}

fn read_even_count(name: &str, default: usize, minimum: usize, maximum: usize) -> usize {
    let value = env::var(name)
        .ok()
        .map(|raw| {
            raw.parse::<usize>()
                .unwrap_or_else(|_| panic!("{name} must be an integer"))
        })
        .unwrap_or(default);
    assert!(
        (minimum..=maximum).contains(&value),
        "{name} must be in {minimum}..={maximum}"
    );
    assert_eq!(value % 2, 0, "{name} must be even for balanced classes");
    value
}

fn read_seed() -> [u8; 32] {
    let Some(raw) = env::var(SEED_ENV).ok() else {
        return [0xc7; 32];
    };
    let decoded = hex::decode(raw).expect("THUNDERBOLT_CT_SEED must be lower/upper hexadecimal");
    <[u8; 32]>::try_from(decoded).expect("THUNDERBOLT_CT_SEED must encode exactly 32 bytes")
}

fn domain_seed(mut seed: [u8; 32], domain: u8) -> [u8; 32] {
    seed[0] ^= domain;
    seed
}

fn shuffled_balanced_classes(samples: usize, rng: &mut ChaCha20Rng) -> Vec<usize> {
    let mut classes = (0..samples).map(|index| index & 1).collect::<Vec<_>>();
    for index in (1..classes.len()).rev() {
        let swap_with = (rng.next_u64() % (index as u64 + 1)) as usize;
        classes.swap(index, swap_with);
    }
    classes
}

#[derive(Clone, Copy, Default)]
struct OnlineStats {
    count: u64,
    mean: f64,
    m2: f64,
}

impl OnlineStats {
    fn record(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta_after = value - self.mean;
        self.m2 += delta * delta_after;
    }

    fn variance(self) -> f64 {
        self.m2 / (self.count.saturating_sub(1) as f64)
    }
}

fn checked_welch(classes: [OnlineStats; 2]) -> Result<(f64, f64), &'static str> {
    let left = classes[0];
    let right = classes[1];
    if left.count < 2 || right.count < 2 {
        return Err("each class requires at least two samples");
    }
    if !left.mean.is_finite() || !right.mean.is_finite() {
        return Err("class means are not finite");
    }
    let left_variance = left.variance();
    let right_variance = right.variance();
    if !left_variance.is_finite() || !right_variance.is_finite() || left_variance < 0.0 || right_variance < 0.0 {
        return Err("class variances are invalid");
    }
    let left_term = left_variance / left.count as f64;
    let right_term = right_variance / right.count as f64;
    let standard_error_squared = left_term + right_term;
    if !standard_error_squared.is_finite() || standard_error_squared <= 0.0 {
        return Err("Welch standard error is zero or non-finite");
    }
    let t = (left.mean - right.mean) / standard_error_squared.sqrt();
    if !t.is_finite() {
        return Err("Welch t statistic is not finite");
    }
    let degrees_denominator =
        left_term * left_term / (left.count - 1) as f64 + right_term * right_term / (right.count - 1) as f64;
    if !degrees_denominator.is_finite() || degrees_denominator <= 0.0 {
        return Err("Welch degrees-of-freedom denominator is invalid");
    }
    let degrees = standard_error_squared * standard_error_squared / degrees_denominator;
    if !degrees.is_finite() || degrees <= 0.0 {
        return Err("Welch degrees of freedom are invalid");
    }
    Ok((t, degrees))
}

fn report(
    operation: &str,
    config: &TimingConfig,
    public_fingerprint: [u8; 8],
    classes: [OnlineStats; 2],
) -> Result<(), &'static str> {
    let (t, degrees) = match checked_welch(classes) {
        Ok(statistics) => statistics,
        Err(reason) => {
            eprintln!("CT_EXPERIMENT operation={operation} status=invalid_statistics reason={reason}");
            return Err(reason);
        }
    };
    let signal = if t.abs() >= SIGNAL_T {
        "investigate"
    } else {
        "no_large_signal_observed"
    };
    eprintln!(
        "CT_EXPERIMENT operation={operation} status=measurement_only samples={} warmup={} seed={} \
         public_fingerprint={} class0_n={} class1_n={} class0_mean_ns={:.3} class1_mean_ns={:.3} \
         class0_variance_ns2={:.3} class1_variance_ns2={:.3} \
         welch_t={:.6} welch_df={:.2} heuristic_abs_t={} signal={signal}",
        config.samples,
        config.warmup,
        hex::encode(config.seed),
        hex::encode(public_fingerprint),
        classes[0].count,
        classes[1].count,
        classes[0].mean,
        classes[1].mean,
        classes[0].variance(),
        classes[1].variance(),
        t,
        degrees,
        SIGNAL_T,
    );
    eprintln!("CT_EXPERIMENT_NOTE operation={operation} result_is_statistical_evidence_not_a_constant_time_proof");
    Ok(())
}

fn write_sample_csv(
    operation: &str,
    config: &TimingConfig,
    public_fingerprint: [u8; 8],
    samples: &[(usize, f64)],
) -> std::io::Result<()> {
    let Some(directory) = env::var(CSV_DIR_ENV).ok() else {
        eprintln!("CT_EXPERIMENT_SAMPLES operation={operation} csv=disabled");
        return Ok(());
    };
    let path = Path::new(&directory).join(format!("{operation}-{}.csv", hex::encode(config.seed)));
    let mut output = OpenOptions::new().write(true).create_new(true).open(&path)?;
    writeln!(
        output,
        "# operation={operation},samples={},warmup={},seed={},public_fingerprint={}",
        config.samples,
        config.warmup,
        hex::encode(config.seed),
        hex::encode(public_fingerprint)
    )?;
    writeln!(output, "index,class,elapsed_ns")?;
    for (index, (class, elapsed_ns)) in samples.iter().enumerate() {
        writeln!(output, "{index},{class},{elapsed_ns:.3}")?;
    }
    output.flush()?;
    eprintln!("CT_EXPERIMENT_SAMPLES operation={operation} csv={}", path.display());
    Ok(())
}

#[test]
fn welch_known_case_is_stable() {
    let mut classes = [OnlineStats::default(), OnlineStats::default()];
    for value in [1.0, 2.0, 3.0, 4.0] {
        classes[0].record(value);
    }
    for value in [2.0, 4.0, 6.0, 8.0] {
        classes[1].record(value);
    }
    let (t, degrees) = checked_welch(classes).expect("known finite Welch case");
    assert!((t - -1.732_050_807_568_877_2).abs() < 1e-12);
    assert!((degrees - 4.411_764_705_882_353).abs() < 1e-12);
}

#[test]
fn welch_zero_variance_is_rejected() {
    let mut classes = [OnlineStats::default(), OnlineStats::default()];
    for _ in 0..4 {
        classes[0].record(7.0);
        classes[1].record(7.0);
    }
    assert_eq!(
        checked_welch(classes),
        Err("Welch standard error is zero or non-finite")
    );
}
