use std::error::Error;
use std::path::{Path, PathBuf};

use proptest::prelude::*;
use sha2::{Digest, Sha256};
use thunderbolt_ledger::LedgerChainIdV2;
use thunderbolt_ledger_abci::{ConsensusProfileV2, StaticAdmissionRequestV2, StaticAdmissionVerifierV2};
use thunderbolt_protocol::v2::ProtocolLimitsV2;

use crate::*;

const LEDGER: &str = include_str!("../examples/ledger-regtest.toml");
const HOLDER: &str = include_str!("../examples/holder-regtest.toml");
const COMMITTEE: &str = include_str!("../examples/committee-regtest.toml");

struct TestCheckpointCapability {
    provider: [u8; 32],
    trust_domain: [u8; 32],
    policy: [u8; 32],
}

impl CheckpointProviderCapability for TestCheckpointCapability {
    fn provider_id(&self) -> [u8; 32] {
        self.provider
    }

    fn trust_domain_id(&self) -> [u8; 32] {
        self.trust_domain
    }

    fn policy_profile_id(&self) -> [u8; 32] {
        self.policy
    }
}

struct TestAdmissionIdentity {
    verifier_profile: [u8; 32],
    deployment_descriptor: [u8; 32],
}

impl StaticAdmissionVerifierV2 for TestAdmissionIdentity {
    type Error = ();

    fn verifier_profile_id(&self) -> [u8; 32] {
        self.verifier_profile
    }

    fn deployment_descriptor(&self) -> [u8; 32] {
        self.deployment_descriptor
    }

    fn verify_static(&self, _request: StaticAdmissionRequestV2<'_>) -> std::result::Result<(), Self::Error> {
        Err(())
    }
}

#[test]
fn three_regtest_samples_map_and_cross_check() -> std::result::Result<(), Box<dyn Error>> {
    let ledger = ParsedRuntimeConfig::parse_toml(LEDGER)?;
    let holder = ParsedRuntimeConfig::parse_toml(HOLDER)?;
    let committee = ParsedRuntimeConfig::parse_toml(COMMITTEE)?;
    assert_eq!(ledger.role(), RuntimeRole::Ledger);
    assert_eq!(holder.role(), RuntimeRole::Holder);
    assert_eq!(committee.role(), RuntimeRole::Committee);
    let consistent = check_deployment_consistency(&[&ledger, &holder, &committee])?;
    assert_eq!(consistent.config_count(), 3);
    assert_eq!(consistent.committee_member_count(), 1);
    Ok(())
}

#[test]
fn unknown_and_secret_fields_fail_closed() {
    let unknown = HOLDER.replace("[holder]", "unexpected = 1\n\n[holder]");
    assert!(ParsedRuntimeConfig::parse_toml(&unknown).is_err());
    let password = HOLDER.replace("[holder]", "password = \"not-allowed\"\n\n[holder]");
    assert!(matches!(
        ParsedRuntimeConfig::parse_toml(&password),
        Err(ConfigError::SecretValueForbidden)
    ));
    let token = HOLDER.replace("[holder]", "api_token = \"not-allowed\"\n\n[holder]");
    assert!(matches!(
        ParsedRuntimeConfig::parse_toml(&token),
        Err(ConfigError::SecretValueForbidden)
    ));
}

#[test]
fn network_crypto_and_signing_claims_fail_closed() -> std::result::Result<(), Box<dyn Error>> {
    let capabilities = CapabilityBoundary;
    assert!(!capabilities.holder_signing_available());
    assert!(!capabilities.committee_threshold_signing_available());
    assert!(!capabilities.production_paillier_3072_available());
    assert!(!capabilities.external_checkpoint_providers_ready());
    assert!(!capabilities.authenticated_comet_transport_ready());
    for network in ["mainnet", "testnet4"] {
        let changed = HOLDER.replace("network = \"regtest\"", &format!("network = \"{network}\""));
        assert!(ParsedRuntimeConfig::parse_toml(&changed).is_err());
    }
    for (from, to) in [
        ("holder_signing = \"unavailable\"", "holder_signing = \"production\""),
        (
            "committee_threshold_signing = \"unavailable\"",
            "committee_threshold_signing = \"production\"",
        ),
        (
            "paillier_profile = \"legacy_rc2048_v1\"",
            "paillier_profile = \"protocol_v2_production3072\"",
        ),
        (
            "deployment_mode = \"non_production\"",
            "deployment_mode = \"production\"",
        ),
    ] {
        assert!(ParsedRuntimeConfig::parse_toml(&HOLDER.replace(from, to)).is_err());
    }
    let parsed = ParsedRuntimeConfig::parse_toml(HOLDER)?;
    let requirement = parsed
        .candidate
        .paths()
        .vault_checkpoint_provider()
        .ok_or("vault checkpoint requirement")?;
    let matching = TestCheckpointCapability {
        provider: *requirement.required_provider_id(),
        trust_domain: *requirement.required_trust_domain_id(),
        policy: *requirement.policy_profile_id(),
    };
    assert!(requirement.accepts(&matching));
    assert!(!parsed
        .candidate
        .paths()
        .trust_checkpoint_provider()
        .ok_or("trust checkpoint requirement")?
        .accepts(&matching));
    Ok(())
}

#[test]
fn path_url_and_limit_cliffs_are_rejected() {
    let relative = HOLDER.replace(
        "data_dir = \"/var/lib/thunderbolt/regtest/holder-01\"",
        "data_dir = \"relative/holder-01\"",
    );
    assert!(ParsedRuntimeConfig::parse_toml(&relative).is_err());
    let traversal = HOLDER.replace(
        "service_db = \"/var/lib/thunderbolt/regtest/holder-01/service.sqlite3\"",
        "service_db = \"/var/lib/thunderbolt/regtest/holder-01/../shared.sqlite3\"",
    );
    assert!(ParsedRuntimeConfig::parse_toml(&traversal).is_err());
    for endpoint in [
        "http://user:password@127.0.0.1:18443/",
        "http://192.0.2.1:18443/",
        "http://127.0.0.1:18443/?token=x",
        "file:///tmp/bitcoin.sock",
    ] {
        let changed = HOLDER.replace(
            "endpoint = \"http://127.0.0.1:18443/\"",
            &format!("endpoint = \"{endpoint}\""),
        );
        assert!(ParsedRuntimeConfig::parse_toml(&changed).is_err());
    }
    for (from, to) in [
        ("operation_timeout_ms = 10000", "operation_timeout_ms = 0"),
        ("max_trace_encoded_bytes = 1048576", "max_trace_encoded_bytes = 0"),
        ("max_frame_bytes = 1048576", "max_frame_bytes = 0"),
        ("retry_maximum_attempts = 12", "retry_maximum_attempts = 0"),
    ] {
        assert!(ParsedRuntimeConfig::parse_toml(&HOLDER.replace(from, to)).is_err());
    }
}

#[test]
fn https_requires_explicit_ca_and_client_identity_references() -> std::result::Result<(), Box<dyn Error>> {
    let https = HOLDER
        .replace("http://127.0.0.1:26657/", "https://primary.example.invalid/")
        .replace("http://127.0.0.1:27657/", "https://witness.example.invalid/");
    assert!(ParsedRuntimeConfig::parse_toml(&https).is_err());
    let tls = concat!(
        "comet_tls = { ca_certificates = [{ path = \"/etc/thunderbolt/regtest/comet-ca.pem\", sha256 = ",
        "\"abababababababababababababababababababababababababababababababab\" }], ",
        "client_certificate_file = { path = \"/etc/thunderbolt/regtest/comet-client.pem\" }, ",
        "client_private_key_file = { path = \"/etc/thunderbolt/regtest/comet-client-key.pem\" } }\n"
    );
    let https = https
        .replace("[control]", &format!("{tls}\n[control]"))
        .replace(
            "50d4e01279dbb7fcf6cb0e8a7d407b7713d86b83346b13c60f13b52f8045728d",
            "fb3e96081aaf08654ff1e054b5d7ccf7b285096aa68795c71d666d4198267fc6",
        )
        .replace(
            "5e4d04cd79e904b5457c689d6c1f810f01c81c156ec637af30126f7a9fbfe7b8",
            "8887f5aca924dc7b2e89cc3117ce98687b06be9525022ff5426064a89ab2ae51",
        );
    ParsedRuntimeConfig::parse_toml(&https)?;
    assert!(ParsedRuntimeConfig::parse_toml(&https.replace(
        "https://primary.example.invalid/",
        "https://primary.example.invalid/rpc",
    ))
    .is_err());
    assert!(ParsedRuntimeConfig::parse_toml(
        &https.replace("https://primary.example.invalid/", "https://primary.example.invalid:0/",)
    )
    .is_err());
    let ambiguous = https
        .replace("https://primary.example.invalid/", "http://127.0.0.1:26657/")
        .replace("https://witness.example.invalid/", "http://127.0.0.1:27657/");
    assert!(ParsedRuntimeConfig::parse_toml(&ambiguous).is_err());
    Ok(())
}

#[test]
fn identity_profile_and_cross_role_tamper_fail() -> std::result::Result<(), Box<dyn Error>> {
    let bad_profile = HOLDER.replace(
        "4ba1fc95b531329ae4161c164302210a740b60e9071859687aa64d3ebbad53c2",
        "4ba1fc95b531329ae4161c164302210a740b60e9071859687aa64d3ebbad53c3",
    );
    assert!(ParsedRuntimeConfig::parse_toml(&bad_profile).is_err());
    let bad_descriptor = HOLDER.replace(
        "committee_descriptor_digest = \"2222222222222222222222222222222222222222222222222222222222222222\"",
        "committee_descriptor_digest = \"2322222222222222222222222222222222222222222222222222222222222222\"",
    );
    assert!(ParsedRuntimeConfig::parse_toml(&bad_descriptor).is_err());
    assert!(ParsedRuntimeConfig::parse_toml(
        &HOLDER.replace("trusting_period_seconds = 120", "trusting_period_seconds = 121")
    )
    .is_err());
    assert!(ParsedRuntimeConfig::parse_toml(&COMMITTEE.replace(
        "trust_root_header_hash = \"9999999999999999999999999999999999999999999999999999999999999999\"",
        "trust_root_header_hash = \"9899999999999999999999999999999999999999999999999999999999999999\"",
    ))
    .is_err());
    let ledger = ParsedRuntimeConfig::parse_toml(LEDGER)?;
    let holder = ParsedRuntimeConfig::parse_toml(HOLDER)?;
    let drifted_committee = ParsedRuntimeConfig::parse_toml(&COMMITTEE.replace(
        "deployment_id_hex = \"7468756e646572626f6c742d72656774657374\"",
        "deployment_id_hex = \"7468756e646572626f6c742d72656774657375\"",
    ))?;
    assert!(check_deployment_consistency(&[&ledger, &holder, &drifted_committee]).is_err());
    let reused_paths = COMMITTEE.replace(
        "/var/lib/thunderbolt/regtest/committee-01",
        "/var/lib/thunderbolt/regtest/holder-01",
    );
    let reused_paths = reused_paths.replace(
        "/run/user/1000/thunderbolt-regtest-committee-01",
        "/run/user/1000/thunderbolt-regtest-holder-01",
    );
    let reused_paths = ParsedRuntimeConfig::parse_toml(&reused_paths)?;
    assert!(check_deployment_consistency(&[&ledger, &holder, &reused_paths]).is_err());
    let reused_coordinator = ParsedRuntimeConfig::parse_toml(&COMMITTEE.replace(
        "7272727272727272727272727272727272727272727272727272727272727272",
        "7171717171717171717171717171717171717171717171717171717171717171",
    ))?;
    assert!(check_deployment_consistency(&[&ledger, &holder, &reused_coordinator]).is_err());
    let cross_alias_holder = ParsedRuntimeConfig::parse_toml(&HOLDER.replace(
        "/etc/thunderbolt/regtest/holder-01-vault-password",
        "/var/lib/thunderbolt/regtest/committee-01/service.sqlite3",
    ))?;
    let committee = ParsedRuntimeConfig::parse_toml(COMMITTEE)?;
    assert!(check_deployment_consistency(&[&ledger, &cross_alias_holder, &committee]).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn owner_only_files_validate_then_tamper_and_symlink_fail() -> std::result::Result<(), Box<dyn Error>> {
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    let directory = tempfile::tempdir()?;
    let root = std::fs::canonicalize(directory.path())?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    let fixture = FilesystemFixture::new(&root)?;
    let parsed = ParsedRuntimeConfig::parse_toml(&fixture.config)?;
    let effective = parsed.validate_filesystem()?;
    let handoff = effective.revalidate_for_handoff()?;
    assert!(handoff.holder().is_some());
    let _ = handoff.comet_transport()?;
    let redacted = effective.redacted().to_toml()?;
    assert!(!redacted.contains(root.to_string_lossy().as_ref()));
    assert!(!redacted.contains("127.0.0.1"));
    assert!(redacted.contains("unavailable"));

    std::fs::write(&fixture.descriptor, b"tampered")?;
    assert!(effective.revalidate_for_handoff().is_err());
    assert!(check_effective_deployment_consistency(&[&effective]).is_err());
    let parsed = ParsedRuntimeConfig::parse_toml(&fixture.config)?;
    assert!(matches!(
        parsed.validate_filesystem(),
        Err(ConfigError::ReferenceMismatch)
    ));

    std::fs::write(&fixture.descriptor, b"descriptor")?;
    let link = root.join("cookie-link");
    symlink(&fixture.cookie, &link)?;
    let linked_config = fixture.config.replace(&toml_path(&fixture.cookie), &toml_path(&link));
    let linked = ParsedRuntimeConfig::parse_toml(&linked_config)?;
    assert!(linked.validate_filesystem().is_err());

    let config_path = root.join("holder.toml");
    std::fs::write(&config_path, &fixture.config)?;
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))?;
    ParsedRuntimeConfig::load_owner_only(&config_path)?;
    let config_link = root.join("holder-link.toml");
    symlink(&config_path, &config_link)?;
    assert!(ParsedRuntimeConfig::load_owner_only(config_link).is_err());

    let nested_password = owner_file(&fixture.data, "nested-password", b"secret")?;
    let nested = fixture
        .config
        .replace(&toml_path(&root.join("vault.password")), &toml_path(&nested_password));
    assert!(ParsedRuntimeConfig::parse_toml(&nested).is_err());

    let alias_directory = tempfile::tempdir()?;
    let alias_root = std::fs::canonicalize(alias_directory.path())?;
    std::fs::set_permissions(&alias_root, std::fs::Permissions::from_mode(0o700))?;
    let alias_fixture = FilesystemFixture::new(&alias_root)?;
    let service = alias_fixture.data.join("service.sqlite3");
    let vault = alias_fixture.data.join("vault.tbks");
    std::fs::write(&service, b"alias")?;
    std::fs::set_permissions(&service, std::fs::Permissions::from_mode(0o600))?;
    std::fs::hard_link(&service, &vault)?;
    let alias = ParsedRuntimeConfig::parse_toml(&alias_fixture.config)?;
    assert!(alias.validate_filesystem().is_err());

    let unsafe_parent = root.join("unsafe-parent");
    std::fs::create_dir(&unsafe_parent)?;
    std::fs::set_permissions(&unsafe_parent, std::fs::Permissions::from_mode(0o777))?;
    let unsafe_config = unsafe_parent.join("holder.toml");
    std::fs::write(&unsafe_config, &fixture.config)?;
    std::fs::set_permissions(&unsafe_config, std::fs::Permissions::from_mode(0o600))?;
    assert!(ParsedRuntimeConfig::load_owner_only(unsafe_config).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn effective_consistency_revalidates_and_rejects_duplicate_checkpoint_domains(
) -> std::result::Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir()?;
    let root = std::fs::canonicalize(directory.path())?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    let common = CommonRoleFiles::new(&root)?;
    let ledger =
        ParsedRuntimeConfig::parse_toml(&materialize_role_sample(LEDGER, RuntimeRole::Ledger, &root, &common)?)?
            .validate_filesystem()?;
    let holder =
        ParsedRuntimeConfig::parse_toml(&materialize_role_sample(HOLDER, RuntimeRole::Holder, &root, &common)?)?
            .validate_filesystem()?;
    let committee_config = materialize_role_sample(COMMITTEE, RuntimeRole::Committee, &root, &common)?
        .replace(
            "417af1de2cc3a40d610071d6850b942a37cb57c1c218ccbd187326aa3fee271b",
            "f7be2f3033559fad96785b0cbe9499ca7b115f6927444346f4d13250b63b655f",
        )
        .replace(
            "64c0515f27e5fb2acdeff9635e785eb519dbeaa4bbb3e013e80d6a95a5a74630",
            "6294144c3dfb2d043dfae75aa960236e2a26b9af5429188168854ad3db924b0a",
        );
    let committee = ParsedRuntimeConfig::parse_toml(&committee_config)?.validate_filesystem()?;
    assert!(matches!(
        check_effective_deployment_consistency(&[&ledger, &holder, &committee]),
        Err(ConfigError::DeploymentMismatch)
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn https_material_is_constructor_compatible_and_rechecked() -> std::result::Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir()?;
    let root = std::fs::canonicalize(directory.path())?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    let fixture = FilesystemFixture::new(&root)?;
    let generated = rcgen::generate_simple_self_signed(vec!["client.example.invalid".to_owned()])?;
    let ca = owner_file(&root, "comet-ca.pem", generated.cert.pem().as_bytes())?;
    let certificate = owner_file(&root, "comet-client.pem", generated.cert.pem().as_bytes())?;
    let key = owner_file(
        &root,
        "comet-client-key.pem",
        generated.signing_key.serialize_pem().as_bytes(),
    )?;
    let ca_digest = digest(generated.cert.pem().as_bytes());
    let tls = format!(
        "comet_tls = {{ ca_certificates = [{{ path = \"{}\", sha256 = \"{}\" }}], client_certificate_file = {{ path = \"{}\" }}, client_private_key_file = {{ path = \"{}\" }} }}\n",
        toml_path(&ca),
        hex(&ca_digest),
        toml_path(&certificate),
        toml_path(&key),
    );
    let profile_digest = digest(b"profile");
    let http_policy = decode_hex32("50d4e01279dbb7fcf6cb0e8a7d407b7713d86b83346b13c60f13b52f8045728d")?;
    let https_policy = https_policy_digest(ca_digest);
    let http_finality = derived_pair(
        b"bitcoin-thunderbolt/runtime-config/finality-verifier-profile/v2",
        profile_digest,
        http_policy,
    );
    let https_finality = derived_pair(
        b"bitcoin-thunderbolt/runtime-config/finality-verifier-profile/v2",
        profile_digest,
        https_policy,
    );
    let config = fixture
        .config
        .replace("http://127.0.0.1:26657/", "https://primary.example.invalid/")
        .replace("http://127.0.0.1:27657/", "https://witness.example.invalid/")
        .replace("[control]", &format!("{tls}\n[control]"))
        .replace(&hex(&http_policy), &hex(&https_policy))
        .replace(&hex(&http_finality), &hex(&https_finality));
    let effective = ParsedRuntimeConfig::parse_toml(&config)?.validate_filesystem()?;
    let handoff = effective.revalidate_for_handoff()?;
    let loaded = handoff
        .holder()
        .ok_or("holder handoff")?
        .paths()
        .comet_tls()
        .ok_or("TLS references")?
        .load_for_handoff()?;
    assert_eq!(loaded.ca_certificates().len(), 1);
    let _ = handoff.comet_transport()?;
    std::fs::write(&ca, b"not a certificate")?;
    assert!(effective.revalidate_for_handoff().is_err());
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn arbitrary_toml_never_panics(input in prop::collection::vec(any::<u8>(), 0..4096)) {
        if let Ok(text) = std::str::from_utf8(&input) {
            let _ = ParsedRuntimeConfig::parse_toml(text);
        }
    }

    #[test]
    fn every_unknown_top_level_key_is_rejected(key in "[a-z]{1,24}", value in any::<u64>()) {
        prop_assume!(!["config_version", "role"].contains(&key.as_str()));
        let changed = HOLDER.replacen("config_version = 2", &format!("config_version = 2\n{key} = {value}"), 1);
        prop_assert!(ParsedRuntimeConfig::parse_toml(&changed).is_err());
    }
}

#[cfg(unix)]
struct FilesystemFixture {
    config: String,
    descriptor: PathBuf,
    cookie: PathBuf,
    data: PathBuf,
}

#[cfg(unix)]
struct CommonRoleFiles {
    descriptor: PathBuf,
    anchor: PathBuf,
    profile: PathBuf,
    trust_root: PathBuf,
    cookie: PathBuf,
}

#[cfg(unix)]
impl CommonRoleFiles {
    fn new(root: &Path) -> std::result::Result<Self, Box<dyn Error>> {
        Ok(Self {
            descriptor: owner_file(root, "shared-descriptor.json", b"descriptor")?,
            anchor: owner_file(root, "shared-anchor.json", b"anchor")?,
            profile: owner_file(root, "shared-profile.json", b"profile")?,
            trust_root: owner_file(root, "shared-trust-root.json", b"trust-root")?,
            cookie: owner_file(root, "shared-bitcoin.cookie", b"__cookie__:secret")?,
        })
    }
}

#[cfg(unix)]
fn materialize_role_sample(
    sample: &str,
    role: RuntimeRole,
    root: &Path,
    common: &CommonRoleFiles,
) -> std::result::Result<String, Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let (role_name, old_data, old_control) = match role {
        RuntimeRole::Ledger => (
            "ledger",
            "/var/lib/thunderbolt/regtest/ledger",
            "/run/user/1000/thunderbolt-regtest-ledger",
        ),
        RuntimeRole::Holder => (
            "holder",
            "/var/lib/thunderbolt/regtest/holder-01",
            "/run/user/1000/thunderbolt-regtest-holder-01",
        ),
        RuntimeRole::Committee => (
            "committee",
            "/var/lib/thunderbolt/regtest/committee-01",
            "/run/user/1000/thunderbolt-regtest-committee-01",
        ),
    };
    let data = root.join(format!("{role_name}-data"));
    let control = root.join(format!("{role_name}-control"));
    std::fs::create_dir(&data)?;
    std::fs::create_dir(&control)?;
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700))?;
    std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o700))?;

    let descriptor_digest = digest(b"descriptor");
    let anchor_digest = digest(b"anchor");
    let profile_digest = digest(b"profile");
    let runtime_profile = derived(b"bitcoin-thunderbolt/runtime-config/runtime-profile/v2", profile_digest);
    let finality_profile = derived_pair(
        b"bitcoin-thunderbolt/runtime-config/finality-verifier-profile/v2",
        profile_digest,
        decode_hex32("50d4e01279dbb7fcf6cb0e8a7d407b7713d86b83346b13c60f13b52f8045728d")?,
    );
    let static_profile = derived(
        b"bitcoin-thunderbolt/runtime-config/static-verifier-profile/v2",
        profile_digest,
    );
    let deployment_descriptor = test_deployment_descriptor(descriptor_digest, anchor_digest)?;
    let consensus_profile = ConsensusProfileV2::from_verifier(
        &LedgerChainIdV2::new("thunderbolt-regtest-1")?,
        ProtocolLimitsV2::new(1_000_000, 8, 86_400_000)?,
        &TestAdmissionIdentity {
            verifier_profile: static_profile,
            deployment_descriptor,
        },
    )?;
    let mut config = sample
        .replace(old_data, &toml_path(&data))
        .replace(old_control, &toml_path(&control))
        .replace(
            "/etc/thunderbolt/regtest/bitcoin-cookie.ref",
            &toml_path(&common.cookie),
        )
        .replace(
            "/etc/thunderbolt/regtest/committee-descriptor.json",
            &toml_path(&common.descriptor),
        )
        .replace("/etc/thunderbolt/regtest/anchor-suite.json", &toml_path(&common.anchor))
        .replace(
            "/etc/thunderbolt/regtest/runtime-profile.json",
            &toml_path(&common.profile),
        )
        .replace(
            "/etc/thunderbolt/regtest/comet-root.json",
            &toml_path(&common.trust_root),
        )
        .replace(&"22".repeat(32), &hex(&descriptor_digest))
        .replace(&"33".repeat(32), &hex(&anchor_digest))
        .replace(&"aa".repeat(32), &hex(&profile_digest))
        .replace(&"66".repeat(32), &hex(&digest(b"trust-root")))
        .replace(
            "4ba1fc95b531329ae4161c164302210a740b60e9071859687aa64d3ebbad53c2",
            &hex(&runtime_profile),
        )
        .replace(
            "5e4d04cd79e904b5457c689d6c1f810f01c81c156ec637af30126f7a9fbfe7b8",
            &hex(&finality_profile),
        )
        .replace(
            "b1e18cafc550975a6602a8311b016bc3ad9b2580975ff427eb1da9b0af17359b",
            &hex(&static_profile),
        )
        .replace(
            "36fc734f78f1fb5fdcb380ae7905d6871144063db36f2846bb6412dfde3e1eb7",
            &hex(&deployment_descriptor),
        )
        .replace(
            "81461d89549ebcc121f89b19f80148d0f2b1c80f3c08cac31530dd58b6e9a5e0",
            &hex(consensus_profile.as_bytes()),
        );
    if role != RuntimeRole::Ledger {
        let password = owner_file(root, &format!("{role_name}-vault.password"), b"secret")?;
        let vault_manifest = owner_file(
            root,
            &format!("{role_name}-vault-provider.json"),
            format!("{role_name}-vault-provider").as_bytes(),
        )?;
        let trust_manifest = owner_file(
            root,
            &format!("{role_name}-trust-provider.json"),
            format!("{role_name}-trust-provider").as_bytes(),
        )?;
        let (old_password, old_vault, old_trust, vault_placeholder, trust_placeholder) = match role {
            RuntimeRole::Holder => (
                "/etc/thunderbolt/regtest/holder-01-vault-password",
                "/etc/thunderbolt/regtest/holder-01-vault-checkpoint-provider.json",
                "/etc/thunderbolt/regtest/holder-01-trust-checkpoint-provider.json",
                "44",
                "55",
            ),
            RuntimeRole::Committee => (
                "/etc/thunderbolt/regtest/committee-01-vault-password",
                "/etc/thunderbolt/regtest/committee-01-vault-checkpoint-provider.json",
                "/etc/thunderbolt/regtest/committee-01-trust-checkpoint-provider.json",
                "47",
                "57",
            ),
            RuntimeRole::Ledger => return Err("Ledger has no checkpoint providers".into()),
        };
        config = config
            .replace(old_password, &toml_path(&password))
            .replace(old_vault, &toml_path(&vault_manifest))
            .replace(old_trust, &toml_path(&trust_manifest))
            .replace(
                &vault_placeholder.repeat(32),
                &hex(&digest(format!("{role_name}-vault-provider").as_bytes())),
            )
            .replace(
                &trust_placeholder.repeat(32),
                &hex(&digest(format!("{role_name}-trust-provider").as_bytes())),
            );
    }
    Ok(config)
}

fn test_deployment_descriptor(
    committee_descriptor: [u8; 32],
    anchor_suite: [u8; 32],
) -> std::result::Result<[u8; 32], Box<dyn Error>> {
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoin-thunderbolt/runtime-config/deployment-descriptor/v2");
    hasher.update([4]);
    append_hash(&mut hasher, b"thunderbolt-regtest-1");
    append_hash(&mut hasher, b"thunderbolt-regtest");
    append_hash(&mut hasher, &[0x11; 32]);
    append_hash(
        &mut hasher,
        &decode_hex32("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")?,
    );
    hasher.update(9_u64.to_be_bytes());
    append_hash(&mut hasher, &committee_descriptor);
    append_hash(&mut hasher, &anchor_suite);
    Ok(hasher.finalize().into())
}

#[cfg(unix)]
impl FilesystemFixture {
    fn new(root: &Path) -> std::result::Result<Self, Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt as _;

        let data = root.join("data");
        let control = root.join("control");
        std::fs::create_dir(&data)?;
        std::fs::create_dir(&control)?;
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o700))?;

        let descriptor = owner_file(root, "descriptor.json", b"descriptor")?;
        let anchor = owner_file(root, "anchor.json", b"anchor")?;
        let profile = owner_file(root, "profile.json", b"profile")?;
        let vault_checkpoint = owner_file(root, "vault-checkpoint.json", b"vault-checkpoint")?;
        let trust_checkpoint = owner_file(root, "trust-checkpoint.json", b"trust-checkpoint")?;
        let trust_root = owner_file(root, "trust-root.json", b"trust-root")?;
        let cookie = owner_file(root, "bitcoin.cookie", b"__cookie__:secret")?;
        let vault_password = owner_file(root, "vault.password", b"secret")?;

        let descriptor_digest = digest(b"descriptor");
        let anchor_digest = digest(b"anchor");
        let profile_digest = digest(b"profile");
        let runtime_profile = derived(b"bitcoin-thunderbolt/runtime-config/runtime-profile/v2", profile_digest);
        let finality_profile = derived_pair(
            b"bitcoin-thunderbolt/runtime-config/finality-verifier-profile/v2",
            profile_digest,
            [
                0x50, 0xd4, 0xe0, 0x12, 0x79, 0xdb, 0xb7, 0xfc, 0xf6, 0xcb, 0x0e, 0x8a, 0x7d, 0x40, 0x7b, 0x77, 0x13,
                0xd8, 0x6b, 0x83, 0x34, 0x6b, 0x13, 0xc6, 0x0f, 0x13, 0xb5, 0x2f, 0x80, 0x45, 0x72, 0x8d,
            ],
        );
        let vault_checkpoint_digest = digest(b"vault-checkpoint");
        let trust_checkpoint_digest = digest(b"trust-checkpoint");
        let mut config = HOLDER.to_owned();
        config = config.replace("/var/lib/thunderbolt/regtest/holder-01", &toml_path(&data));
        config = config.replace("/run/user/1000/thunderbolt-regtest-holder-01", &toml_path(&control));
        for (from, to) in [
            (
                "/etc/thunderbolt/regtest/holder-01-vault-password",
                toml_path(&vault_password),
            ),
            (
                "/etc/thunderbolt/regtest/holder-01-vault-checkpoint-provider.json",
                toml_path(&vault_checkpoint),
            ),
            (
                "/etc/thunderbolt/regtest/holder-01-trust-checkpoint-provider.json",
                toml_path(&trust_checkpoint),
            ),
            ("/etc/thunderbolt/regtest/comet-root.json", toml_path(&trust_root)),
            ("/etc/thunderbolt/regtest/bitcoin-cookie.ref", toml_path(&cookie)),
            (
                "/etc/thunderbolt/regtest/committee-descriptor.json",
                toml_path(&descriptor),
            ),
            ("/etc/thunderbolt/regtest/anchor-suite.json", toml_path(&anchor)),
            ("/etc/thunderbolt/regtest/runtime-profile.json", toml_path(&profile)),
        ] {
            config = config.replace(from, &to);
        }
        for (from, to) in [
            ("22".repeat(32), hex(&descriptor_digest)),
            ("33".repeat(32), hex(&anchor_digest)),
            ("aa".repeat(32), hex(&profile_digest)),
            ("44".repeat(32), hex(&vault_checkpoint_digest)),
            ("55".repeat(32), hex(&trust_checkpoint_digest)),
            (
                "4ba1fc95b531329ae4161c164302210a740b60e9071859687aa64d3ebbad53c2".to_owned(),
                hex(&runtime_profile),
            ),
            (
                "5e4d04cd79e904b5457c689d6c1f810f01c81c156ec637af30126f7a9fbfe7b8".to_owned(),
                hex(&finality_profile),
            ),
            ("66".repeat(32), hex(&digest(b"trust-root"))),
        ] {
            config = config.replace(&from, &to);
        }
        Ok(Self {
            config,
            descriptor,
            cookie,
            data,
        })
    }
}

#[cfg(unix)]
fn owner_file(root: &Path, name: &str, bytes: &[u8]) -> std::result::Result<PathBuf, Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt as _;

    let path = root.join(name);
    std::fs::write(&path, bytes)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(path)
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn derived(domain: &[u8], source: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(source);
    hasher.finalize().into()
}

fn derived_pair(domain: &[u8], first: [u8; 32], second: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(first);
    hasher.update(second);
    hasher.finalize().into()
}

fn https_policy_digest(ca_digest: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoin-thunderbolt/runtime-config/comet-policy/v2");
    append_hash(&mut hasher, b"thunderbolt-regtest-1");
    hasher.update(2_u64.to_be_bytes());
    hasher.update(1_u64.to_be_bytes());
    for (position, endpoint, node, binding) in [
        (
            0_u64,
            b"https://primary.example.invalid/".as_slice(),
            [0xa1; 20],
            [0x81; 32],
        ),
        (
            1_u64,
            b"https://witness.example.invalid/".as_slice(),
            [0xb2; 20],
            [0x82; 32],
        ),
    ] {
        if position == 1 {
            hasher.update(1_u64.to_be_bytes());
        }
        hasher.update(position.to_be_bytes());
        append_hash(&mut hasher, endpoint);
        hasher.update(node);
        hasher.update(binding);
    }
    hasher.update(10_u64.to_be_bytes());
    hasher.update([0x99; 32]);
    for value in [
        120_u64, 1_000, 16, 64, 1, 2, 5_000, 1_048_576, 8_388_608, 16_777_216, 10_000, 64, 67_108_864, 4_096, 262_144,
        786_432, 3, 100, 64, 64, 65_536,
    ] {
        hasher.update(value.to_be_bytes());
    }
    hasher.update([1]);
    hasher.update(1_u64.to_be_bytes());
    hasher.update(ca_digest);
    hasher.finalize().into()
}

fn append_hash(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

fn decode_hex32(value: &str) -> std::result::Result<[u8; 32], Box<dyn Error>> {
    if value.len() != 64 {
        return Err("hex length".into());
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair)?;
        output[index] = u8::from_str_radix(text, 16)?;
    }
    Ok(output)
}

fn hex(bytes: &[u8]) -> String {
    crate::mapping::hex_encode(bytes)
}

fn toml_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
