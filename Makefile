CARGO ?= cargo
VERSION ?= v1.0.0-rc.1

.PHONY: fmt lint test doc check audit deny semver sbom image regtest-up regtest-status regtest-down release verify

fmt:
	$(CARGO) fmt --all --check

lint:
	$(CARGO) clippy --workspace --all-targets --all-features --locked -- -D warnings

test:
	$(CARGO) test --workspace --all-features --locked --lib --bins --tests

doc:
	$(CARGO) test --workspace --all-features --locked --doc

check: fmt lint test doc

audit:
	$(CARGO) audit --deny warnings

deny:
	$(CARGO) deny --locked check advisories bans licenses sources

semver:
	@test -n "$(BASELINE)" || { echo "BASELINE is required" >&2; exit 2; }
	$(CARGO) semver-checks --workspace --baseline-rev "$(BASELINE)"

sbom:
	./scripts/generate-sbom.sh dist/sbom

image:
	docker build --pull --build-arg VERSION="$(patsubst v%,%,$(VERSION))" --build-arg REVISION="$$(git rev-parse HEAD)" --tag bitcoin-thunderbolt:local .

regtest-up:
	docker compose --file deploy/regtest/compose.yaml up --build --detach

regtest-status:
	docker compose --file deploy/regtest/compose.yaml exec -T thunderboltd thunderbolt-cli --config /etc/bitcoin-thunderbolt/thunderbolt.toml health --ready

regtest-down:
	docker compose --file deploy/regtest/compose.yaml down

release:
	./scripts/package-release.sh "$(VERSION)" dist

verify:
	./scripts/verify-release.sh --checksums-only dist
