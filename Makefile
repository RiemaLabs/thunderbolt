CARGO ?= cargo
VERSION ?= v1.0.0

.PHONY: fmt binary-graph lint test doc check audit deny semver sbom image regtest-up regtest-status regtest-down release verify

fmt:
	$(CARGO) fmt --all --check

binary-graph:
	python3 scripts/check-default-binary-graph.py

lint:
	$(CARGO) clippy --workspace --all-targets --all-features --locked -- -D warnings

test:
	$(CARGO) test --workspace --all-features --locked --lib --bins --tests

doc:
	$(CARGO) test --workspace --all-features --locked --doc

check: fmt binary-graph lint test doc

audit:
	$(CARGO) audit --deny warnings

deny:
	$(CARGO) deny --locked check advisories bans licenses sources

semver:
	@test -n "$(BASELINE)" || { echo "BASELINE is required" >&2; exit 2; }
	$(CARGO) semver-checks --workspace --baseline-rev "$(BASELINE)"

sbom:
	./scripts/generate-sbom.sh dist/sbom

image: binary-graph
	docker build --pull --build-arg VERSION="$(patsubst v%,%,$(VERSION))" --build-arg REVISION="$$(git rev-parse HEAD)" --tag bitcoin-thunderbolt:local .

regtest-up:
	docker compose --file deploy/regtest/compose.yaml up --build --detach

regtest-status:
	docker compose --file deploy/regtest/compose.yaml exec -T thunderboltd thunderbolt-cli --config /var/lib/thunderbolt/config/runtime.toml status

regtest-down:
	docker compose --file deploy/regtest/compose.yaml down

release:
	./scripts/package-release.sh "$(VERSION)" dist

verify:
	./scripts/verify-release.sh --checksums-only dist
