use std::future::{Future, IntoFuture};
use std::net::SocketAddr;
use std::sync::Arc;

use thunderbolt_config::{Config, Environment, Network, NodeRole, TokenScope, TokenStore};
use thunderbolt_storage::SqliteStorage;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::api::{build_router, AppState};
use crate::{NodeError, ProposalVerifier};

/// Runtime switches which are intentionally not part of the durable protocol.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NodeOptions {
    /// Permit unverified lifecycle demonstrations on development regtest only.
    ///
    /// The server still rejects client-asserted verification evidence. It
    /// synthesizes deterministic attestations labelled
    /// `development-unverified-demo` using transaction-scoped ledger time.
    pub allow_unverified_demo_events: bool,
}

/// Validates safety constraints enforced by version 1.0.
pub fn validate_runtime_config(config: &Config, options: NodeOptions) -> Result<(), NodeError> {
    config
        .validate()
        .map_err(|error| NodeError::Configuration(error.to_string()))?;

    if config.deployment.network == Network::Mainnet {
        return Err(NodeError::Configuration(
            "mainnet is disabled in version 1.0; use regtest, signet, or testnet".to_owned(),
        ));
    }
    if config.node.role != NodeRole::Ledger {
        return Err(NodeError::Configuration(
            "the reference ledger server requires node.role=ledger; holder and committee participants use clients"
                .to_owned(),
        ));
    }
    if !config.admin.enabled {
        return Err(NodeError::Configuration(
            "the local operator API must be enabled".to_owned(),
        ));
    }
    if !config.admin.bind_address.is_loopback() {
        return Err(NodeError::Configuration(
            "this release serves the operator API on loopback only".to_owned(),
        ));
    }
    if config.admin.remote_http {
        return Err(NodeError::Configuration(
            "remote operator HTTP is not supported by this release".to_owned(),
        ));
    }
    if config.admin.tls.enabled {
        return Err(NodeError::Configuration(
            "built-in operator TLS is not available; keep the API on loopback".to_owned(),
        ));
    }
    if config.auth.enabled
        && !config.auth.tokens.iter().any(|token| {
            token
                .scopes
                .iter()
                .copied()
                .any(|scope| scope.allows(TokenScope::Admin))
        })
    {
        return Err(NodeError::Configuration(
            "at least one bearer token must grant the admin scope".to_owned(),
        ));
    }
    if config.deployment.environment != Environment::Development {
        if !config.auth.enabled {
            return Err(NodeError::Configuration(
                "authentication cannot be disabled in staging or production".to_owned(),
            ));
        }
        if config.development.allow_insecure_ledger_http
            || config.development.allow_unauthenticated_admin
            || config.development.accept_invalid_tls_certificates
            || config.development.allow_ephemeral_storage
        {
            return Err(NodeError::Configuration(
                "development-only safety exceptions are forbidden in staging and production".to_owned(),
            ));
        }
    }
    if options.allow_unverified_demo_events
        && (config.deployment.environment != Environment::Development || config.deployment.network != Network::Regtest)
    {
        return Err(NodeError::Configuration(
            "--development-allow-unverified-demo-events requires environment=development and network=regtest"
                .to_owned(),
        ));
    }
    Ok(())
}

/// A bound reference node ready to serve requests.
pub struct NodeServer {
    listener: TcpListener,
    state: AppState,
    router: axum::Router,
    graceful_shutdown_timeout: std::time::Duration,
}

impl NodeServer {
    /// Binds the configured loopback operator address and prepares storage.
    pub async fn bind(config: Config, options: NodeOptions) -> Result<Self, NodeError> {
        validate_runtime_config(&config, options)?;
        let address = SocketAddr::new(config.admin.bind_address, config.admin.port);
        let listener = TcpListener::bind(address).await?;
        Self::from_listener_inner(listener, config, options, None).await
    }

    /// Binds with a trusted Invoice/Transfer verifier.
    ///
    /// Open and Finalize remain fail-closed even when a verifier is supplied.
    pub async fn bind_with_verifier(
        config: Config,
        options: NodeOptions,
        verifier: Arc<dyn ProposalVerifier>,
    ) -> Result<Self, NodeError> {
        validate_runtime_config(&config, options)?;
        if options.allow_unverified_demo_events {
            return Err(NodeError::Configuration(
                "development demo evidence and a trusted verifier cannot be enabled together".to_owned(),
            ));
        }
        let address = SocketAddr::new(config.admin.bind_address, config.admin.port);
        let listener = TcpListener::bind(address).await?;
        Self::from_listener_inner(listener, config, options, Some(verifier)).await
    }

    /// Uses an already-bound loopback listener.
    ///
    /// This supports socket activation and ephemeral-port integration tests.
    pub async fn from_listener(listener: TcpListener, config: Config, options: NodeOptions) -> Result<Self, NodeError> {
        Self::from_listener_inner(listener, config, options, None).await
    }

    /// Uses an already-bound listener and an injected trusted verifier.
    pub async fn from_listener_with_verifier(
        listener: TcpListener,
        config: Config,
        options: NodeOptions,
        verifier: Arc<dyn ProposalVerifier>,
    ) -> Result<Self, NodeError> {
        Self::from_listener_inner(listener, config, options, Some(verifier)).await
    }

    async fn from_listener_inner(
        listener: TcpListener,
        config: Config,
        options: NodeOptions,
        verifier: Option<Arc<dyn ProposalVerifier>>,
    ) -> Result<Self, NodeError> {
        validate_runtime_config(&config, options)?;
        if options.allow_unverified_demo_events && verifier.is_some() {
            return Err(NodeError::Configuration(
                "development demo evidence and a trusted verifier cannot be enabled together".to_owned(),
            ));
        }
        let local_address = listener.local_addr()?;
        if !local_address.ip().is_loopback() {
            return Err(NodeError::Configuration(
                "the supplied operator listener is not loopback".to_owned(),
            ));
        }

        let token_store = Arc::new(TokenStore::load(&config.auth)?);
        let database_path = config.paths.database_path.clone();
        let storage = tokio::task::spawn_blocking(move || {
            let storage = SqliteStorage::open(database_path)?;
            storage.integrity_check()?;
            Ok::<SqliteStorage, thunderbolt_storage::StorageError>(storage)
        })
        .await
        .map_err(|error| NodeError::DatabaseWorker(error.to_string()))??;

        let max_requests = usize::try_from(config.limits.max_concurrent_requests)
            .map_err(|_| NodeError::Configuration("max_concurrent_requests does not fit this platform".to_owned()))?;
        let database_workers = max_requests.clamp(1, 32);
        let graceful_shutdown_timeout = config.limits.graceful_shutdown_timeout();
        let state = AppState::new(
            Arc::new(config),
            token_store,
            Arc::new(storage),
            database_workers,
            options,
            verifier,
        );
        let router = build_router(state.clone())?;
        Ok(Self {
            listener,
            state,
            router,
            graceful_shutdown_timeout,
        })
    }

    /// Returns the address selected by the operating system.
    pub fn local_addr(&self) -> Result<SocketAddr, NodeError> {
        self.listener.local_addr().map_err(NodeError::from)
    }

    /// Serves until an OS signal future or the authenticated stop endpoint fires.
    pub async fn run<F>(self, external_shutdown: F) -> Result<(), NodeError>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let graceful_trigger = CancellationToken::new();
        let server_trigger = graceful_trigger.clone();
        let server = axum::serve(self.listener, self.router)
            .with_graceful_shutdown(server_trigger.cancelled_owned())
            .into_future();
        tokio::pin!(server);
        let external_shutdown = Box::pin(external_shutdown);
        tokio::pin!(external_shutdown);

        tokio::select! {
            result = &mut server => {
                self.state.mark_not_ready();
                return result.map_err(NodeError::from);
            }
            () = self.state.stop_requested() => {}
            () = &mut external_shutdown => {}
        }

        self.state.mark_not_ready();
        graceful_trigger.cancel();
        match timeout(self.graceful_shutdown_timeout, &mut server).await {
            Ok(result) => result.map_err(NodeError::from),
            Err(_) => Err(NodeError::GracefulShutdownTimeout),
        }
    }
}
