use thunderbolt_abci_server::ProcessExitFatalServerHandler;
use thunderbolt_floor_abci::{ProcessExitFatalHandler, ThunderboltFloorAbci};
use thunderbolt_floor_app::FloorApplication;

use crate::config::ValidatedConfig;
use crate::error::{NodeError, Result};

const ABCI_FATAL_EXIT_CODE: u8 = 70;
const SERVER_FATAL_EXIT_CODE: u8 = 71;

pub(crate) async fn start(config: ValidatedConfig) -> Result<()> {
    let mut signals = ShutdownSignals::new()?;
    config.revalidate()?;
    let lease = config.acquire_database_lease()?;
    let application =
        FloorApplication::open(config.database_path(), config.genesis().clone()).map_err(|_| NodeError::Application)?;
    application.status().map_err(|_| NodeError::Application)?;
    config.revalidate_after_database_open()?;
    lease.revalidate()?;

    let adapter_fatal = ProcessExitFatalHandler::new(ABCI_FATAL_EXIT_CODE).map_err(|_| NodeError::Abci)?;
    let adapter = ThunderboltFloorAbci::new(application, config.validators().clone(), adapter_fatal)
        .map_err(|_| NodeError::Abci)?;
    if adapter.chain_id() != config.comet_chain_id()
        || adapter.consensus_profile() != config.profile()
        || adapter.consensus_parameters() != crate::genesis::consensus_parameters()
    {
        return Err(NodeError::Abci);
    }

    config.revalidate_after_database_open()?;
    let server_config = config.server_config()?;
    let server_fatal = ProcessExitFatalServerHandler::new(SERVER_FATAL_EXIT_CODE).map_err(|_| NodeError::Server)?;
    let server = thunderbolt_abci_server::start(server_config, adapter, server_fatal).map_err(|_| NodeError::Server)?;
    eprintln!("Floor ABCI server started");
    let signal = signals.wait().await;
    server.shutdown_and_join();
    drop(lease);
    signal
}

#[cfg(unix)]
struct ShutdownSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ShutdownSignals {
    fn new() -> Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};

        Ok(Self {
            interrupt: signal(SignalKind::interrupt()).map_err(|_| NodeError::Signal)?,
            terminate: signal(SignalKind::terminate()).map_err(|_| NodeError::Signal)?,
        })
    }

    async fn wait(&mut self) -> Result<()> {
        tokio::select! {
            value = self.interrupt.recv() => value.map(|_| ()).ok_or(NodeError::Signal),
            value = self.terminate.recv() => value.map(|_| ()).ok_or(NodeError::Signal),
        }
    }
}

#[cfg(not(unix))]
struct ShutdownSignals;

#[cfg(not(unix))]
impl ShutdownSignals {
    fn new() -> Result<Self> {
        Err(NodeError::UnsupportedPlatform)
    }

    async fn wait(&mut self) -> Result<()> {
        Err(NodeError::UnsupportedPlatform)
    }
}
