use serde::{Deserialize, Serialize};

use crate::{CommandId, QueueProposalRequest, QueuedProposal, RunReport, ServiceStatus};

/// Secret-free request for an owner-only local control transport.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalControlRequest {
    Status,
    QueueProposal(Box<QueueProposalRequest>),
    RunOnce { now_ms: u64 },
    Retry { command_id: CommandId, now_ms: u64 },
    BeginDraining,
    Stop,
    AcknowledgeFault,
}

/// Secret-free local control response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalControlResponse {
    Status(Box<ServiceStatus>),
    Queued(QueuedProposal),
    Run(RunReport),
    Accepted,
}
