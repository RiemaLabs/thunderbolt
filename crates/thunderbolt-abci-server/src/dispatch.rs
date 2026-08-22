use std::panic::{catch_unwind, AssertUnwindSafe};

use prost::Message as _;
use tendermint_abci::Application;
use tendermint_proto::v0_38::abci::{request, response, Request, Response};

use crate::preflight::preflight_request;

pub(crate) enum DispatchFailure {
    Client,
    Server,
    Panicked,
}

pub(crate) fn dispatch_frame<A, F>(
    application: F,
    frame: Vec<u8>,
    response_cap: usize,
    request_decode_item_limit: usize,
) -> std::result::Result<Vec<u8>, DispatchFailure>
where
    A: Application,
    F: FnOnce() -> std::result::Result<A, DispatchFailure>,
{
    match catch_unwind(AssertUnwindSafe(|| {
        dispatch_inner(application, &frame, response_cap, request_decode_item_limit)
    })) {
        Ok(result) => result,
        Err(_) => Err(DispatchFailure::Panicked),
    }
}

fn dispatch_inner<A, F>(
    application: F,
    frame: &[u8],
    response_cap: usize,
    request_decode_item_limit: usize,
) -> std::result::Result<Vec<u8>, DispatchFailure>
where
    A: Application,
    F: FnOnce() -> std::result::Result<A, DispatchFailure>,
{
    let _decoded_items = preflight_request(frame, request_decode_item_limit).map_err(|()| DispatchFailure::Client)?;
    let mut remaining = frame;
    let request = Request::decode(&mut remaining).map_err(|_| DispatchFailure::Client)?;
    if !remaining.is_empty() {
        return Err(DispatchFailure::Client);
    }
    let value = request.value.ok_or(DispatchFailure::Client)?;
    let application = application()?;
    let value = match value {
        request::Value::Echo(value) => response::Value::Echo(application.echo(value)),
        request::Value::Flush(_) => response::Value::Flush(application.flush()),
        request::Value::Info(value) => response::Value::Info(application.info(value)),
        request::Value::InitChain(value) => response::Value::InitChain(application.init_chain(value)),
        request::Value::Query(value) => response::Value::Query(application.query(value)),
        request::Value::CheckTx(value) => response::Value::CheckTx(application.check_tx(value)),
        request::Value::Commit(_) => response::Value::Commit(application.commit()),
        request::Value::ListSnapshots(_) => response::Value::ListSnapshots(application.list_snapshots()),
        request::Value::OfferSnapshot(value) => response::Value::OfferSnapshot(application.offer_snapshot(value)),
        request::Value::LoadSnapshotChunk(value) => {
            response::Value::LoadSnapshotChunk(application.load_snapshot_chunk(value))
        }
        request::Value::ApplySnapshotChunk(value) => {
            response::Value::ApplySnapshotChunk(application.apply_snapshot_chunk(value))
        }
        request::Value::PrepareProposal(value) => response::Value::PrepareProposal(application.prepare_proposal(value)),
        request::Value::ProcessProposal(value) => response::Value::ProcessProposal(application.process_proposal(value)),
        request::Value::ExtendVote(value) => response::Value::ExtendVote(application.extend_vote(value)),
        request::Value::VerifyVoteExtension(value) => {
            response::Value::VerifyVoteExtension(application.verify_vote_extension(value))
        }
        request::Value::FinalizeBlock(value) => response::Value::FinalizeBlock(application.finalize_block(value)),
    };
    let response = Response { value: Some(value) };
    let length = response.encoded_len();
    if length == 0 || length > response_cap {
        return Err(DispatchFailure::Server);
    }
    let mut encoded = Vec::new();
    encoded.try_reserve_exact(length).map_err(|_| DispatchFailure::Server)?;
    response.encode(&mut encoded).map_err(|_| DispatchFailure::Server)?;
    if encoded.len() != length {
        return Err(DispatchFailure::Server);
    }
    Ok(encoded)
}
