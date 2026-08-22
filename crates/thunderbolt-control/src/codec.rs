use crate::types::{validate_method, ControlRequest, ControlResponse, ControlStatus, RequestId};
use crate::{ControlError, Result, CONTROL_PROTOCOL_VERSION, MAX_ERROR_MESSAGE_BYTES, MAX_METHOD_BYTES};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"THBC";
const REQUEST_KIND: u8 = 1;
const RESPONSE_KIND: u8 = 2;
const COMMON_HEADER_BYTES: usize = 4 + 2 + 1 + 1 + 16;
const REQUEST_FIXED_BYTES: usize = COMMON_HEADER_BYTES + 2 + 4;
const RESPONSE_FIXED_BYTES: usize = COMMON_HEADER_BYTES + 2 + 2 + 4;

pub(crate) fn encode_request(request: &ControlRequest, max_frame_bytes: usize) -> Result<Zeroizing<Vec<u8>>> {
    let method_len = u16::try_from(request.method().len())
        .map_err(|_| ControlError::InvalidFrame("method length does not fit in u16"))?;
    let payload_len = u32::try_from(request.payload().len())
        .map_err(|_| ControlError::InvalidFrame("request payload length does not fit in u32"))?;
    let total = REQUEST_FIXED_BYTES
        .checked_add(request.method().len())
        .and_then(|size| size.checked_add(request.payload().len()))
        .ok_or(ControlError::InvalidFrame("request frame length overflows"))?;
    ensure_total(total, max_frame_bytes)?;
    let mut frame = Zeroizing::new(Vec::with_capacity(total));
    encode_common(&mut frame, REQUEST_KIND, request.request_id());
    frame.extend_from_slice(&method_len.to_be_bytes());
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(request.method().as_bytes());
    frame.extend_from_slice(request.payload());
    Ok(frame)
}

pub(crate) fn decode_request(frame: &[u8], max_frame_bytes: usize) -> Result<ControlRequest> {
    ensure_total(frame.len(), max_frame_bytes)?;
    if frame.len() < REQUEST_FIXED_BYTES {
        return Err(ControlError::InvalidFrame("request frame is truncated"));
    }
    let request_id = decode_common(frame, REQUEST_KIND)?;
    let method_len = usize::from(u16::from_be_bytes([frame[24], frame[25]]));
    let payload_len = usize::try_from(u32::from_be_bytes([frame[26], frame[27], frame[28], frame[29]]))
        .map_err(|_| ControlError::InvalidFrame("payload length does not fit this platform"))?;
    if method_len == 0 || method_len > MAX_METHOD_BYTES {
        return Err(ControlError::InvalidFrame("method length is outside the safety bound"));
    }
    let expected = REQUEST_FIXED_BYTES
        .checked_add(method_len)
        .and_then(|size| size.checked_add(payload_len))
        .ok_or(ControlError::InvalidFrame("request frame length overflows"))?;
    if expected != frame.len() {
        return Err(ControlError::InvalidFrame("request lengths do not match the frame"));
    }
    let method_end = REQUEST_FIXED_BYTES + method_len;
    let method = std::str::from_utf8(&frame[REQUEST_FIXED_BYTES..method_end])
        .map_err(|_| ControlError::InvalidFrame("method is not UTF-8"))?;
    validate_method(method)?;
    ControlRequest::new(request_id, method.to_owned(), frame[method_end..].to_vec())
}

pub(crate) fn encode_response(response: &ControlResponse, max_frame_bytes: usize) -> Result<Zeroizing<Vec<u8>>> {
    let message_len = u16::try_from(response.message().len())
        .map_err(|_| ControlError::InvalidFrame("response message length does not fit in u16"))?;
    let payload_len = u32::try_from(response.payload().len())
        .map_err(|_| ControlError::InvalidFrame("response payload length does not fit in u32"))?;
    let total = RESPONSE_FIXED_BYTES
        .checked_add(response.message().len())
        .and_then(|size| size.checked_add(response.payload().len()))
        .ok_or(ControlError::InvalidFrame("response frame length overflows"))?;
    ensure_total(total, max_frame_bytes)?;
    let mut frame = Zeroizing::new(Vec::with_capacity(total));
    encode_common(&mut frame, RESPONSE_KIND, response.request_id());
    frame.extend_from_slice(&(response.status() as u16).to_be_bytes());
    frame.extend_from_slice(&message_len.to_be_bytes());
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(response.message().as_bytes());
    frame.extend_from_slice(response.payload());
    Ok(frame)
}

pub(crate) fn decode_response(frame: &[u8], max_frame_bytes: usize) -> Result<ControlResponse> {
    ensure_total(frame.len(), max_frame_bytes)?;
    if frame.len() < RESPONSE_FIXED_BYTES {
        return Err(ControlError::InvalidFrame("response frame is truncated"));
    }
    let request_id = decode_common(frame, RESPONSE_KIND)?;
    let status = ControlStatus::from_u16(u16::from_be_bytes([frame[24], frame[25]]))?;
    let message_len = usize::from(u16::from_be_bytes([frame[26], frame[27]]));
    let payload_len = usize::try_from(u32::from_be_bytes([frame[28], frame[29], frame[30], frame[31]]))
        .map_err(|_| ControlError::InvalidFrame("payload length does not fit this platform"))?;
    if message_len > MAX_ERROR_MESSAGE_BYTES {
        return Err(ControlError::InvalidFrame("response message exceeds the safety bound"));
    }
    let expected = RESPONSE_FIXED_BYTES
        .checked_add(message_len)
        .and_then(|size| size.checked_add(payload_len))
        .ok_or(ControlError::InvalidFrame("response frame length overflows"))?;
    if expected != frame.len() {
        return Err(ControlError::InvalidFrame("response lengths do not match the frame"));
    }
    let message_end = RESPONSE_FIXED_BYTES + message_len;
    let message = std::str::from_utf8(&frame[RESPONSE_FIXED_BYTES..message_end])
        .map_err(|_| ControlError::InvalidFrame("response message is not UTF-8"))?;
    if status == ControlStatus::Ok {
        if !message.is_empty() {
            return Err(ControlError::InvalidFrame(
                "success response must not contain an error message",
            ));
        }
        Ok(ControlResponse::success(request_id, frame[message_end..].to_vec()))
    } else {
        if payload_len != 0 {
            return Err(ControlError::InvalidFrame(
                "failure response must not contain a payload",
            ));
        }
        ControlResponse::failure(request_id, status, message.to_owned())
    }
}

fn encode_common(frame: &mut Vec<u8>, kind: u8, request_id: RequestId) {
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&CONTROL_PROTOCOL_VERSION.to_be_bytes());
    frame.push(kind);
    frame.push(0);
    frame.extend_from_slice(request_id.as_bytes());
}

fn decode_common(frame: &[u8], expected_kind: u8) -> Result<RequestId> {
    if &frame[..4] != MAGIC {
        return Err(ControlError::InvalidFrame("frame magic differs"));
    }
    if u16::from_be_bytes([frame[4], frame[5]]) != CONTROL_PROTOCOL_VERSION {
        return Err(ControlError::InvalidFrame("control protocol version differs"));
    }
    if frame[6] != expected_kind || frame[7] != 0 {
        return Err(ControlError::InvalidFrame("frame kind or reserved byte differs"));
    }
    let bytes =
        <[u8; 16]>::try_from(&frame[8..24]).map_err(|_| ControlError::InvalidFrame("request id width differs"))?;
    RequestId::from_bytes(bytes)
}

fn ensure_total(total: usize, max_frame_bytes: usize) -> Result<()> {
    if total == 0 || total > max_frame_bytes {
        return Err(ControlError::InvalidFrame("frame exceeds the configured bound"));
    }
    Ok(())
}
