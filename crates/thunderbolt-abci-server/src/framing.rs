use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::{ServerDeadlines, ServerLimits};
use crate::semaphore::{Permit, PermitPool};
use crate::FrameError;

pub(crate) trait TimedStream: Read + Write + Send + 'static {
    fn set_read_deadline(&self, timeout: Duration) -> io::Result<()>;
    fn set_write_deadline(&self, timeout: Duration) -> io::Result<()>;
    fn shutdown_both(&self) -> io::Result<()>;
}

pub(crate) struct InboundFrame {
    pub(crate) bytes: Vec<u8>,
    pub(crate) permit: Permit,
}

pub(crate) fn read_frame<S: TimedStream>(
    stream: &mut S,
    limits: ServerLimits,
    deadlines: ServerDeadlines,
    shutdown: &AtomicBool,
    inflight: &Arc<PermitPool>,
) -> std::result::Result<Option<InboundFrame>, FrameError> {
    if shutdown.load(Ordering::Acquire) {
        return Err(FrameError::Shutdown);
    }
    let idle_deadline = Instant::now()
        .checked_add(deadlines.idle())
        .ok_or(FrameError::IdleTimeout)?;
    stream.set_read_deadline(deadlines.idle()).map_err(FrameError::Io)?;
    let Some(first) = read_one(stream).map_err(|error| map_read_error(error, FrameError::IdleTimeout))? else {
        return Ok(None);
    };
    if Instant::now() > idle_deadline {
        return Err(FrameError::IdleTimeout);
    }
    let header_started = Instant::now();
    let header_deadline = header_started
        .checked_add(deadlines.header())
        .ok_or(FrameError::InvalidLengthPrefix)?;
    let mut value = 0_u64;
    let mut prefix_len = 0_usize;
    let mut byte = first;
    loop {
        if shutdown.load(Ordering::Acquire) {
            return Err(FrameError::Shutdown);
        }
        if prefix_len == 10 || (prefix_len == 9 && byte & 0xfe != 0) {
            return Err(FrameError::InvalidLengthPrefix);
        }
        let shift = u32::try_from(prefix_len)
            .ok()
            .and_then(|index| index.checked_mul(7))
            .ok_or(FrameError::InvalidLengthPrefix)?;
        value |= u64::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or(FrameError::InvalidLengthPrefix)?;
        prefix_len = prefix_len.checked_add(1).ok_or(FrameError::InvalidLengthPrefix)?;
        if byte & 0x80 == 0 {
            break;
        }
        let remaining = header_deadline
            .checked_duration_since(Instant::now())
            .ok_or(FrameError::HeaderTimeout)?;
        stream
            .set_read_deadline(deadlines.read().min(remaining))
            .map_err(FrameError::Io)?;
        byte = read_one(stream)
            .map_err(|error| map_read_error(error, FrameError::HeaderTimeout))?
            .ok_or(FrameError::InvalidLengthPrefix)?;
        if Instant::now() > header_deadline {
            return Err(FrameError::HeaderTimeout);
        }
    }
    if prefix_len != varint_len(value) {
        return Err(FrameError::NonCanonicalLength);
    }
    if value == 0 {
        return Err(FrameError::ZeroLength);
    }
    let length = usize::try_from(value).map_err(|_| FrameError::FrameTooLarge)?;
    if length > limits.request_frame_bytes() {
        return Err(FrameError::FrameTooLarge);
    }
    let frame_deadline = Instant::now()
        .checked_add(deadlines.frame())
        .ok_or(FrameError::FrameTimeout)?;
    let permit = inflight
        .acquire_until(limits.reservation_per_handler(), frame_deadline, shutdown)
        .map_err(|()| FrameError::AccountingInvariant)?
        .ok_or_else(|| {
            if shutdown.load(Ordering::Acquire) {
                FrameError::Shutdown
            } else {
                FrameError::InflightBudget
            }
        })?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| FrameError::Allocation)?;
    bytes.resize(length, 0);
    let mut offset = 0_usize;
    while offset < length {
        if shutdown.load(Ordering::Acquire) {
            return Err(FrameError::Shutdown);
        }
        let remaining = frame_deadline
            .checked_duration_since(Instant::now())
            .ok_or(FrameError::FrameTimeout)?;
        stream
            .set_read_deadline(deadlines.read().min(remaining))
            .map_err(FrameError::Io)?;
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => return Err(FrameError::TruncatedFrame),
            Ok(read) => {
                offset = offset.checked_add(read).ok_or(FrameError::FrameTooLarge)?;
                if Instant::now() > frame_deadline {
                    return Err(FrameError::FrameTimeout);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) => {
                return Err(FrameError::FrameTimeout);
            }
            Err(error) => return Err(FrameError::Io(error)),
        }
    }
    Ok(Some(InboundFrame { bytes, permit }))
}

pub(crate) fn write_frame<S: TimedStream>(
    stream: &mut S,
    payload: &[u8],
    response_cap: usize,
    deadline: Instant,
    shutdown: &AtomicBool,
) -> std::result::Result<(), FrameError> {
    if payload.is_empty() || payload.len() > response_cap {
        return Err(FrameError::FrameTooLarge);
    }
    let prefix = encode_varint(u64::try_from(payload.len()).map_err(|_| FrameError::FrameTooLarge)?);
    if Instant::now() >= deadline {
        return Err(FrameError::WriteTimeout);
    }
    write_all(stream, &prefix, deadline, shutdown)?;
    write_all(stream, payload, deadline, shutdown)?;
    stream.flush().map_err(FrameError::Io)?;
    if shutdown.load(Ordering::Acquire) {
        return Err(FrameError::Shutdown);
    }
    if Instant::now() > deadline {
        return Err(FrameError::WriteTimeout);
    }
    Ok(())
}

fn write_all<S: TimedStream>(
    stream: &mut S,
    bytes: &[u8],
    deadline: Instant,
    shutdown: &AtomicBool,
) -> std::result::Result<(), FrameError> {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        if shutdown.load(Ordering::Acquire) {
            return Err(FrameError::Shutdown);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(FrameError::WriteTimeout)?;
        stream.set_write_deadline(remaining).map_err(FrameError::Io)?;
        match stream.write(&bytes[offset..]) {
            Ok(0) => return Err(FrameError::WriteTimeout),
            Ok(written) => {
                offset = offset.checked_add(written).ok_or(FrameError::WriteTimeout)?;
                if Instant::now() > deadline {
                    return Err(FrameError::WriteTimeout);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) => {
                return Err(FrameError::WriteTimeout);
            }
            Err(error) => return Err(FrameError::Io(error)),
        }
    }
    Ok(())
}

fn read_one<R: Read>(reader: &mut R) -> io::Result<Option<u8>> {
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return Ok(None),
            Ok(_) => return Ok(Some(byte[0])),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn map_read_error(error: io::Error, timeout: FrameError) -> FrameError {
    if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) {
        timeout
    } else {
        FrameError::Io(error)
    }
}

pub(crate) fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(10);
    loop {
        let low = u8::try_from(value & 0x7f).unwrap_or(0);
        value >>= 7;
        bytes.push(if value == 0 { low } else { low | 0x80 });
        if value == 0 {
            break;
        }
    }
    bytes
}

fn varint_len(mut value: u64) -> usize {
    let mut length = 1_usize;
    while value >= 0x80 {
        value >>= 7;
        length = length.saturating_add(1);
    }
    length
}
