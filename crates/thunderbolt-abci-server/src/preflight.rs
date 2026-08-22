use std::mem::size_of;

use prost::bytes::Bytes;
use tendermint_proto::v0_38::abci::{ExtendedVoteInfo, Misbehavior, Request, ValidatorUpdate, VoteInfo};

use crate::SERVER_REQUEST_DECODE_ITEM_RESERVATION_BYTES;

const VEC_CAPACITY_MULTIPLIER: usize = 4;

// Every allocation-producing repeated element reachable from a v0.38 Request
// is listed here. Vec may initially reserve four elements; thereafter its
// capacity stays below twice its length. Payload bytes and strings are covered
// separately by the full decoded-payload reservation.
const _: () = assert!(size_of::<Bytes>() * VEC_CAPACITY_MULTIPLIER <= SERVER_REQUEST_DECODE_ITEM_RESERVATION_BYTES);
const _: () = assert!(size_of::<String>() * VEC_CAPACITY_MULTIPLIER <= SERVER_REQUEST_DECODE_ITEM_RESERVATION_BYTES);
const _: () =
    assert!(size_of::<ValidatorUpdate>() * VEC_CAPACITY_MULTIPLIER <= SERVER_REQUEST_DECODE_ITEM_RESERVATION_BYTES);
const _: () = assert!(size_of::<VoteInfo>() * VEC_CAPACITY_MULTIPLIER <= SERVER_REQUEST_DECODE_ITEM_RESERVATION_BYTES);
const _: () =
    assert!(size_of::<ExtendedVoteInfo>() * VEC_CAPACITY_MULTIPLIER <= SERVER_REQUEST_DECODE_ITEM_RESERVATION_BYTES);
const _: () =
    assert!(size_of::<Misbehavior>() * VEC_CAPACITY_MULTIPLIER <= SERVER_REQUEST_DECODE_ITEM_RESERVATION_BYTES);
const _: () = assert!(size_of::<Request>() <= crate::SERVER_REQUEST_FIXED_DECODE_RESERVATION_BYTES);

pub(crate) fn preflight_request(bytes: &[u8], item_limit: usize) -> Result<usize, ()> {
    let mut budget = DecodeBudget {
        items: 0,
        limit: item_limit,
    };
    let mut fields = Fields::new(bytes);
    while let Some(field) = fields.next()? {
        let number = field.number;
        let message = match number {
            1 | 2 | 3 | 5 | 6 | 8 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 => field.message()?,
            _ => continue,
        };
        match number {
            5 => scan_init_chain(message, &mut budget)?,
            16 => scan_prepare_proposal(message, &mut budget)?,
            17 => scan_process_proposal(message, &mut budget)?,
            18 => scan_extend_vote(message, &mut budget)?,
            20 => scan_finalize_block(message, &mut budget)?,
            _ => {}
        }
    }
    Ok(budget.items)
}

fn scan_init_chain(bytes: &[u8], budget: &mut DecodeBudget) -> Result<(), ()> {
    let mut fields = Fields::new(bytes);
    while let Some(field) = fields.next()? {
        match field.number {
            3 => scan_consensus_params(field.message()?, budget)?,
            4 => budget.add(field.message()?)?,
            _ => {}
        }
    }
    Ok(())
}

fn scan_consensus_params(bytes: &[u8], budget: &mut DecodeBudget) -> Result<(), ()> {
    let mut fields = Fields::new(bytes);
    while let Some(field) = fields.next()? {
        if field.number == 3 {
            scan_validator_params(field.message()?, budget)?;
        }
    }
    Ok(())
}

fn scan_validator_params(bytes: &[u8], budget: &mut DecodeBudget) -> Result<(), ()> {
    let mut fields = Fields::new(bytes);
    while let Some(field) = fields.next()? {
        if field.number == 1 {
            budget.add(field.message()?)?;
        }
    }
    Ok(())
}

fn scan_prepare_proposal(bytes: &[u8], budget: &mut DecodeBudget) -> Result<(), ()> {
    let mut fields = Fields::new(bytes);
    while let Some(field) = fields.next()? {
        match field.number {
            2 | 4 => budget.add(field.message()?)?,
            3 => scan_extended_commit_info(field.message()?, budget)?,
            _ => {}
        }
    }
    Ok(())
}

fn scan_process_proposal(bytes: &[u8], budget: &mut DecodeBudget) -> Result<(), ()> {
    let mut fields = Fields::new(bytes);
    while let Some(field) = fields.next()? {
        match field.number {
            1 | 3 => budget.add(field.message()?)?,
            2 => scan_commit_info(field.message()?, budget)?,
            _ => {}
        }
    }
    Ok(())
}

fn scan_extend_vote(bytes: &[u8], budget: &mut DecodeBudget) -> Result<(), ()> {
    let mut fields = Fields::new(bytes);
    while let Some(field) = fields.next()? {
        match field.number {
            4 | 6 => budget.add(field.message()?)?,
            5 => scan_commit_info(field.message()?, budget)?,
            _ => {}
        }
    }
    Ok(())
}

fn scan_finalize_block(bytes: &[u8], budget: &mut DecodeBudget) -> Result<(), ()> {
    let mut fields = Fields::new(bytes);
    while let Some(field) = fields.next()? {
        match field.number {
            1 | 3 => budget.add(field.message()?)?,
            2 => scan_commit_info(field.message()?, budget)?,
            _ => {}
        }
    }
    Ok(())
}

fn scan_commit_info(bytes: &[u8], budget: &mut DecodeBudget) -> Result<(), ()> {
    scan_repeated_message_field(bytes, 2, budget)
}

fn scan_extended_commit_info(bytes: &[u8], budget: &mut DecodeBudget) -> Result<(), ()> {
    scan_repeated_message_field(bytes, 2, budget)
}

fn scan_repeated_message_field(bytes: &[u8], number: u32, budget: &mut DecodeBudget) -> Result<(), ()> {
    let mut fields = Fields::new(bytes);
    while let Some(field) = fields.next()? {
        if field.number == number {
            budget.add(field.message()?)?;
        }
    }
    Ok(())
}

struct DecodeBudget {
    items: usize,
    limit: usize,
}

impl DecodeBudget {
    fn add(&mut self, _encoded_value: &[u8]) -> Result<(), ()> {
        self.items = self.items.checked_add(1).ok_or(())?;
        if self.items > self.limit {
            return Err(());
        }
        Ok(())
    }
}

struct Fields<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Fields<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn next(&mut self) -> Result<Option<Field<'a>>, ()> {
        if self.offset == self.bytes.len() {
            return Ok(None);
        }
        let key = read_varint(self.bytes, &mut self.offset)?;
        let number = u32::try_from(key >> 3).map_err(|_| ())?;
        if number == 0 || number > 0x1fff_ffff {
            return Err(());
        }
        let value = match key & 0x07 {
            0 => {
                let _ = read_varint(self.bytes, &mut self.offset)?;
                WireValue::Scalar
            }
            1 => {
                self.skip(8)?;
                WireValue::Scalar
            }
            2 => {
                let length = usize::try_from(read_varint(self.bytes, &mut self.offset)?).map_err(|_| ())?;
                let end = self.offset.checked_add(length).ok_or(())?;
                let value = self.bytes.get(self.offset..end).ok_or(())?;
                self.offset = end;
                WireValue::LengthDelimited(value)
            }
            5 => {
                self.skip(4)?;
                WireValue::Scalar
            }
            _ => return Err(()),
        };
        Ok(Some(Field { number, value }))
    }

    fn skip(&mut self, length: usize) -> Result<(), ()> {
        let end = self.offset.checked_add(length).ok_or(())?;
        if end > self.bytes.len() {
            return Err(());
        }
        self.offset = end;
        Ok(())
    }
}

struct Field<'a> {
    number: u32,
    value: WireValue<'a>,
}

impl<'a> Field<'a> {
    fn message(self) -> Result<&'a [u8], ()> {
        match self.value {
            WireValue::LengthDelimited(value) => Ok(value),
            WireValue::Scalar => Err(()),
        }
    }
}

enum WireValue<'a> {
    Scalar,
    LengthDelimited(&'a [u8]),
}

fn read_varint(bytes: &[u8], offset: &mut usize) -> Result<u64, ()> {
    let start = *offset;
    let mut value = 0_u64;
    for index in 0..10_usize {
        let byte = *bytes.get(*offset).ok_or(())?;
        *offset = offset.checked_add(1).ok_or(())?;
        if index == 9 && byte & 0xfe != 0 {
            return Err(());
        }
        let shift = u32::try_from(index.checked_mul(7).ok_or(())?).map_err(|_| ())?;
        value |= u64::from(byte & 0x7f).checked_shl(shift).ok_or(())?;
        if byte & 0x80 == 0 {
            if offset.checked_sub(start).ok_or(())? != varint_len(value) {
                return Err(());
            }
            return Ok(value);
        }
    }
    Err(())
}

fn varint_len(mut value: u64) -> usize {
    let mut length = 1_usize;
    while value >= 0x80 {
        value >>= 7;
        length = length.saturating_add(1);
    }
    length
}
