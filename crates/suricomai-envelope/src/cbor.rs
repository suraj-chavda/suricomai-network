// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Canonical CBOR subset: unsigned integers, byte strings, and maps with integer keys.
//!
//! One encoding is accepted. Indefinite lengths, non-shortest integers, unsorted or
//! duplicate keys, trailing bytes, and every other major type are rejected.

use std::collections::BTreeMap;

use crate::error::EnvelopeError;
use crate::suite::MAX_MESSAGE;

/// A value this codec can carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Cbor {
    UInt(u64),
    Bytes(Vec<u8>),
    Map(BTreeMap<u64, Cbor>),
}

/// Decode one canonical value and reject trailing bytes.
pub(crate) fn decode(bytes: &[u8]) -> Result<Cbor, EnvelopeError> {
    if bytes.is_empty() || bytes.len() > MAX_MESSAGE {
        return Err(EnvelopeError::Malformed);
    }
    let (value, rest) = decode_one(bytes, 0)?;
    if !rest.is_empty() {
        return Err(EnvelopeError::Malformed);
    }
    Ok(value)
}

/// Encode one value in canonical form.
pub(crate) fn encode(value: &Cbor) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

pub(crate) fn as_u64(value: &Cbor) -> Result<u64, EnvelopeError> {
    match value {
        Cbor::UInt(n) => Ok(*n),
        _ => Err(EnvelopeError::Malformed),
    }
}

pub(crate) fn as_bytes(value: &Cbor) -> Result<&[u8], EnvelopeError> {
    match value {
        Cbor::Bytes(b) => Ok(b),
        _ => Err(EnvelopeError::Malformed),
    }
}

pub(crate) fn as_map(value: &Cbor) -> Result<&BTreeMap<u64, Cbor>, EnvelopeError> {
    match value {
        Cbor::Map(m) => Ok(m),
        _ => Err(EnvelopeError::Malformed),
    }
}

#[cfg(test)]
pub(crate) fn as_map_mut(value: &mut Cbor) -> Result<&mut BTreeMap<u64, Cbor>, EnvelopeError> {
    match value {
        Cbor::Map(m) => Ok(m),
        _ => Err(EnvelopeError::Malformed),
    }
}

fn encode_into(value: &Cbor, out: &mut Vec<u8>) {
    match value {
        Cbor::UInt(n) => encode_len(0, *n, out),
        Cbor::Bytes(b) => {
            encode_len(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Cbor::Map(m) => {
            encode_len(5, m.len() as u64, out);
            for (k, v) in m {
                encode_len(0, *k, out);
                encode_into(v, out);
            }
        }
    }
}

fn encode_len(major: u8, n: u64, out: &mut Vec<u8>) {
    let head = major << 5;
    if n < 24 {
        out.push(head | n as u8);
    } else if n <= u64::from(u8::MAX) {
        out.push(head | 24);
        out.push(n as u8);
    } else if n <= u64::from(u16::MAX) {
        out.push(head | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u64::from(u32::MAX) {
        out.push(head | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(head | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn decode_one(input: &[u8], depth: usize) -> Result<(Cbor, &[u8]), EnvelopeError> {
    if depth > 4 || input.is_empty() {
        return Err(EnvelopeError::Malformed);
    }
    let (major, argument, rest) = read_argument(input)?;
    match major {
        0 => Ok((Cbor::UInt(argument), rest)),
        2 => {
            let len = usize::try_from(argument).map_err(|_| EnvelopeError::Malformed)?;
            if rest.len() < len {
                return Err(EnvelopeError::Malformed);
            }
            let (body, rest) = rest.split_at(len);
            Ok((Cbor::Bytes(body.to_vec()), rest))
        }
        5 => {
            let count = usize::try_from(argument).map_err(|_| EnvelopeError::Malformed)?;
            let mut rest = rest;
            let mut map = BTreeMap::new();
            let mut prev: Option<u64> = None;
            for _ in 0..count {
                let (key_value, next) = decode_one(rest, depth + 1)?;
                let key = match key_value {
                    Cbor::UInt(n) => n,
                    _ => return Err(EnvelopeError::Malformed),
                };
                if prev.is_some_and(|p| key <= p) {
                    return Err(EnvelopeError::NonCanonical);
                }
                prev = Some(key);
                let (value, next) = decode_one(next, depth + 1)?;
                map.insert(key, value);
                rest = next;
            }
            Ok((Cbor::Map(map), rest))
        }
        _ => Err(EnvelopeError::Malformed),
    }
}

/// Read a major type and its argument, enforcing the shortest integer form.
fn read_argument(input: &[u8]) -> Result<(u8, u64, &[u8]), EnvelopeError> {
    let first = input[0];
    let major = first >> 5;
    let info = first & 0x1f;
    let rest = &input[1..];
    let (argument, rest) = match info {
        0..=23 => (u64::from(info), rest),
        24 => {
            let (n, rest) = read_n(rest, 1)?;
            if n < 24 {
                return Err(EnvelopeError::NonCanonical);
            }
            (n, rest)
        }
        25 => {
            let (n, rest) = read_n(rest, 2)?;
            if n <= u64::from(u8::MAX) {
                return Err(EnvelopeError::NonCanonical);
            }
            (n, rest)
        }
        26 => {
            let (n, rest) = read_n(rest, 4)?;
            if n <= u64::from(u16::MAX) {
                return Err(EnvelopeError::NonCanonical);
            }
            (n, rest)
        }
        27 => {
            let (n, rest) = read_n(rest, 8)?;
            if n <= u64::from(u32::MAX) {
                return Err(EnvelopeError::NonCanonical);
            }
            (n, rest)
        }
        _ => return Err(EnvelopeError::Malformed),
    };
    Ok((major, argument, rest))
}

fn read_n(input: &[u8], n: usize) -> Result<(u64, &[u8]), EnvelopeError> {
    if input.len() < n {
        return Err(EnvelopeError::Malformed);
    }
    let mut buf = [0u8; 8];
    buf[8 - n..].copy_from_slice(&input[..n]);
    Ok((u64::from_be_bytes(buf), &input[n..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_nested_bytes() {
        let mut inner = BTreeMap::new();
        inner.insert(1, Cbor::UInt(1));
        inner.insert(2, Cbor::Bytes(b"abc".to_vec()));
        let value = Cbor::Map(inner);
        let bytes = encode(&value);
        assert_eq!(decode(&bytes).unwrap(), value);
    }

    #[test]
    fn rejects_non_shortest_integer() {
        // {1: 1} with the value encoded as a one-byte integer instead of the short form.
        let raw = [0xa1, 0x01, 0x18, 0x01];
        assert_eq!(decode(&raw), Err(EnvelopeError::NonCanonical));
    }

    #[test]
    fn rejects_unsorted_keys() {
        // {2: 1, 1: 1}
        let raw = [0xa2, 0x02, 0x01, 0x01, 0x01];
        assert_eq!(decode(&raw), Err(EnvelopeError::NonCanonical));
    }

    #[test]
    fn rejects_trailing_and_unknown_major() {
        assert_eq!(decode(&[0x01, 0x01]), Err(EnvelopeError::Malformed));
        assert_eq!(decode(&[0x60]), Err(EnvelopeError::Malformed));
        assert_eq!(decode(&[]), Err(EnvelopeError::Malformed));
    }
}
