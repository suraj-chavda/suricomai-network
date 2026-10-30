// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! The one line a development client needs to reach a development node.
//!
//! It carries the pinned transport key and the node's lab quote root. A vendor quote
//! verifier replaces the second field, so a shipping build never prints or reads one.

use crate::error::RuntimeError;

const PREFIX: &str = "suricomai-ticket-v1";

/// Where and how to trust a development node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeTicket {
    /// Transport key the client pins before it connects.
    pub transport_key: [u8; 32],
    /// Ed25519 public key of the node's lab quote root.
    pub lab_root: [u8; 32],
}

impl NodeTicket {
    /// The printable form.
    pub fn to_line(&self) -> String {
        format!(
            "{PREFIX}.{}.{}",
            key_to_hex(&self.transport_key),
            key_to_hex(&self.lab_root)
        )
    }

    /// Read a printed ticket. Anything but the exact form is refused.
    pub fn parse(line: &str) -> Result<Self, RuntimeError> {
        let mut parts = line.trim().split('.');
        let (Some(prefix), Some(transport), Some(root), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(RuntimeError::BadRequest);
        };
        if prefix != PREFIX {
            return Err(RuntimeError::BadRequest);
        }
        Ok(Self {
            transport_key: key_from_hex(transport)?,
            lab_root: key_from_hex(root)?,
        })
    }
}

/// Lowercase hex of a 32-byte key.
pub fn key_to_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Read a 64-character hex key. Anything else is refused.
pub fn key_from_hex(text: &str) -> Result<[u8; 32], RuntimeError> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(RuntimeError::BadRequest);
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
            .map_err(|_| RuntimeError::BadRequest)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> NodeTicket {
        NodeTicket {
            transport_key: [0xAB; 32],
            lab_root: [0x01; 32],
        }
    }

    #[test]
    fn a_ticket_round_trips() {
        assert_eq!(NodeTicket::parse(&sample().to_line()).unwrap(), sample());
    }

    #[test]
    fn a_malformed_ticket_is_refused() {
        let good = sample().to_line();
        let bad = [
            String::new(),
            good.replace("suricomai-ticket-v1", "suricomai-ticket-v2"),
            format!("{good}.00"),
            good.rsplit_once('.').unwrap().0.to_string(),
            good[..good.len() - 1].to_string(),
            format!("{good}0"),
            good.replace("ab", "zz"),
            good.replace('.', ":"),
            format!("{} +{}", &good[..20], &good[22..]),
        ];
        for line in bad {
            assert_eq!(
                NodeTicket::parse(&line),
                Err(RuntimeError::BadRequest),
                "{line}"
            );
        }
    }

    #[test]
    fn a_ticket_with_non_ascii_text_is_refused_without_panicking() {
        let line = format!("suricomai-ticket-v1.{}.{}", "é".repeat(32), "0".repeat(64));
        assert_eq!(NodeTicket::parse(&line), Err(RuntimeError::BadRequest));
    }
}
