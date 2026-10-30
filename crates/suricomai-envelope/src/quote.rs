// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Advertisements and the quote traits.
//!
//! A [`QuoteVerifier`] is where hardware evidence enters. This crate ships no vendor
//! verifier yet. The software quote used in development lives in `lab_quote` and exists only
//! when the `lab` feature is on.

use std::collections::BTreeMap;

use crate::cbor::{self, Cbor};
use crate::commit::advertise_report;
use crate::error::EnvelopeError;
use crate::keys::{verifying_key, EnclaveKeys};
use crate::suite::{
    ADVERTISEMENT_VERSION, DIGEST_LEN, HPKE_PUBLIC_LEN, MAX_ADVERTISEMENT_SECS, MAX_CLOCK_SKEW_SECS,
};
use crate::types::{bytes_at, digest_at, require_keys, MeasurementAllowlist, Tier};

/// Signs `(executor_id, report_data)` into a quote blob.
pub trait QuoteAttester: Send + Sync {
    /// Produce a quote that [`QuoteVerifier`] can check.
    fn attest(
        &self,
        executor_id: &[u8; DIGEST_LEN],
        report_data: &[u8; DIGEST_LEN],
    ) -> Result<Vec<u8>, EnvelopeError>;
}

/// Checks a quote blob against an executor id and report data.
pub trait QuoteVerifier: Send + Sync {
    /// Accept the quote only when it binds `executor_id` and `report_data`.
    fn verify_quote(
        &self,
        executor_id: &[u8; DIGEST_LEN],
        report_data: &[u8; DIGEST_LEN],
        quote: &[u8],
    ) -> Result<(), EnvelopeError>;
}

/// Unverified worker advertisement, as a relay or client would see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advertisement {
    /// Measurement for P2, or worker id for a non-private worker.
    pub executor_id: [u8; DIGEST_LEN],
    /// X-Wing key prompts are sealed to.
    pub hpke_public: Vec<u8>,
    /// Key that will sign the receipt.
    pub receipt_public: [u8; DIGEST_LEN],
    /// Fresh nonce chosen for this advertisement.
    pub nonce: [u8; DIGEST_LEN],
    /// Unix seconds when the worker produced this advertisement.
    pub issued_at: u64,
    /// Unix seconds after which a client must refuse it. At most a day past `issued_at`.
    pub valid_until: u64,
    /// Node transport key, or 32 zero bytes when the node has no network transport.
    pub transport_public: [u8; DIGEST_LEN],
    /// Quote over [`advertise_report`](crate::commit) fields. Opaque to relays.
    pub quote: Vec<u8>,
}

impl Advertisement {
    /// Canonical CBOR map.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        if self.hpke_public.len() != HPKE_PUBLIC_LEN || self.quote.is_empty() {
            return Err(EnvelopeError::BadLength);
        }
        let mut map = BTreeMap::new();
        map.insert(1, Cbor::UInt(ADVERTISEMENT_VERSION));
        map.insert(2, Cbor::Bytes(self.executor_id.to_vec()));
        map.insert(3, Cbor::Bytes(self.hpke_public.clone()));
        map.insert(4, Cbor::Bytes(self.receipt_public.to_vec()));
        map.insert(5, Cbor::Bytes(self.nonce.to_vec()));
        map.insert(6, Cbor::Bytes(self.quote.clone()));
        map.insert(7, Cbor::UInt(self.issued_at));
        map.insert(8, Cbor::UInt(self.valid_until));
        map.insert(9, Cbor::Bytes(self.transport_public.to_vec()));
        Ok(cbor::encode(&Cbor::Map(map)))
    }

    /// Decode a canonical advertisement.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let value = cbor::decode(bytes)?;
        let map = cbor::as_map(&value)?;
        require_keys(map, &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
        if cbor::as_u64(map.get(&1).ok_or(EnvelopeError::Malformed)?)? != ADVERTISEMENT_VERSION {
            return Err(EnvelopeError::BadVersion);
        }
        let ad = Self {
            executor_id: digest_at(map, 2)?,
            hpke_public: bytes_at(map, 3, Some(HPKE_PUBLIC_LEN))?.to_vec(),
            receipt_public: digest_at(map, 4)?,
            nonce: digest_at(map, 5)?,
            quote: bytes_at(map, 6, None)?.to_vec(),
            issued_at: cbor::as_u64(map.get(&7).ok_or(EnvelopeError::Malformed)?)?,
            valid_until: cbor::as_u64(map.get(&8).ok_or(EnvelopeError::Malformed)?)?,
            transport_public: digest_at(map, 9)?,
        };
        if ad.quote.is_empty() || ad.to_bytes()? != bytes {
            return Err(EnvelopeError::NonCanonical);
        }
        Ok(ad)
    }
}

/// An advertisement whose quote, measurement, and keys have been checked.
///
/// Only [`verify_advertisement`] constructs this value.
#[derive(Clone, Debug)]
pub struct VerifiedAdvertisement {
    executor_id: [u8; DIGEST_LEN],
    hpke_public: Vec<u8>,
    receipt_public: [u8; DIGEST_LEN],
    transport_public: [u8; DIGEST_LEN],
}

impl VerifiedAdvertisement {
    /// Measurement bound into the quote.
    pub fn executor_id(&self) -> [u8; DIGEST_LEN] {
        self.executor_id
    }

    /// Enclave HPKE key. Safe to seal to.
    pub fn hpke_public(&self) -> &[u8] {
        &self.hpke_public
    }

    /// Receipt key bound into the same quote.
    pub fn receipt_public(&self) -> [u8; DIGEST_LEN] {
        self.receipt_public
    }

    /// Transport key bound into the same quote. All zero means no network transport.
    pub fn transport_public(&self) -> [u8; DIGEST_LEN] {
        self.transport_public
    }
}

/// Build an advertisement for `keys` that is valid from `issued_at` until `valid_until`,
/// and bind it with `attester`. The window is inside the quoted report data, so a
/// relay cannot stretch it.
pub fn advertise(
    keys: &EnclaveKeys,
    nonce: [u8; DIGEST_LEN],
    issued_at: u64,
    valid_until: u64,
    transport_public: [u8; DIGEST_LEN],
    attester: &dyn QuoteAttester,
) -> Result<Advertisement, EnvelopeError> {
    check_window(issued_at, valid_until)?;
    let executor_id = keys.executor_id();
    let receipt_public = keys.receipt_public();
    let report = advertise_report(
        keys.hpke_public(),
        &receipt_public,
        &executor_id,
        &nonce,
        issued_at,
        valid_until,
        &transport_public,
    );
    let quote = attester.attest(&executor_id, &report)?;
    Ok(Advertisement {
        executor_id,
        hpke_public: keys.hpke_public().to_vec(),
        receipt_public,
        nonce,
        quote,
        issued_at,
        valid_until,
        transport_public,
    })
}

fn check_window(issued_at: u64, valid_until: u64) -> Result<(), EnvelopeError> {
    if valid_until <= issued_at || valid_until - issued_at > MAX_ADVERTISEMENT_SECS {
        return Err(EnvelopeError::StaleAdvertisement);
    }
    Ok(())
}

fn check_fresh(ad: &Advertisement, now: u64) -> Result<(), EnvelopeError> {
    check_window(ad.issued_at, ad.valid_until)?;
    if now.saturating_add(MAX_CLOCK_SKEW_SECS) < ad.issued_at || now >= ad.valid_until {
        return Err(EnvelopeError::StaleAdvertisement);
    }
    Ok(())
}

/// Check a worker advertisement for a P0 or P1 job.
///
/// The quote must bind the HPKE and receipt keys. The measurement allowlist is
/// not used. The worker still reads the prompt after open.
pub fn verify_transit_advertisement(
    ad: &Advertisement,
    verifier: &dyn QuoteVerifier,
    now: u64,
) -> Result<TransitTarget, EnvelopeError> {
    if ad.hpke_public.len() != HPKE_PUBLIC_LEN {
        return Err(EnvelopeError::BadLength);
    }
    check_fresh(ad, now)?;
    let _ = verifying_key(&ad.receipt_public)?;
    let report = advertise_report(
        &ad.hpke_public,
        &ad.receipt_public,
        &ad.executor_id,
        &ad.nonce,
        ad.issued_at,
        ad.valid_until,
        &ad.transport_public,
    );
    verifier.verify_quote(&ad.executor_id, &report, &ad.quote)?;
    TransitTarget::new(ad.executor_id, ad.hpke_public.clone(), ad.receipt_public)
}

/// Check the quote before any prompt leaves the caller.
pub fn verify_advertisement(
    ad: &Advertisement,
    allowlist: &MeasurementAllowlist,
    verifier: &dyn QuoteVerifier,
    now: u64,
) -> Result<VerifiedAdvertisement, EnvelopeError> {
    if ad.hpke_public.len() != HPKE_PUBLIC_LEN {
        return Err(EnvelopeError::BadLength);
    }
    check_fresh(ad, now)?;
    if !allowlist.contains(&ad.executor_id) {
        return Err(EnvelopeError::MeasurementRejected);
    }
    let _ = verifying_key(&ad.receipt_public)?;
    let report = advertise_report(
        &ad.hpke_public,
        &ad.receipt_public,
        &ad.executor_id,
        &ad.nonce,
        ad.issued_at,
        ad.valid_until,
        &ad.transport_public,
    );
    verifier.verify_quote(&ad.executor_id, &report, &ad.quote)?;
    Ok(VerifiedAdvertisement {
        executor_id: ad.executor_id,
        hpke_public: ad.hpke_public.clone(),
        receipt_public: ad.receipt_public,
        transport_public: ad.transport_public,
    })
}

/// Where a non-private job is sealed. Holding this value does not mean a TEE was checked.
#[derive(Clone, Debug)]
pub struct TransitTarget {
    worker_id: [u8; DIGEST_LEN],
    hpke_public: Vec<u8>,
    receipt_public: [u8; DIGEST_LEN],
}

impl TransitTarget {
    /// Pin a worker key for a P0 or P1 job.
    pub fn new(
        worker_id: [u8; DIGEST_LEN],
        hpke_public: Vec<u8>,
        receipt_public: [u8; DIGEST_LEN],
    ) -> Result<Self, EnvelopeError> {
        if hpke_public.len() != HPKE_PUBLIC_LEN {
            return Err(EnvelopeError::BadLength);
        }
        let _ = verifying_key(&receipt_public)?;
        Ok(Self {
            worker_id,
            hpke_public,
            receipt_public,
        })
    }

    /// Worker id copied into the sealed job.
    pub fn worker_id(&self) -> [u8; DIGEST_LEN] {
        self.worker_id
    }

    /// HPKE key the prompt is sealed to.
    pub fn hpke_public(&self) -> &[u8] {
        &self.hpke_public
    }

    /// Receipt key the user will require on the proof.
    pub fn receipt_public(&self) -> [u8; DIGEST_LEN] {
        self.receipt_public
    }
}

/// Who the user is willing to seal to, matched to the contract tier.
#[derive(Clone, Debug)]
pub enum SealTarget {
    /// P2 only. Constructed from [`verify_advertisement`].
    Private(VerifiedAdvertisement),
    /// P0 or P1 only. The worker will see the prompt.
    Transit(TransitTarget),
}

impl SealTarget {
    pub(crate) fn identity(&self) -> ([u8; DIGEST_LEN], &[u8], [u8; DIGEST_LEN]) {
        match self {
            Self::Private(ad) => (ad.executor_id(), ad.hpke_public(), ad.receipt_public()),
            Self::Transit(target) => (
                target.worker_id(),
                target.hpke_public(),
                target.receipt_public(),
            ),
        }
    }

    pub(crate) fn matches_tier(&self, tier: Tier) -> Result<(), EnvelopeError> {
        match (tier, self) {
            (Tier::P2, Self::Private(_)) => Ok(()),
            (Tier::P2, Self::Transit(_)) => Err(EnvelopeError::NotPrivateTarget),
            (Tier::P0 | Tier::P1, Self::Transit(_)) => Ok(()),
            (Tier::P0 | Tier::P1, Self::Private(_)) => Err(EnvelopeError::NotTransitTarget),
        }
    }
}
