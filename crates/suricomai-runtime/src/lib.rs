// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! SuriComAI **executor node** runtime (reference implementation).
//!
//! Loads pinned models, accepts sealed jobs, returns sealed answers and proof
//! bundles. Production P2 uses a vendor [`suricomai_envelope::QuoteVerifier`] inside
//! a measured guest; **development builds** on non-TEE hardware use the lab quote
//! and [`Executor::claim_hardware_p2`] always fails until attestation is real.
//!
//! The same code path runs on a developer machine and on a network executor.
//! Only the quote verifier and the privacy labels change.

#![forbid(unsafe_code)]

#[cfg(not(feature = "lab"))]
compile_error!(
    "suricomai-runtime is the development node: it signs software quotes and ships a test model. \
     Build it with `--features lab`. There is no hardware-backed build yet."
);

mod chat;
mod client;
mod directory;
mod error;
#[cfg(test)]
mod hosting_tests;
mod http;
#[cfg(unix)]
mod identity;
mod lab;
mod model;
mod node;
mod pack;
mod registry;
mod relay;
mod select;
mod session;
pub mod testing;
#[cfg(test)]
mod testkit;
mod text_model;
mod ticket;
mod transport;
mod trust;
mod wire;

pub use chat::{pack_user_prompt, ChatCompletion, ChatMessage, ChatRequest};
pub use client::{Client, Completion, JobRequest, PrivacyLabel};
pub use directory::{
    address_allowed, list_directory, publish_to_directory, Directory, DirectoryConfig,
    DirectoryEntry, SyncReport,
};
pub use error::RuntimeError;
pub use http::serve_chat_once;
#[cfg(unix)]
pub use identity::NodeIdentity;
pub use lab::{lab_approver_public, lab_catalog};
pub use model::{
    infer, model_digest, pinned_weights, runtime_digest, runtime_measurement,
    tokenizer_file_digest, weights_file_digest, MODEL_NAME,
};
pub use node::{Executor, NodeCard, NodeStatus, ADVERTISEMENT_SECS};
pub use pack::{load_catalog, load_hosted, HostLimits, HostedModel, HostedSet};
pub use registry::{
    object_id, registry_get, registry_list, registry_put, sync_registry, Registry, RegistryConfig,
    SyncOutcome, OBJECT_APPROVAL, OBJECT_MANIFEST,
};
pub use relay::{serve_relay, RelayLimits};
pub use select::{
    complete_on_first_reachable, pick_order, select, survey, Attempt, Candidate, Surveyed, Wanted,
    SURVEY_CANDIDATES, SURVEY_DEADLINE,
};
pub use session::{
    format_elapsed, Header, ModelRow, Outcome, ProofSummary, Reply, Role, Session, ViewLine,
};
pub use text_model::TEXT_MODEL_NAME;
pub use ticket::{key_from_hex, key_to_hex, NodeTicket};
pub use transport::{
    exchange_secure, exchange_secure_via, fetch_card, fetch_card_via, fetch_model_card_via,
    serve_secure, serve_secure_one, Handler, Route, ServerLimits, TransportKey,
};
pub use trust::TrustPolicy;
pub use wire::{exchange_tcp, serve_one};

#[cfg(test)]
mod tests;
