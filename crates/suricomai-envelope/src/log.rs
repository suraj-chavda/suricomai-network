// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Host log. The only accepted line is metadata plus a `'static` code.
//!
//! A prompt cannot be passed to [`HostLog::record`]: the code parameter is `'static`,
//! and the ids are fixed-width digests rendered as hex.

use crate::commit::hex32;
use crate::error::EnvelopeError;

/// Oldest lines are dropped past this count so a long-running host stays bounded.
const MAX_LINES: usize = 4096;

/// Lines produced while opening a job or an answer.
#[derive(Debug, Default)]
pub struct HostLog {
    lines: Vec<String>,
}

impl HostLog {
    /// Record one attempt. `code` is a static error code or `"accepted"`.
    pub fn record(
        &mut self,
        job_id: &[u8; 32],
        size_class: u64,
        executor: &[u8; 32],
        code: &'static str,
    ) {
        if self.lines.len() >= MAX_LINES {
            self.lines.remove(0);
        }
        self.lines.push(format!(
            "job_id={} size_class={size_class} executor={} code={code}",
            hex32(job_id),
            hex32(executor),
        ));
    }

    /// Borrow the lines joined by newlines.
    pub fn as_text(&self) -> String {
        self.lines.join("\n")
    }

    /// True when any recorded line contains `needle`.
    pub fn contains(&self, needle: &str) -> bool {
        self.lines.iter().any(|line| line.contains(needle))
    }
}

/// Logs exactly once when dropped, using only ids known so far and a static code.
pub(crate) struct AttemptLog<'a> {
    log: &'a mut HostLog,
    job_id: [u8; 32],
    size_class: u64,
    executor: [u8; 32],
    known: bool,
    code: &'static str,
}

impl<'a> AttemptLog<'a> {
    pub(crate) fn new(log: &'a mut HostLog) -> Self {
        Self {
            log,
            job_id: [0; 32],
            size_class: 0,
            executor: [0; 32],
            known: false,
            code: EnvelopeError::Malformed.code(),
        }
    }

    pub(crate) fn set_meta(&mut self, job_id: [u8; 32], size_class: u64, executor: [u8; 32]) {
        self.job_id = job_id;
        self.size_class = size_class;
        self.executor = executor;
        self.known = true;
    }

    pub(crate) fn reject<T>(&mut self, err: EnvelopeError) -> Result<T, EnvelopeError> {
        self.code = err.code();
        Err(err)
    }

    pub(crate) fn accept(&mut self) {
        self.code = "accepted";
    }
}

impl Drop for AttemptLog<'_> {
    fn drop(&mut self) {
        self.log
            .record(&self.job_id, self.size_class, &self.executor, self.code);
    }
}
