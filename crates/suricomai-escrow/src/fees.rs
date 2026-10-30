// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! What a job costs, line by line, and where every unit goes.
//!
//! A [`Quote`] is the whole price: the worker's price plus three named lines. There is no
//! other charge. [`Quote::settled`] and [`Quote::failed`] return a [`Payout`] whose parts
//! always sum to the quote, so nothing is taken that the quote did not show. All amounts are
//! whole units of the smallest denomination (millionths of a dollar for USDC). Every line is
//! an integer computation with one fixed rounding rule, so any implementation gets the same
//! bytes. The protocol specification, "Fee schedule", is the normative text, and `vectors/fees-v1.txt` is
//! checked by this module and by an independent Python implementation.

/// Basis points in a whole.
pub const BPS: u64 = 10_000;

/// Smallest worker price a job may have. Below it the fixed attestation line would be most
/// of the cost, and dust jobs would cost the network more than they pay.
pub const MIN_PRICE: u64 = 10_000;

/// The protocol fee can never exceed this, whatever a schedule says.
pub const MAX_PROTOCOL_BPS: u64 = 300;

/// The attestation fee can never exceed this many basis points of the price.
pub const MAX_ATTESTATION_BPS: u64 = 300;

/// The relay fee can never exceed this many basis points of the price.
pub const MAX_RELAY_BPS: u64 = 300;

/// The fixed floor of the attestation line can never exceed this.
pub const MAX_ATTESTATION_MIN: u64 = 100_000;

/// Why a schedule or a quote was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeError {
    /// A schedule field is past its hard cap, or encoded bytes are not a schedule.
    BadSchedule,
    /// The worker price is below [`MIN_PRICE`].
    PriceTooSmall,
    /// An amount does not fit in a `u64`.
    Overflow,
}

impl FeeError {
    /// Stable code, safe to log and to put on the wire.
    pub const fn code(self) -> &'static str {
        match self {
            Self::BadSchedule => "bad_fee_schedule",
            Self::PriceTooSmall => "price_too_small",
            Self::Overflow => "fee_overflow",
        }
    }
}

impl std::fmt::Display for FeeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for FeeError {}

/// The three rates a deployment is built with. They are fixed for that deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeSchedule {
    /// Protocol fee in basis points of the worker price.
    pub protocol_bps: u64,
    /// Attestation fee in basis points of the worker price.
    pub attestation_bps: u64,
    /// The attestation fee is at least this many units, because its cost does not shrink
    /// with the price.
    pub attestation_min: u64,
    /// Most the relay line can be, in basis points of the worker price. It is charged only
    /// when a relay carried the job.
    pub relay_bps: u64,
}

const MAGIC: &[u8; 4] = b"SFS1";

impl FeeSchedule {
    /// A schedule, refused if any field is past its hard cap.
    pub fn new(
        protocol_bps: u64,
        attestation_bps: u64,
        attestation_min: u64,
        relay_bps: u64,
    ) -> Result<Self, FeeError> {
        if protocol_bps > MAX_PROTOCOL_BPS
            || attestation_bps > MAX_ATTESTATION_BPS
            || relay_bps > MAX_RELAY_BPS
            || attestation_min > MAX_ATTESTATION_MIN
        {
            return Err(FeeError::BadSchedule);
        }
        Ok(Self {
            protocol_bps,
            attestation_bps,
            attestation_min,
            relay_bps,
        })
    }

    /// Canonical bytes: `SFS1` then the four fields as big endian `u64`. A client shows the
    /// hash of these bytes next to the contract address, so a different schedule is visible.
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut out = [0u8; 36];
        out[..4].copy_from_slice(MAGIC);
        for (i, field) in [
            self.protocol_bps,
            self.attestation_bps,
            self.attestation_min,
            self.relay_bps,
        ]
        .iter()
        .enumerate()
        {
            out[4 + i * 8..12 + i * 8].copy_from_slice(&field.to_be_bytes());
        }
        out
    }

    /// Read canonical bytes. Wrong length, wrong magic or a field past its cap is refused.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FeeError> {
        let bytes: &[u8; 36] = bytes.try_into().map_err(|_| FeeError::BadSchedule)?;
        if &bytes[..4] != MAGIC {
            return Err(FeeError::BadSchedule);
        }
        let field = |i: usize| -> u64 {
            let mut word = [0u8; 8];
            word.copy_from_slice(&bytes[4 + i * 8..12 + i * 8]);
            u64::from_be_bytes(word)
        };
        Self::new(field(0), field(1), field(2), field(3))
    }
}

/// `ceil(price * bps / 10000)`, computed in 128 bits so it cannot overflow before the check.
fn ceil_bps(price: u64, bps: u64) -> Result<u64, FeeError> {
    let product = u128::from(price) * u128::from(bps);
    let units = product.div_ceil(u128::from(BPS));
    u64::try_from(units).map_err(|_| FeeError::Overflow)
}

/// The whole price of one job. The user locks `total`. Nothing else is ever charged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quote {
    /// What the worker is paid.
    pub price: u64,
    /// The protocol fee.
    pub protocol: u64,
    /// The attestation fee, paid to the committee that signs the settlement.
    pub attestation: u64,
    /// The most a relay can be paid. Unused, it is refunded.
    pub relay_max: u64,
    /// `price + protocol + attestation + relay_max`.
    pub total: u64,
}

/// Quote a job. Every charge line rounds up to the next unit, so a line is never rounded
/// away to nothing, and never exceeds its rate by a full unit.
pub fn quote(price: u64, schedule: &FeeSchedule) -> Result<Quote, FeeError> {
    if price < MIN_PRICE {
        return Err(FeeError::PriceTooSmall);
    }
    let protocol = ceil_bps(price, schedule.protocol_bps)?;
    let attestation = ceil_bps(price, schedule.attestation_bps)?.max(schedule.attestation_min);
    let relay_max = ceil_bps(price, schedule.relay_bps)?;
    let total = price
        .checked_add(protocol)
        .and_then(|sum| sum.checked_add(attestation))
        .and_then(|sum| sum.checked_add(relay_max))
        .ok_or(FeeError::Overflow)?;
    Ok(Quote {
        price,
        protocol,
        attestation,
        relay_max,
        total,
    })
}

/// Where every unit of a locked quote goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Payout {
    /// To the worker.
    pub worker: u64,
    /// To the protocol fee recipient.
    pub protocol: u64,
    /// To the attestation committee.
    pub attestation: u64,
    /// To the relay that carried the job.
    pub relay: u64,
    /// Back to the user.
    pub refund: u64,
}

impl Payout {
    /// The sum of every part. It always equals the quote total.
    pub fn total(&self) -> u64 {
        self.worker + self.protocol + self.attestation + self.relay + self.refund
    }
}

impl Quote {
    /// A job that was proven and paid. The relay line is paid only if a relay carried the
    /// job, and the rest of it goes back to the user.
    pub fn settled(&self, relay_carried: bool) -> Payout {
        let relay = if relay_carried { self.relay_max } else { 0 };
        Payout {
            worker: self.price,
            protocol: self.protocol,
            attestation: self.attestation,
            relay,
            refund: self.relay_max - relay,
        }
    }

    /// A job that expired or was slashed. The user gets everything back. No fee is taken on
    /// work that was not delivered.
    pub fn failed(&self) -> Payout {
        Payout {
            worker: 0,
            protocol: 0,
            attestation: 0,
            relay: 0,
            refund: self.total,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn standard() -> FeeSchedule {
        FeeSchedule::new(100, 100, 2_000, 100).unwrap()
    }

    #[test]
    fn a_one_dollar_job_is_priced_by_hand() {
        // 1.00 USD is 1_000_000 units. 1% of that is 10_000 for each line.
        let q = quote(1_000_000, &standard()).unwrap();
        assert_eq!(q.price, 1_000_000);
        assert_eq!(q.protocol, 10_000);
        assert_eq!(q.attestation, 10_000);
        assert_eq!(q.relay_max, 10_000);
        assert_eq!(q.total, 1_030_000);
        let paid = q.settled(true);
        assert_eq!(
            (
                paid.worker,
                paid.protocol,
                paid.attestation,
                paid.relay,
                paid.refund
            ),
            (1_000_000, 10_000, 10_000, 10_000, 0)
        );
        let direct = q.settled(false);
        assert_eq!((direct.relay, direct.refund), (0, 10_000));
    }

    #[test]
    fn the_smallest_job_is_dominated_by_the_fixed_floor_and_that_is_visible() {
        // 0.01 USD: 1% is 100, so the attestation line is the 2_000 floor.
        let q = quote(MIN_PRICE, &standard()).unwrap();
        assert_eq!(q.protocol, 100);
        assert_eq!(q.attestation, 2_000);
        assert_eq!(q.relay_max, 100);
        assert_eq!(q.total, 12_200);
    }

    #[test]
    fn rounding_goes_up_by_less_than_a_unit_and_never_to_zero() {
        // 10_001 * 100 bps = 100.01 units, so the line is 101 and not 100.
        let q = quote(10_001, &standard()).unwrap();
        assert_eq!(q.protocol, 101);
        let free = FeeSchedule::new(0, 0, 0, 0).unwrap();
        let q = quote(123_456, &free).unwrap();
        assert_eq!((q.protocol, q.attestation, q.relay_max), (0, 0, 0));
        assert_eq!(q.total, 123_456);
        let tiny_rate = FeeSchedule::new(1, 0, 0, 0).unwrap();
        assert_eq!(quote(MIN_PRICE, &tiny_rate).unwrap().protocol, 1);
    }

    #[test]
    fn every_price_in_a_wide_range_sums_exactly_and_stays_inside_its_rate() {
        let schedules = [
            standard(),
            FeeSchedule::new(300, 300, 100_000, 300).unwrap(),
            FeeSchedule::new(1, 1, 0, 1).unwrap(),
            FeeSchedule::new(0, 0, 0, 0).unwrap(),
            FeeSchedule::new(299, 7, 12_345, 133).unwrap(),
        ];
        for schedule in schedules {
            for price in MIN_PRICE..MIN_PRICE + 40_000 {
                let q = quote(price, &schedule).unwrap();
                assert_eq!(q.total, q.price + q.protocol + q.attestation + q.relay_max);
                for (line, bps) in [
                    (q.protocol, schedule.protocol_bps),
                    (q.relay_max, schedule.relay_bps),
                ] {
                    let exact = u128::from(price) * u128::from(bps);
                    assert!(u128::from(line) * 10_000 >= exact, "rounded down");
                    assert!(
                        u128::from(line) * 10_000 < exact + 10_000,
                        "rounded up a whole unit"
                    );
                }
                let rate = u128::from(price) * u128::from(schedule.attestation_bps);
                assert!(q.attestation >= schedule.attestation_min);
                assert!(u128::from(q.attestation) * 10_000 >= rate);
                for relay_carried in [true, false] {
                    assert_eq!(q.settled(relay_carried).total(), q.total);
                }
                let failed = q.failed();
                assert_eq!(failed.total(), q.total);
                assert_eq!(failed.refund, q.total);
                assert_eq!(
                    failed.worker + failed.protocol + failed.attestation + failed.relay,
                    0
                );
            }
        }
    }

    #[test]
    fn the_total_overhead_never_passes_the_published_cap() {
        // Worst case: 3 percent for each of three lines, plus the fixed floor and rounding.
        let worst = FeeSchedule::new(
            MAX_PROTOCOL_BPS,
            MAX_ATTESTATION_BPS,
            MAX_ATTESTATION_MIN,
            MAX_RELAY_BPS,
        )
        .unwrap();
        for price in [MIN_PRICE, 99_999, 1_000_000, 123_456_789, 10_000_000_000] {
            let q = quote(price, &worst).unwrap();
            let overhead = q.total - q.price;
            let bound = u128::from(price) * 900 / 10_000 + 3 + u128::from(MAX_ATTESTATION_MIN);
            assert!(
                u128::from(overhead) <= bound,
                "{price}: {overhead} > {bound}"
            );
        }
    }

    #[test]
    fn a_price_below_the_minimum_or_one_that_overflows_is_refused_without_panicking() {
        for price in [0, 1, MIN_PRICE - 1] {
            assert_eq!(quote(price, &standard()), Err(FeeError::PriceTooSmall));
        }
        let worst = FeeSchedule::new(300, 300, 100_000, 300).unwrap();
        for price in [u64::MAX, u64::MAX - 1, u64::MAX / 1_000 * 999] {
            let outcome = quote(price, &worst);
            assert!(
                matches!(outcome, Err(FeeError::Overflow)),
                "{price}: {outcome:?}"
            );
        }
        // Half of the range plus 9 percent still fits, and is priced exactly.
        let half = quote(u64::MAX / 2, &worst).unwrap();
        assert_eq!(
            half.total,
            half.price + half.protocol + half.attestation + half.relay_max
        );
        let free = FeeSchedule::new(0, 0, 0, 0).unwrap();
        assert_eq!(quote(u64::MAX, &free).unwrap().total, u64::MAX);
    }

    #[test]
    fn a_schedule_past_any_hard_cap_is_refused() {
        assert!(FeeSchedule::new(
            MAX_PROTOCOL_BPS,
            MAX_ATTESTATION_BPS,
            MAX_ATTESTATION_MIN,
            MAX_RELAY_BPS
        )
        .is_ok());
        for bad in [
            FeeSchedule::new(MAX_PROTOCOL_BPS + 1, 0, 0, 0),
            FeeSchedule::new(0, MAX_ATTESTATION_BPS + 1, 0, 0),
            FeeSchedule::new(0, 0, MAX_ATTESTATION_MIN + 1, 0),
            FeeSchedule::new(0, 0, 0, MAX_RELAY_BPS + 1),
            FeeSchedule::new(u64::MAX, u64::MAX, u64::MAX, u64::MAX),
        ] {
            assert_eq!(bad, Err(FeeError::BadSchedule));
        }
    }

    #[test]
    fn a_schedule_round_trips_and_malformed_bytes_are_refused() {
        let schedule = standard();
        assert_eq!(FeeSchedule::from_bytes(&schedule.to_bytes()), Ok(schedule));
        let good = schedule.to_bytes();
        let mut wrong_magic = good;
        wrong_magic[0] = b'X';
        let mut past_cap = good;
        past_cap[4..12].copy_from_slice(&(MAX_PROTOCOL_BPS + 1).to_be_bytes());
        for bad in [
            Vec::new(),
            good[..35].to_vec(),
            [good.as_slice(), &[0]].concat(),
            wrong_magic.to_vec(),
            past_cap.to_vec(),
        ] {
            assert_eq!(FeeSchedule::from_bytes(&bad), Err(FeeError::BadSchedule));
        }
        let other = FeeSchedule::new(101, 100, 2_000, 100).unwrap();
        assert_ne!(schedule.to_bytes(), other.to_bytes());
    }

    #[test]
    fn the_checked_in_vectors_match() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vectors/fees-v1.txt"
        ))
        .expect("vectors/fees-v1.txt");
        let mut checked = 0;
        for line in text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        {
            let (input, expected) = line.split_once('|').expect("input | expected");
            let n: Vec<u64> = input
                .split_whitespace()
                .map(|w| w.parse().unwrap())
                .collect();
            let want: Vec<&str> = expected.split_whitespace().collect();
            let schedule = FeeSchedule::new(n[0], n[1], n[2], n[3]).unwrap();
            match quote(n[4], &schedule) {
                Ok(q) => {
                    let got = [q.price, q.protocol, q.attestation, q.relay_max, q.total];
                    let want: Vec<u64> = want.iter().map(|w| w.parse().unwrap()).collect();
                    assert_eq!(got.to_vec(), want, "{line}");
                }
                Err(e) => assert_eq!(want, [e.code()], "{line}"),
            }
            checked += 1;
        }
        assert!(checked >= 100, "only {checked} vectors");
    }
}
