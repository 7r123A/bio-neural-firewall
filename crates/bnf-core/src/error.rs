//! Precise rejection reasons produced by the firewall pipeline.
//!
//! Every rejection carries enough numeric context to be audited after the fact
//! (e.g. the computed charge and the limit it exceeded), and maps to a stable
//! numeric code and a stable `SCREAMING_SNAKE_CASE` name for logging and for the
//! C ABI. Codes are grouped by layer: 1xx framing, 2xx authentication,
//! 3xx freshness, 4xx physical safety.

use core::fmt;

/// The pipeline layer that produced a rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionLayer {
    /// Packet length, version or opcode was invalid.
    Framing,
    /// Session establishment or message authentication failed.
    Authentication,
    /// The counter was not strictly greater than the last accepted one, or is exhausted.
    Freshness,
    /// The authenticated command violated a physical safety limit.
    Safety,
}

/// The stimulation parameter that left the absolute safety envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeParameter {
    /// Cathodic phase amplitude (µA).
    CathodicCurrent,
    /// Anodic phase amplitude (µA).
    AnodicCurrent,
    /// Cathodic phase width (µs).
    CathodicWidth,
    /// Anodic phase width (µs).
    AnodicWidth,
    /// Gap between the two phases (µs).
    InterphaseGap,
    /// Pulse repetition rate (Hz).
    PulseRate,
    /// Number of pulses in the train.
    PulseCount,
    /// Total train duration, `pulse_count × (1 / pulse_rate)` (µs).
    TrainDuration,
}

impl EnvelopeParameter {
    /// Human-readable name with unit.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CathodicCurrent => "cathodic current (uA)",
            Self::AnodicCurrent => "anodic current (uA)",
            Self::CathodicWidth => "cathodic phase width (us)",
            Self::AnodicWidth => "anodic phase width (us)",
            Self::InterphaseGap => "interphase gap (us)",
            Self::PulseRate => "pulse rate (Hz)",
            Self::PulseCount => "pulse count",
            Self::TrainDuration => "train duration (us)",
        }
    }
}

/// Why a handshake, a signing request or a stimulation command was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rejection {
    // ---------------------------------------------------------------- framing
    /// The packet does not have the fixed wire length.
    MalformedPacket {
        /// Required length in bytes.
        expected_len: usize,
        /// Received length in bytes.
        actual_len: usize,
    },
    /// The protocol version byte is not supported.
    UnsupportedVersion {
        /// Received version byte.
        version: u8,
    },
    /// The opcode byte is not a known command.
    UnknownOpcode {
        /// Received opcode byte.
        opcode: u8,
    },

    // --------------------------------------------------------- authentication
    /// No authenticated session is active; all commands are dropped.
    NoActiveSession,
    /// `complete_handshake` was called without a pending `begin_handshake`.
    HandshakeNotStarted,
    /// ML-KEM ciphertext or key-confirmation tag was invalid
    /// (wrong length, wrong PSK, or tampered transcript).
    HandshakeFailed,
    /// The command MAC did not verify under the session key.
    AuthenticationFailed,

    // -------------------------------------------------------------- freshness
    /// The counter was not strictly greater than the last accepted counter.
    ReplayDetected {
        /// Counter carried by the rejected packet.
        counter: u64,
        /// Highest counter accepted so far in this session.
        last_accepted: u64,
    },
    /// The host has used every counter value of this session; a new handshake
    /// is required. (2⁶⁴ − 1 commands: unreachable in practice, but never
    /// allowed to wrap or repeat.)
    CounterExhausted,

    // ----------------------------------------------------------------- safety
    /// The electrode id is not present in the provisioned electrode table.
    UnknownElectrode {
        /// Requested electrode id.
        electrode_id: u16,
    },
    /// A raw parameter left the absolute envelope (above `limit`, or zero where
    /// a minimum of 1 applies: pulse rate and pulse count).
    EnvelopeExceeded {
        /// Offending parameter.
        parameter: EnvelopeParameter,
        /// Received (or derived) value.
        value: u32,
        /// Inclusive maximum.
        limit: u32,
    },
    /// The biphasic pulse does not fit inside one repetition period.
    PulseTimingInvalid {
        /// Cathodic width + interphase gap + anodic width (µs).
        active_us: u32,
        /// 1 / pulse rate (µs).
        period_us: u32,
    },
    /// One of the two phases carries zero charge (DC / monophasic pulse).
    MonophasicPulse,
    /// Cathodic and anodic charges differ by more than the tolerance.
    ChargeImbalance {
        /// Cathodic phase charge (pC).
        cathodic_pc: u64,
        /// Anodic phase charge (pC).
        anodic_pc: u64,
        /// Allowed relative mismatch (parts per million).
        tolerance_ppm: u32,
    },
    /// Shannon criterion violated: log10(D) + log10(Q) > k.
    ShannonLimitExceeded {
        /// Worst-phase charge (pC).
        charge_pc: u64,
        /// Geometric electrode area (µm²).
        area_um2: u64,
        /// D·Q × 10⁶, in µC²/cm².
        dq_micro: u64,
        /// 10^k × 10⁶ derived from the configured k.
        limit_dq_micro: u64,
    },
    /// Geometric charge density exceeded the electrode-material limit.
    ChargeDensityExceeded {
        /// Worst-phase charge (pC).
        charge_pc: u64,
        /// Geometric electrode area (µm²).
        area_um2: u64,
        /// Computed density (nC/cm²).
        density_nc_per_cm2: u64,
        /// Configured limit (nC/cm²).
        limit_nc_per_cm2: u64,
    },
}

/// Every rejection code with its stable name, in ascending code order.
pub const REJECTION_CODES: [(u16, &str); 17] = [
    (101, "MALFORMED_PACKET"),
    (102, "UNSUPPORTED_VERSION"),
    (103, "UNKNOWN_OPCODE"),
    (201, "NO_ACTIVE_SESSION"),
    (202, "HANDSHAKE_NOT_STARTED"),
    (203, "HANDSHAKE_FAILED"),
    (204, "AUTHENTICATION_FAILED"),
    (301, "REPLAY_DETECTED"),
    (302, "COUNTER_EXHAUSTED"),
    (401, "UNKNOWN_ELECTRODE"),
    (402, "ENVELOPE_EXCEEDED"),
    (403, "PULSE_TIMING_INVALID"),
    (404, "MONOPHASIC_PULSE"),
    (405, "CHARGE_IMBALANCE"),
    (406, "SHANNON_LIMIT_EXCEEDED"),
    (407, "CHARGE_DENSITY_EXCEEDED"),
    (0, "ACCEPTED"),
];

/// Stable name of a rejection code (`0` is `"ACCEPTED"`), or `None` if unknown.
#[must_use]
pub fn rejection_name(code: u16) -> Option<&'static str> {
    REJECTION_CODES.iter().find(|(c, _)| *c == code).map(|(_, name)| *name)
}

impl Rejection {
    /// Stable numeric code (1xx framing, 2xx authentication, 3xx freshness, 4xx safety).
    #[must_use]
    pub const fn code(&self) -> u16 {
        match self {
            Self::MalformedPacket { .. } => 101,
            Self::UnsupportedVersion { .. } => 102,
            Self::UnknownOpcode { .. } => 103,
            Self::NoActiveSession => 201,
            Self::HandshakeNotStarted => 202,
            Self::HandshakeFailed => 203,
            Self::AuthenticationFailed => 204,
            Self::ReplayDetected { .. } => 301,
            Self::CounterExhausted => 302,
            Self::UnknownElectrode { .. } => 401,
            Self::EnvelopeExceeded { .. } => 402,
            Self::PulseTimingInvalid { .. } => 403,
            Self::MonophasicPulse => 404,
            Self::ChargeImbalance { .. } => 405,
            Self::ShannonLimitExceeded { .. } => 406,
            Self::ChargeDensityExceeded { .. } => 407,
        }
    }

    /// Stable `SCREAMING_SNAKE_CASE` name of this rejection.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::MalformedPacket { .. } => "MALFORMED_PACKET",
            Self::UnsupportedVersion { .. } => "UNSUPPORTED_VERSION",
            Self::UnknownOpcode { .. } => "UNKNOWN_OPCODE",
            Self::NoActiveSession => "NO_ACTIVE_SESSION",
            Self::HandshakeNotStarted => "HANDSHAKE_NOT_STARTED",
            Self::HandshakeFailed => "HANDSHAKE_FAILED",
            Self::AuthenticationFailed => "AUTHENTICATION_FAILED",
            Self::ReplayDetected { .. } => "REPLAY_DETECTED",
            Self::CounterExhausted => "COUNTER_EXHAUSTED",
            Self::UnknownElectrode { .. } => "UNKNOWN_ELECTRODE",
            Self::EnvelopeExceeded { .. } => "ENVELOPE_EXCEEDED",
            Self::PulseTimingInvalid { .. } => "PULSE_TIMING_INVALID",
            Self::MonophasicPulse => "MONOPHASIC_PULSE",
            Self::ChargeImbalance { .. } => "CHARGE_IMBALANCE",
            Self::ShannonLimitExceeded { .. } => "SHANNON_LIMIT_EXCEEDED",
            Self::ChargeDensityExceeded { .. } => "CHARGE_DENSITY_EXCEEDED",
        }
    }

    /// The pipeline layer that produced this rejection.
    #[must_use]
    pub const fn layer(&self) -> RejectionLayer {
        match self.code() / 100 {
            1 => RejectionLayer::Framing,
            2 => RejectionLayer::Authentication,
            3 => RejectionLayer::Freshness,
            _ => RejectionLayer::Safety,
        }
    }
}

/// Formats a fixed-point integer `value / 10^decimals` without floating point.
struct Fixed {
    value: u64,
    decimals: u32,
}

impl fmt::Display for Fixed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scale = 10u64.pow(self.decimals);
        write!(
            f,
            "{}.{:0width$}",
            self.value / scale,
            self.value % scale,
            width = self.decimals as usize
        )
    }
}

const fn uc(pc: u64) -> Fixed {
    Fixed { value: pc, decimals: 6 }
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::MalformedPacket {
                expected_len,
                actual_len,
            } => write!(
                f,
                "malformed packet: expected {expected_len} bytes, received {actual_len}"
            ),
            Self::UnsupportedVersion { version } => write!(f, "unsupported protocol version 0x{version:02x}"),
            Self::UnknownOpcode { opcode } => write!(f, "unknown opcode 0x{opcode:02x}"),
            Self::NoActiveSession => f.write_str("no authenticated session; command dropped"),
            Self::HandshakeNotStarted => f.write_str("handshake completion without a pending handshake"),
            Self::HandshakeFailed => {
                f.write_str("handshake failed: ML-KEM ciphertext or PSK-bound key confirmation invalid")
            }
            Self::AuthenticationFailed => {
                f.write_str("MAC verification failed: command is not signed by the session key")
            }
            Self::ReplayDetected { counter, last_accepted } => write!(
                f,
                "replay detected: counter {counter} <= last accepted counter {last_accepted}"
            ),
            Self::CounterExhausted => f.write_str("session counter exhausted: a new handshake is required"),
            Self::UnknownElectrode { electrode_id } => write!(f, "electrode {electrode_id} is not provisioned"),
            Self::EnvelopeExceeded {
                parameter,
                value,
                limit,
            } => write!(
                f,
                "envelope violation: {} = {value} outside allowed range (limit {limit})",
                parameter.name()
            ),
            Self::PulseTimingInvalid { active_us, period_us } => write!(
                f,
                "pulse timing invalid: active pulse {active_us} us does not fit in period {period_us} us"
            ),
            Self::MonophasicPulse => {
                f.write_str("monophasic/DC pulse rejected: both phases must carry charge (biphasic required)")
            }
            Self::ChargeImbalance {
                cathodic_pc,
                anodic_pc,
                tolerance_ppm,
            } => write!(
                f,
                "charge imbalance: cathodic {} uC vs anodic {} uC exceeds {} % tolerance",
                uc(cathodic_pc),
                uc(anodic_pc),
                Fixed {
                    value: u64::from(tolerance_ppm),
                    decimals: 4
                }
            ),
            Self::ShannonLimitExceeded {
                charge_pc,
                area_um2,
                dq_micro,
                limit_dq_micro,
            } => write!(
                f,
                "Shannon limit exceeded: Q = {} uC/phase, A = {} cm^2, D*Q = {} uC^2/cm^2 > 10^k = {}",
                uc(charge_pc),
                Fixed {
                    value: area_um2,
                    decimals: 8
                },
                uc(dq_micro),
                uc(limit_dq_micro)
            ),
            Self::ChargeDensityExceeded {
                charge_pc,
                density_nc_per_cm2,
                limit_nc_per_cm2,
                ..
            } => write!(
                f,
                "charge density exceeded: Q = {} uC/phase, D = {} uC/cm^2 > limit {} uC/cm^2",
                uc(charge_pc),
                Fixed {
                    value: density_nc_per_cm2,
                    decimals: 3
                },
                Fixed {
                    value: limit_nc_per_cm2,
                    decimals: 3
                }
            ),
        }
    }
}

impl core::error::Error for Rejection {}

#[cfg(test)]
mod tests {
    use super::*;

    /// One instance of every variant (keep in sync with the enum: the exhaustive
    /// match in `code()` and the length assertion below catch omissions).
    fn every_variant() -> [Rejection; 16] {
        [
            Rejection::MalformedPacket {
                expected_len: 68,
                actual_len: 0,
            },
            Rejection::UnsupportedVersion { version: 2 },
            Rejection::UnknownOpcode { opcode: 0x99 },
            Rejection::NoActiveSession,
            Rejection::HandshakeNotStarted,
            Rejection::HandshakeFailed,
            Rejection::AuthenticationFailed,
            Rejection::ReplayDetected {
                counter: 1,
                last_accepted: 1,
            },
            Rejection::CounterExhausted,
            Rejection::UnknownElectrode { electrode_id: 9 },
            Rejection::EnvelopeExceeded {
                parameter: EnvelopeParameter::PulseRate,
                value: 0,
                limit: 300,
            },
            Rejection::PulseTimingInvalid {
                active_us: 2_200,
                period_us: 1_000,
            },
            Rejection::MonophasicPulse,
            Rejection::ChargeImbalance {
                cathodic_pc: 100_000,
                anodic_pc: 98_000,
                tolerance_ppm: 10_000,
            },
            Rejection::ShannonLimitExceeded {
                charge_pc: 10_000_000,
                area_um2: 4_000_000,
                dq_micro: 2_500_000_000,
                limit_dq_micro: 56_234_130,
            },
            Rejection::ChargeDensityExceeded {
                charge_pc: 1_300_000,
                area_um2: 4_000_000,
                density_nc_per_cm2: 32_500,
                limit_nc_per_cm2: 30_000,
            },
        ]
    }

    #[test]
    fn code_table_is_consistent_with_variants() {
        let variants = every_variant();
        // Every variant except ACCEPTED appears exactly once in the table.
        assert_eq!(variants.len() + 1, REJECTION_CODES.len());
        for r in variants {
            assert_eq!(rejection_name(r.code()), Some(r.name()), "{r:?}");
        }
        for (i, (code, name)) in REJECTION_CODES.iter().enumerate() {
            assert!(
                REJECTION_CODES[i + 1..].iter().all(|(c, n)| c != code && n != name),
                "duplicate entry {code} {name}"
            );
        }
        assert_eq!(rejection_name(0), Some("ACCEPTED"));
        assert_eq!(rejection_name(999), None);
    }

    #[test]
    fn codes_map_to_layers() {
        let expected = |r: &Rejection| match r.code() {
            101..=199 => RejectionLayer::Framing,
            201..=299 => RejectionLayer::Authentication,
            301..=399 => RejectionLayer::Freshness,
            _ => RejectionLayer::Safety,
        };
        for r in every_variant() {
            assert_eq!(r.layer(), expected(&r), "{r:?}");
        }
    }

    #[test]
    fn every_variant_has_a_meaningful_ascii_message() {
        for r in every_variant() {
            let msg = format!("{r}");
            assert!(msg.len() > 15, "{r:?} -> {msg}");
            assert!(msg.is_ascii(), "{msg}");
        }
    }

    #[test]
    fn physics_messages_are_formatted_exactly() {
        let v = every_variant();
        assert_eq!(
            v[14].to_string(),
            "Shannon limit exceeded: Q = 10.000000 uC/phase, A = 0.04000000 cm^2, \
             D*Q = 2500.000000 uC^2/cm^2 > 10^k = 56.234130"
        );
        assert_eq!(
            v[15].to_string(),
            "charge density exceeded: Q = 1.300000 uC/phase, D = 32.500 uC/cm^2 > limit 30.000 uC/cm^2"
        );
        assert_eq!(
            v[13].to_string(),
            "charge imbalance: cathodic 0.100000 uC vs anodic 0.098000 uC exceeds 1.0000 % tolerance"
        );
    }

    #[test]
    fn fixed_point_formatting() {
        let f = |value, decimals| Fixed { value, decimals }.to_string();
        assert_eq!(f(10_000_000, 6), "10.000000");
        assert_eq!(f(4_000_000, 8), "0.04000000");
        assert_eq!(f(30_000, 3), "30.000");
        assert_eq!(f(0, 3), "0.000");
        assert_eq!(f(7, 3), "0.007");
        assert_eq!(f(u64::MAX, 6), "18446744073709.551615");
    }

    #[test]
    fn every_envelope_parameter_has_a_unit_name() {
        use EnvelopeParameter as P;
        for p in [
            P::CathodicCurrent,
            P::AnodicCurrent,
            P::CathodicWidth,
            P::AnodicWidth,
            P::InterphaseGap,
            P::PulseRate,
            P::PulseCount,
            P::TrainDuration,
        ] {
            assert_ne!(p.name(), "");
        }
    }
}
