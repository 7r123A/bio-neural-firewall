//! Physical safety limiter: Shannon criterion, charge density, charge balance,
//! pulse timing, train duration and absolute envelope.
//!
//! ## Equations and unit handling
//!
//! ```text
//! Q [pC]       = I [µA] × t [µs]                      (1 µA·µs = 1 pC = 10⁻⁶ µC)
//! A [cm²]      = A [µm²] × 10⁻⁸
//! D [µC/cm²]   = Q [µC] / A [cm²] = Q[pC] × 100 / A[µm²]
//! Shannon:       log10(D) = k − log10(Q)   ⇔   D·Q = 10^k
//!                reject if D·Q > 10^k, with D·Q [µC²/cm²] = Q[pC]² × 10⁻⁴ / A[µm²]
//! ```
//!
//! The decision `Q² × 10⁻⁴ / A > 10^k` is evaluated as the exact integer inequality
//!
//! ```text
//! Q[pC]² × 10  >  floor(10^k × 10⁵) × A[µm²]
//! ```
//!
//! in `u128`. `Q ≤ (2³² − 1)²` so `Q²` always fits in `u128`; the final `× 10`
//! uses checked arithmetic and an overflow is treated as a violation (fail closed).
//! Rounding `10^k` down makes the check marginally stricter, never looser.

use crate::config::{ElectrodeSpec, SafetyLimits};
use crate::error::{EnvelopeParameter, Rejection};
use crate::packet::StimulationCommand;

/// Picocoulombs per microcoulomb.
pub const PC_PER_UC: u64 = 1_000_000;

/// Microseconds per second.
const US_PER_S: u64 = 1_000_000;

/// Charge of one phase in pC (`1 µA × 1 µs = 1 pC`).
#[must_use]
pub fn phase_charge_pc(current_ua: u32, width_us: u32) -> u64 {
    u64::from(current_ua) * u64::from(width_us)
}

/// Derived physical quantities of one phase on one electrode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhaseAssessment {
    /// Phase charge (pC).
    pub charge_pc: u64,
    /// Geometric charge density (nC/cm²), rounded down.
    pub density_nc_per_cm2: u64,
    /// D·Q × 10⁶ in µC²/cm², rounded down (log10 of `dq_micro / 10⁶` is the pulse's k).
    pub dq_micro: u64,
}

/// Computes density and D·Q for a phase charge on an electrode of area `area_um2`
/// (reporting only; decisions use [`exceeds_shannon`] and [`exceeds_density`]).
#[must_use]
pub fn assess_phase(charge_pc: u64, area_um2: u64) -> PhaseAssessment {
    let q = u128::from(charge_pc);
    let a = u128::from(area_um2.max(1));
    // D [nC/cm²] = Q[pC] × 10⁵ / A[µm²]
    let density = q.saturating_mul(100_000) / a;
    // D·Q × 10⁶ = Q[pC]² × 100 / A[µm²]
    let dq = (q * q).saturating_mul(100) / a;
    PhaseAssessment {
        charge_pc,
        density_nc_per_cm2: u64::try_from(density).unwrap_or(u64::MAX),
        dq_micro: u64::try_from(dq).unwrap_or(u64::MAX),
    }
}

/// `true` if `D·Q > 10^k` (exact integer comparison, fail-closed on overflow).
#[must_use]
pub fn exceeds_shannon(charge_pc: u64, area_um2: u64, limits: &SafetyLimits) -> bool {
    let q = u128::from(charge_pc);
    let lhs = (q * q).checked_mul(10);
    let rhs = u128::from(limits.shannon_k.pow10_k_e5()).checked_mul(u128::from(area_um2));
    match (lhs, rhs) {
        (Some(l), Some(r)) => l > r,
        _ => true,
    }
}

/// `true` if `D > D_max`, i.e. `Q[pC] × 10⁵ > D_max[nC/cm²] × A[µm²]` (exact).
/// Both products of two `u64` values fit in `u128`, so no overflow is possible.
#[must_use]
pub fn exceeds_density(charge_pc: u64, area_um2: u64, limits: &SafetyLimits) -> bool {
    u128::from(charge_pc) * 100_000 > u128::from(limits.max_charge_density_nc_per_cm2) * u128::from(area_um2)
}

/// Exact train duration `ceil(pulse_count × 10⁶ / pulse_rate)` in µs (`rate ≥ 1`).
#[must_use]
pub fn train_duration_us(pulse_count: u16, pulse_rate_hz: u16) -> u64 {
    (u64::from(pulse_count) * US_PER_S).div_ceil(u64::from(pulse_rate_hz.max(1)))
}

/// A command that passed every physical check. Only this module can construct it,
/// so a [`crate::StimulationGate`] can never be handed an unchecked pulse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedPulse {
    command: StimulationCommand,
    electrode: ElectrodeSpec,
    worst_phase: PhaseAssessment,
}

impl ValidatedPulse {
    /// The accepted command.
    #[must_use]
    pub const fn command(&self) -> &StimulationCommand {
        &self.command
    }

    /// The electrode the command targets (from the provisioned table).
    #[must_use]
    pub const fn electrode(&self) -> &ElectrodeSpec {
        &self.electrode
    }

    /// Physical figures of the phase with the larger charge.
    #[must_use]
    pub const fn worst_phase(&self) -> &PhaseAssessment {
        &self.worst_phase
    }
}

const fn envelope(parameter: EnvelopeParameter, value: u32, min: u32, max: u32) -> Result<(), Rejection> {
    if value < min || value > max {
        Err(Rejection::EnvelopeExceeded {
            parameter,
            value,
            limit: max,
        })
    } else {
        Ok(())
    }
}

fn saturate_u32(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

fn check_envelope(cmd: &StimulationCommand, limits: &SafetyLimits) -> Result<(), Rejection> {
    use EnvelopeParameter as P;
    let p = &cmd.pulse;
    // Zero amplitude/width is allowed here and diagnosed below as a monophasic
    // pulse, which is the more precise reason.
    envelope(P::CathodicCurrent, p.cathodic_current_ua, 0, limits.max_current_ua)?;
    envelope(P::AnodicCurrent, p.anodic_current_ua, 0, limits.max_current_ua)?;
    envelope(P::CathodicWidth, p.cathodic_width_us, 0, limits.max_phase_width_us)?;
    envelope(P::AnodicWidth, p.anodic_width_us, 0, limits.max_phase_width_us)?;
    envelope(P::InterphaseGap, p.interphase_gap_us, 0, limits.max_interphase_gap_us)?;
    envelope(
        P::PulseRate,
        u32::from(cmd.pulse_rate_hz),
        1,
        u32::from(limits.max_pulse_rate_hz),
    )?;
    envelope(
        P::PulseCount,
        u32::from(cmd.pulse_count),
        1,
        u32::from(limits.max_pulse_count),
    )?;
    envelope(
        P::TrainDuration,
        saturate_u32(train_duration_us(cmd.pulse_count, cmd.pulse_rate_hz)),
        0,
        limits.max_train_duration_us,
    )
}

/// Runs every physical check, cheapest first. The first violation is returned.
///
/// Order: envelope → biphasic → timing → charge balance → Shannon → density.
///
/// # Errors
/// The first violated [`Rejection`] of the safety layer (codes 402–407).
pub fn validate(
    cmd: &StimulationCommand,
    electrode: &ElectrodeSpec,
    limits: &SafetyLimits,
) -> Result<ValidatedPulse, Rejection> {
    let p = &cmd.pulse;

    // 1. Absolute envelope (incl. train duration).
    check_envelope(cmd, limits)?;

    // 2. Biphasic requirement: a phase with zero charge means net DC injection.
    let qc = phase_charge_pc(p.cathodic_current_ua, p.cathodic_width_us);
    let qa = phase_charge_pc(p.anodic_current_ua, p.anodic_width_us);
    if qc == 0 || qa == 0 {
        return Err(Rejection::MonophasicPulse);
    }

    // 3. Timing: the whole biphasic pulse must fit inside one period (u32 inputs,
    //    so the u64 sum cannot overflow).
    let active = u64::from(p.cathodic_width_us) + u64::from(p.interphase_gap_us) + u64::from(p.anodic_width_us);
    let period = US_PER_S / u64::from(cmd.pulse_rate_hz);
    if active >= period {
        return Err(Rejection::PulseTimingInvalid {
            active_us: saturate_u32(active),
            period_us: saturate_u32(period),
        });
    }

    // 4. Charge balance: |Qc − Qa| / max(Qc, Qa) <= tolerance.
    let q_max = qc.max(qa);
    let mismatch = u128::from(qc.abs_diff(qa)) * 1_000_000;
    if mismatch > u128::from(limits.charge_balance_tolerance_ppm) * u128::from(q_max) {
        return Err(Rejection::ChargeImbalance {
            cathodic_pc: qc,
            anodic_pc: qa,
            tolerance_ppm: limits.charge_balance_tolerance_ppm,
        });
    }

    // 5 + 6. Shannon criterion and density cap on the worst (largest-charge) phase.
    let area = electrode.geometric_area_um2;
    let worst = assess_phase(q_max, area);
    if exceeds_shannon(q_max, area, limits) {
        return Err(Rejection::ShannonLimitExceeded {
            charge_pc: q_max,
            area_um2: area,
            dq_micro: worst.dq_micro,
            limit_dq_micro: limits.shannon_k.limit_dq_micro(),
        });
    }
    if exceeds_density(q_max, area, limits) {
        return Err(Rejection::ChargeDensityExceeded {
            charge_pc: q_max,
            area_um2: area,
            density_nc_per_cm2: worst.density_nc_per_cm2,
            limit_nc_per_cm2: limits.max_charge_density_nc_per_cm2,
        });
    }

    Ok(ValidatedPulse {
        command: *cmd,
        electrode: *electrode,
        worst_phase: worst,
    })
}

#[cfg(test)]
#[allow(clippy::cast_precision_loss)]
mod tests {
    use super::*;
    use crate::config::ShannonK;
    use crate::packet::BiphasicPulse;
    use proptest::prelude::*;

    /// 0.04 cm² platinum `ECoG` contact (≈ 2.26 mm diameter disc).
    const ECOG: ElectrodeSpec = ElectrodeSpec {
        id: 1,
        geometric_area_um2: 4_000_000,
    };
    const LIMITS: SafetyLimits = SafetyLimits::PLATINUM_MACRO_DEFAULT;

    const fn cmd(pulse: BiphasicPulse) -> StimulationCommand {
        StimulationCommand {
            electrode_id: 1,
            pulse,
            pulse_rate_hz: 100,
            pulse_count: 1,
        }
    }

    fn k_of(a: &PhaseAssessment) -> f64 {
        (a.dq_micro as f64 / 1e6).log10()
    }

    #[test]
    fn unit_conversion_is_exact() {
        // 1 µA × 1 µs = 1 pC
        assert_eq!(phase_charge_pc(1, 1), 1);
        // 2 mA × 200 µs = 0.4 µC = 400 000 pC
        assert_eq!(phase_charge_pc(2_000, 200), 400_000);
        assert_eq!(
            phase_charge_pc(u32::MAX, u32::MAX),
            u64::from(u32::MAX) * u64::from(u32::MAX)
        );
        // On 0.04 cm²: D = 0.4 / 0.04 = 10 µC/cm², D·Q = 4 µC²/cm², k = log10(4) = 0.602
        let a = assess_phase(400_000, ECOG.geometric_area_um2);
        assert_eq!(a.density_nc_per_cm2, 10_000);
        assert_eq!(a.dq_micro, 4_000_000);
        assert!((k_of(&a) - 4f64.log10()).abs() < 1e-9);
    }

    #[test]
    fn assess_phase_saturates_instead_of_overflowing() {
        let a = assess_phase(u64::MAX, 1);
        assert_eq!(a.density_nc_per_cm2, u64::MAX);
        assert_eq!(a.dq_micro, u64::MAX);
        assert_eq!(assess_phase(0, 5).dq_micro, 0);
    }

    #[test]
    fn nominal_pulse_passes() {
        let v = validate(&cmd(BiphasicPulse::symmetric(2_000, 200, 50)), &ECOG, &LIMITS).unwrap();
        assert_eq!(v.worst_phase().charge_pc, 400_000);
        assert_eq!(v.electrode(), &ECOG);
        assert_eq!(v.command().pulse.cathodic_current_ua, 2_000);
    }

    #[test]
    fn lethal_pulse_violates_shannon() {
        // 10 mA × 1000 µs = 10 µC → D = 250 µC/cm², D·Q = 2500, k = 3.40 > 1.75
        let err = validate(&cmd(BiphasicPulse::symmetric(10_000, 1_000, 50)), &ECOG, &LIMITS).unwrap_err();
        assert_eq!(
            err,
            Rejection::ShannonLimitExceeded {
                charge_pc: 10_000_000,
                area_um2: 4_000_000,
                dq_micro: 2_500_000_000,
                limit_dq_micro: 56_234_130,
            }
        );
    }

    #[test]
    fn density_cap_binds_below_shannon_on_small_electrodes() {
        // 2.6 mA × 500 µs = 1.3 µC → D = 32.5 µC/cm² > 30, but k = log10(42.25) = 1.63 < 1.75
        let err = validate(&cmd(BiphasicPulse::symmetric(2_600, 500, 50)), &ECOG, &LIMITS).unwrap_err();
        assert!(matches!(
            err,
            Rejection::ChargeDensityExceeded {
                density_nc_per_cm2: 32_500,
                ..
            }
        ));
    }

    #[test]
    fn density_boundary_is_exact() {
        // Q_max = 30 µC/cm² × 0.04 cm² = 1.2 µC = 1 200 000 pC exactly.
        assert!(!exceeds_density(1_200_000, ECOG.geometric_area_um2, &LIMITS));
        assert!(exceeds_density(1_200_001, ECOG.geometric_area_um2, &LIMITS));
        assert!(validate(&cmd(BiphasicPulse::symmetric(2_400, 500, 50)), &ECOG, &LIMITS).is_ok());
        assert!(validate(&cmd(BiphasicPulse::symmetric(2_401, 500, 50)), &ECOG, &LIMITS).is_err());
    }

    #[test]
    fn shannon_boundary_is_exact() {
        // Large electrode (0.25 cm²) where Shannon binds before the density cap.
        // Q_max = sqrt(10^1.75 × A) = sqrt(56.23413 × 0.25) µC = 3.74947096 µC
        // → 3 749 470 pC is the largest accepted integer charge.
        let area = 25_000_000;
        assert!(!exceeds_shannon(3_749_470, area, &LIMITS));
        assert!(exceeds_shannon(3_749_471, area, &LIMITS));
        // Stricter k must reject what k = 1.75 accepts; looser k accepts more.
        let strict = SafetyLimits {
            shannon_k: ShannonK::K_1_50,
            ..LIMITS
        };
        let loose = SafetyLimits {
            shannon_k: ShannonK::K_1_85,
            ..LIMITS
        };
        assert!(exceeds_shannon(3_749_470, area, &strict));
        assert!(!exceeds_shannon(3_749_471, area, &loose));
    }

    #[test]
    fn crossover_area_between_density_and_shannon() {
        // A* = 10^k / D_max² = 56.234 / 900 = 0.0625 cm². Just below A*, density
        // binds first; just above, Shannon binds first.
        let at = |area: u64, q: u64| (exceeds_shannon(q, area, &LIMITS), exceeds_density(q, area, &LIMITS));
        // A = 0.05 cm²: density limit 1.5 µC, Shannon limit 1.677 µC
        assert_eq!(at(5_000_000, 1_600_000), (false, true));
        // A = 0.08 cm²: density limit 2.4 µC, Shannon limit 2.121 µC
        assert_eq!(at(8_000_000, 2_200_000), (true, false));
    }

    #[test]
    fn monophasic_and_imbalanced_pulses_are_rejected() {
        let base = BiphasicPulse::symmetric(1_000, 100, 0);
        for mono in [
            BiphasicPulse {
                anodic_current_ua: 0,
                ..base
            },
            BiphasicPulse {
                cathodic_current_ua: 0,
                ..base
            },
            BiphasicPulse {
                anodic_width_us: 0,
                ..base
            },
            BiphasicPulse {
                cathodic_width_us: 0,
                ..base
            },
        ] {
            assert_eq!(
                validate(&cmd(mono), &ECOG, &LIMITS).unwrap_err(),
                Rejection::MonophasicPulse
            );
        }

        // 2 % mismatch > 1 % tolerance
        let skew = BiphasicPulse {
            anodic_current_ua: 980,
            ..base
        };
        assert_eq!(
            validate(&cmd(skew), &ECOG, &LIMITS).unwrap_err(),
            Rejection::ChargeImbalance {
                cathodic_pc: 100_000,
                anodic_pc: 98_000,
                tolerance_ppm: 10_000
            }
        );
        // exactly 1 % mismatch is within tolerance
        let edge = BiphasicPulse {
            anodic_current_ua: 990,
            ..base
        };
        assert!(validate(&cmd(edge), &ECOG, &LIMITS).is_ok());

        // Asymmetric but charge-balanced (1 mA × 100 µs vs 0.25 mA × 400 µs) is fine.
        let asym = BiphasicPulse {
            cathodic_current_ua: 1_000,
            cathodic_width_us: 100,
            interphase_gap_us: 50,
            anodic_current_ua: 250,
            anodic_width_us: 400,
        };
        assert!(validate(&cmd(asym), &ECOG, &LIMITS).is_ok());
    }

    #[test]
    fn every_envelope_parameter_is_enforced() {
        use EnvelopeParameter as P;
        let ok = cmd(BiphasicPulse::symmetric(1_000, 100, 10));
        let mut cases: [(StimulationCommand, P); 10] = [(ok, P::CathodicCurrent); 10];
        cases[0].0.pulse.cathodic_current_ua = 10_001;
        cases[1] = (ok, P::AnodicCurrent);
        cases[1].0.pulse.anodic_current_ua = 10_001;
        cases[2] = (ok, P::CathodicWidth);
        cases[2].0.pulse.cathodic_width_us = 1_001;
        cases[3] = (ok, P::AnodicWidth);
        cases[3].0.pulse.anodic_width_us = 1_001;
        cases[4] = (ok, P::InterphaseGap);
        cases[4].0.pulse.interphase_gap_us = 201;
        cases[5] = (ok, P::PulseRate);
        cases[5].0.pulse_rate_hz = 0;
        cases[6] = (ok, P::PulseRate);
        cases[6].0.pulse_rate_hz = 301;
        cases[7] = (ok, P::PulseCount);
        cases[7].0.pulse_count = 0;
        cases[8] = (ok, P::PulseCount);
        cases[8].0.pulse_count = 1_001;
        cases[9] = (ok, P::TrainDuration);
        cases[9].0.pulse_count = 101; // 101 pulses at 100 Hz = 1.01 s > 1 s
        for (c, param) in cases {
            match validate(&c, &ECOG, &LIMITS) {
                Err(Rejection::EnvelopeExceeded { parameter, .. }) => assert_eq!(parameter, param, "{c:?}"),
                other => panic!("{param:?}: unexpected {other:?}"),
            }
        }
        // 100 pulses at 100 Hz is exactly 1 s: allowed.
        let mut edge = ok;
        edge.pulse_count = 100;
        assert!(validate(&edge, &ECOG, &LIMITS).is_ok());
    }

    #[test]
    fn train_duration_is_rounded_up() {
        assert_eq!(train_duration_us(1, 100), 10_000);
        assert_eq!(train_duration_us(1, 300), 3_334); // 3333.33… rounded up
        assert_eq!(train_duration_us(1_000, 1), 1_000_000_000);
        assert_eq!(train_duration_us(u16::MAX, 1), u64::from(u16::MAX) * 1_000_000);
        assert_eq!(train_duration_us(5, 0), 5_000_000); // rate 0 treated as 1 (rejected earlier)
    }

    #[test]
    fn timing_is_enforced_when_limits_allow_fast_rates() {
        let fast_limits = SafetyLimits {
            max_pulse_rate_hz: 1_000,
            ..LIMITS
        };
        let mut c = cmd(BiphasicPulse::symmetric(1_000, 400, 100));
        c.pulse_rate_hz = 1_000; // period 1000 µs, active 900 µs: fits
        assert!(validate(&c, &ECOG, &fast_limits).is_ok());
        c.pulse.interphase_gap_us = 200; // active 1000 µs == period: does not fit
        assert_eq!(
            validate(&c, &ECOG, &fast_limits).unwrap_err(),
            Rejection::PulseTimingInvalid {
                active_us: 1_000,
                period_us: 1_000
            }
        );
    }

    #[test]
    fn overflow_fails_closed() {
        // Q² fits in u128 but Q² × 10 does not: must be treated as a violation.
        assert!(exceeds_shannon(u64::MAX, u64::MAX, &LIMITS));
        assert!(exceeds_density(u64::MAX, 1, &LIMITS));
        assert!(!exceeds_density(0, 1, &LIMITS));
    }

    // ------------------------------------------------------------ properties

    /// Floating-point reference model of the two charge criteria.
    fn reference(charge_pc: u64, area_um2: u64) -> (f64, f64) {
        let q_uc = charge_pc as f64 / 1e6;
        let a_cm2 = area_um2 as f64 / 1e8;
        let d = q_uc / a_cm2;
        (d * q_uc, d)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4_000))]

        /// The integer Shannon decision agrees with a float reference everywhere
        /// except within 1 ppm of the boundary (where float rounding is ambiguous).
        #[test]
        fn prop_shannon_matches_float_reference(i in 0u32..=20_000, t in 0u32..=2_000, area in 1u64..=1_000_000_000) {
            let q = phase_charge_pc(i, t);
            let (dq, _) = reference(q, area);
            let limit = 10f64.powf(1.75);
            prop_assume!((dq / limit - 1.0).abs() > 1e-6);
            prop_assert_eq!(exceeds_shannon(q, area, &LIMITS), dq > limit);
        }

        #[test]
        fn prop_density_matches_float_reference(i in 0u32..=20_000, t in 0u32..=2_000, area in 1u64..=1_000_000_000) {
            let q = phase_charge_pc(i, t);
            let (_, d) = reference(q, area);
            prop_assume!((d / 30.0 - 1.0).abs() > 1e-9);
            prop_assert_eq!(exceeds_density(q, area, &LIMITS), d > 30.0);
        }

        /// Soundness: whatever `validate` accepts satisfies every physical rule.
        #[test]
        fn prop_accepted_pulses_satisfy_every_rule(
            ci in 0u32..=12_000, cw in 0u32..=1_200, gap in 0u32..=250,
            ai in 0u32..=12_000, aw in 0u32..=1_200,
            rate in 0u16..=400, count in 0u16..=1_200,
            area in 1_000u64..=100_000_000,
        ) {
            let c = StimulationCommand {
                electrode_id: 1,
                pulse: BiphasicPulse {
                    cathodic_current_ua: ci, cathodic_width_us: cw, interphase_gap_us: gap,
                    anodic_current_ua: ai, anodic_width_us: aw,
                },
                pulse_rate_hz: rate,
                pulse_count: count,
            };
            let e = ElectrodeSpec { id: 1, geometric_area_um2: area };
            if let Ok(v) = validate(&c, &e, &LIMITS) {
                let qc = phase_charge_pc(ci, cw);
                let qa = phase_charge_pc(ai, aw);
                let q = qc.max(qa);
                prop_assert!(qc > 0 && qa > 0);
                prop_assert!(ci <= 10_000 && ai <= 10_000 && cw <= 1_000 && aw <= 1_000 && gap <= 200);
                prop_assert!((1..=300).contains(&rate) && (1..=1_000).contains(&count));
                // train duration count / rate ≤ 1 s  ⇔  count ≤ rate
                prop_assert!(count <= rate);
                prop_assert!(u64::from(cw + gap + aw) < 1_000_000 / u64::from(rate));
                prop_assert!(qc.abs_diff(qa) * 100 <= q);
                let (dq, d) = reference(q, area);
                prop_assert!(dq <= 10f64.powf(1.75) * (1.0 + 1e-9));
                prop_assert!(d <= 30.0 * (1.0 + 1e-12));
                prop_assert_eq!(v.worst_phase().charge_pc, q);
            }
        }

        /// The limiter never panics, whatever the input.
        #[test]
        fn prop_validate_is_total(raw in any::<[u32; 5]>(), rate in any::<u16>(), count in any::<u16>(), area in 1u64..) {
            let c = StimulationCommand {
                electrode_id: 0,
                pulse: BiphasicPulse {
                    cathodic_current_ua: raw[0], cathodic_width_us: raw[1], interphase_gap_us: raw[2],
                    anodic_current_ua: raw[3], anodic_width_us: raw[4],
                },
                pulse_rate_hz: rate,
                pulse_count: count,
            };
            let _ = validate(&c, &ElectrodeSpec { id: 0, geometric_area_um2: area }, &LIMITS);
        }
    }
}
