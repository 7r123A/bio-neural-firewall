//! Safety limits and the provisioned electrode table.
//!
//! Electrode geometry is **firmware configuration**, never a command field: if the
//! host could declare the electrode area, an attacker could claim an arbitrarily
//! large area and push any charge through the density and Shannon checks.

use core::fmt;

/// Shannon `k` parameter, stored as a pre-computed fixed-point value of 10^k.
///
/// The limiter checks `D·Q <= 10^k` by integer cross-multiplication, so only the
/// constant `10^k × 10⁵` (rounded **down**, i.e. conservatively) is needed at run
/// time. Only vetted presets exist: `k` can never be set above 1.85.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShannonK {
    k_milli: u16,
    pow10_k_e5: u64,
}

impl ShannonK {
    /// k = 1.50 (very conservative). 10^1.50 = 31.6227766…
    pub const K_1_50: Self = Self {
        k_milli: 1_500,
        pow10_k_e5: 3_162_277,
    };
    /// k = 1.75 (project default). 10^1.75 = 56.2341325…
    pub const K_1_75: Self = Self {
        k_milli: 1_750,
        pow10_k_e5: 5_623_413,
    };
    /// k = 1.85 (upper bound of the Shannon 1992 tissue-damage boundary;
    /// do not exceed). 10^1.85 = 70.7945784…
    pub const K_1_85: Self = Self {
        k_milli: 1_850,
        pow10_k_e5: 7_079_457,
    };

    /// k × 1000.
    #[must_use]
    pub const fn k_milli(&self) -> u16 {
        self.k_milli
    }

    /// floor(10^k × 10⁵).
    #[must_use]
    pub const fn pow10_k_e5(&self) -> u64 {
        self.pow10_k_e5
    }

    /// 10^k × 10⁶ (same scale as `dq_micro` in [`crate::Rejection::ShannonLimitExceeded`]).
    #[must_use]
    pub const fn limit_dq_micro(&self) -> u64 {
        self.pow10_k_e5 * 10
    }
}

/// Loosest charge-balance tolerance [`SafetyLimits::validate`] accepts (10 %).
pub const MAX_CHARGE_BALANCE_TOLERANCE_PPM: u32 = 100_000;

/// Absolute physical limits applied to every authenticated command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafetyLimits {
    /// Shannon criterion parameter. A pulse is rejected when `log10(D) + log10(Q) > k`.
    pub shannon_k: ShannonK,
    /// Geometric charge-density cap per phase, in nC/cm² (30 000 = 30 µC/cm²,
    /// the reversible charge-injection limit commonly used for platinum).
    pub max_charge_density_nc_per_cm2: u64,
    /// Allowed |Qc − Qa| / max(Qc, Qa), in parts per million.
    pub charge_balance_tolerance_ppm: u32,
    /// Maximum amplitude of either phase, in µA.
    pub max_current_ua: u32,
    /// Maximum width of either phase, in µs.
    pub max_phase_width_us: u32,
    /// Maximum interphase gap, in µs.
    pub max_interphase_gap_us: u32,
    /// Maximum pulse repetition rate, in Hz.
    pub max_pulse_rate_hz: u16,
    /// Maximum number of pulses in one command.
    pub max_pulse_count: u16,
    /// Maximum duration of one command's pulse train, in µs.
    pub max_train_duration_us: u32,
}

impl SafetyLimits {
    /// Conservative defaults for platinum macro-electrodes (`ECoG` / `DBS` class).
    ///
    /// **Not** suitable as-is for intracortical micro-electrodes: see README,
    /// section "Choosing limits for your electrode".
    pub const PLATINUM_MACRO_DEFAULT: Self = Self {
        shannon_k: ShannonK::K_1_75,
        max_charge_density_nc_per_cm2: 30_000,
        charge_balance_tolerance_ppm: 10_000,
        max_current_ua: 10_000,
        max_phase_width_us: 1_000,
        max_interphase_gap_us: 200,
        max_pulse_rate_hz: 300,
        max_pulse_count: 1_000,
        max_train_duration_us: 1_000_000,
    };

    /// Rejects internally inconsistent limits (zero maxima, a non-charge-balancing
    /// tolerance). Called by [`crate::Firewall::new`].
    ///
    /// # Errors
    /// [`ConfigError::InvalidLimit`] naming the first offending field.
    pub const fn validate(&self) -> Result<(), ConfigError> {
        let field = if self.max_charge_density_nc_per_cm2 == 0 {
            "max_charge_density_nc_per_cm2"
        } else if self.charge_balance_tolerance_ppm > MAX_CHARGE_BALANCE_TOLERANCE_PPM {
            "charge_balance_tolerance_ppm"
        } else if self.max_current_ua == 0 {
            "max_current_ua"
        } else if self.max_phase_width_us == 0 {
            "max_phase_width_us"
        } else if self.max_pulse_rate_hz == 0 {
            "max_pulse_rate_hz"
        } else if self.max_pulse_count == 0 {
            "max_pulse_count"
        } else if self.max_train_duration_us == 0 {
            "max_train_duration_us"
        } else {
            return Ok(());
        };
        Err(ConfigError::InvalidLimit { field })
    }
}

impl Default for SafetyLimits {
    fn default() -> Self {
        Self::PLATINUM_MACRO_DEFAULT
    }
}

/// One provisioned stimulation contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElectrodeSpec {
    /// Electrode id used on the wire.
    pub id: u16,
    /// Geometric surface area in µm² (1 cm² = 100 000 000 µm²).
    pub geometric_area_um2: u64,
}

impl ElectrodeSpec {
    /// Number of µm² in one cm².
    pub const UM2_PER_CM2: u64 = 100_000_000;
}

/// Errors detected while validating the firmware configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// No electrode was provisioned.
    EmptyElectrodeTable,
    /// More electrodes than the table capacity `N`.
    TooManyElectrodes {
        /// Table capacity.
        capacity: usize,
    },
    /// An electrode was declared with zero area.
    ZeroArea {
        /// Offending electrode id.
        electrode_id: u16,
    },
    /// The same electrode id appears twice.
    DuplicateElectrode {
        /// Duplicated electrode id.
        electrode_id: u16,
    },
    /// A [`SafetyLimits`] field is inconsistent.
    InvalidLimit {
        /// Name of the offending field.
        field: &'static str,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyElectrodeTable => f.write_str("electrode table is empty"),
            Self::TooManyElectrodes { capacity } => {
                write!(f, "too many electrodes: table capacity is {capacity}")
            }
            Self::ZeroArea { electrode_id } => write!(f, "electrode {electrode_id} declared with zero area"),
            Self::DuplicateElectrode { electrode_id } => write!(f, "electrode {electrode_id} declared twice"),
            Self::InvalidLimit { field } => write!(f, "invalid safety limit: {field}"),
        }
    }
}

impl core::error::Error for ConfigError {}

/// Fixed-capacity, allocation-free electrode table.
#[derive(Debug, Clone)]
pub struct ElectrodeTable<const N: usize> {
    entries: [Option<ElectrodeSpec>; N],
}

impl<const N: usize> ElectrodeTable<N> {
    /// Validates and stores the electrode list.
    ///
    /// # Errors
    /// Empty list, more than `N` entries, zero area or duplicated id.
    pub fn try_new(specs: &[ElectrodeSpec]) -> Result<Self, ConfigError> {
        if specs.is_empty() {
            return Err(ConfigError::EmptyElectrodeTable);
        }
        if specs.len() > N {
            return Err(ConfigError::TooManyElectrodes { capacity: N });
        }
        let mut entries = [None; N];
        for (i, (slot, spec)) in entries.iter_mut().zip(specs).enumerate() {
            if spec.geometric_area_um2 == 0 {
                return Err(ConfigError::ZeroArea { electrode_id: spec.id });
            }
            if specs[i + 1..].iter().any(|other| other.id == spec.id) {
                return Err(ConfigError::DuplicateElectrode { electrode_id: spec.id });
            }
            *slot = Some(*spec);
        }
        Ok(Self { entries })
    }

    /// Looks up an electrode by id.
    #[must_use]
    pub fn get(&self, id: u16) -> Option<&ElectrodeSpec> {
        self.entries.iter().flatten().find(|e| e.id == id)
    }

    /// Number of provisioned electrodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    /// `true` when no electrode is provisioned (never the case after `try_new`).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: ElectrodeSpec = ElectrodeSpec {
        id: 1,
        geometric_area_um2: 10,
    };

    #[test]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn shannon_constants_match_floating_point_reference() {
        for k in [ShannonK::K_1_50, ShannonK::K_1_75, ShannonK::K_1_85] {
            let exact = 10f64.powf(f64::from(k.k_milli()) / 1000.0) * 1e5;
            assert_eq!(k.pow10_k_e5(), exact.floor() as u64, "k = {}", k.k_milli());
            assert_eq!(k.limit_dq_micro(), k.pow10_k_e5() * 10);
        }
        assert!(ShannonK::K_1_50.pow10_k_e5() < ShannonK::K_1_75.pow10_k_e5());
        assert!(ShannonK::K_1_75.pow10_k_e5() < ShannonK::K_1_85.pow10_k_e5());
    }

    #[test]
    fn default_limits_are_valid_and_documented_values() {
        let l = SafetyLimits::default();
        assert_eq!(l, SafetyLimits::PLATINUM_MACRO_DEFAULT);
        assert_eq!(l.validate(), Ok(()));
        assert_eq!(l.shannon_k, ShannonK::K_1_75);
        assert_eq!(l.max_charge_density_nc_per_cm2, 30_000);
        assert_eq!(l.charge_balance_tolerance_ppm, 10_000);
    }

    #[test]
    fn validate_names_each_inconsistent_field() {
        let d = SafetyLimits::default();
        let cases: [(SafetyLimits, &str); 7] = [
            (
                SafetyLimits {
                    max_charge_density_nc_per_cm2: 0,
                    ..d
                },
                "max_charge_density_nc_per_cm2",
            ),
            (
                SafetyLimits {
                    charge_balance_tolerance_ppm: MAX_CHARGE_BALANCE_TOLERANCE_PPM + 1,
                    ..d
                },
                "charge_balance_tolerance_ppm",
            ),
            (SafetyLimits { max_current_ua: 0, ..d }, "max_current_ua"),
            (
                SafetyLimits {
                    max_phase_width_us: 0,
                    ..d
                },
                "max_phase_width_us",
            ),
            (
                SafetyLimits {
                    max_pulse_rate_hz: 0,
                    ..d
                },
                "max_pulse_rate_hz",
            ),
            (
                SafetyLimits {
                    max_pulse_count: 0,
                    ..d
                },
                "max_pulse_count",
            ),
            (
                SafetyLimits {
                    max_train_duration_us: 0,
                    ..d
                },
                "max_train_duration_us",
            ),
        ];
        for (limits, field) in cases {
            assert_eq!(limits.validate(), Err(ConfigError::InvalidLimit { field }));
        }
        let loosest = SafetyLimits {
            charge_balance_tolerance_ppm: MAX_CHARGE_BALANCE_TOLERANCE_PPM,
            max_interphase_gap_us: 0,
            ..d
        };
        assert_eq!(loosest.validate(), Ok(()));
    }

    #[test]
    fn table_rejects_bad_configuration() {
        let zero = ElectrodeSpec {
            id: 2,
            geometric_area_um2: 0,
        };
        assert_eq!(
            ElectrodeTable::<2>::try_new(&[]).unwrap_err(),
            ConfigError::EmptyElectrodeTable
        );
        assert_eq!(
            ElectrodeTable::<2>::try_new(&[A, A]).unwrap_err(),
            ConfigError::DuplicateElectrode { electrode_id: 1 }
        );
        assert_eq!(
            ElectrodeTable::<2>::try_new(&[A, zero]).unwrap_err(),
            ConfigError::ZeroArea { electrode_id: 2 }
        );
        assert_eq!(
            ElectrodeTable::<1>::try_new(&[A, zero]).unwrap_err(),
            ConfigError::TooManyElectrodes { capacity: 1 }
        );
    }

    #[test]
    fn table_lookup() {
        let b = ElectrodeSpec {
            id: 7,
            geometric_area_um2: 99,
        };
        let t = ElectrodeTable::<4>::try_new(&[A, b]).unwrap();
        assert_eq!(t.len(), 2);
        assert!(!t.is_empty());
        assert_eq!(t.get(7), Some(&b));
        assert_eq!(t.get(1), Some(&A));
        assert!(t.get(9).is_none());
        // Exactly at capacity is fine.
        assert_eq!(ElectrodeTable::<2>::try_new(&[A, b]).unwrap().len(), 2);
    }

    #[test]
    fn config_errors_display() {
        for (e, needle) in [
            (ConfigError::EmptyElectrodeTable, "empty"),
            (ConfigError::TooManyElectrodes { capacity: 3 }, "capacity is 3"),
            (ConfigError::ZeroArea { electrode_id: 4 }, "electrode 4"),
            (ConfigError::DuplicateElectrode { electrode_id: 5 }, "twice"),
            (
                ConfigError::InvalidLimit {
                    field: "max_current_ua",
                },
                "max_current_ua",
            ),
        ] {
            assert!(e.to_string().contains(needle), "{e}");
        }
    }
}
