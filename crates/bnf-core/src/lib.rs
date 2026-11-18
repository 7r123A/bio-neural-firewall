//! # bnf-core — Bio-Neural Firewall safety kernel
//!
//! A `no_std`, allocation-free, `unsafe`-free kernel that sits between an external
//! BCI host and the stimulation front-end of a neural implant. Every stimulation
//! command must pass three independent gates before the output stage is allowed to
//! leave its open-circuit state:
//!
//! 1. **Authentication** — a BLAKE3 keyed MAC under a per-session key that was
//!    established with ML-KEM-768 (FIPS 203) and bound to a provisioning PSK.
//! 2. **Freshness** — a strictly monotonic 64-bit counter (replay protection).
//! 3. **Physics** — an integer-only charge limiter enforcing the Shannon (1992)
//!    criterion, a geometric charge-density cap, biphasic charge balance, pulse
//!    timing, train duration and an absolute parameter envelope.
//!
//! A rejected command never reaches [`StimulationGate::deliver`]; instead the gate
//! is forced into its open-circuit state. Nothing is "absorbed" or dissipated.
//!
//! ## Units (read this before touching the limiter)
//!
//! | Quantity        | Wire unit | Internal unit |
//! |-----------------|-----------|---------------|
//! | Current         | µA        | µA            |
//! | Phase width     | µs        | µs            |
//! | Charge          | —         | pC  (1 µA × 1 µs = 1 pC = 10⁻⁶ µC) |
//! | Electrode area  | —         | µm² (1 cm² = 10⁸ µm²) |
//! | Charge density  | —         | nC/cm² |
//!
//! All safety decisions are made with exact integer cross-multiplication in `u128`;
//! no floating point and no logarithms are evaluated on the decision path.
//!
//! ## Example
//!
//! ```
//! use bnf_core::{
//!     BiphasicPulse, ElectrodeSpec, ElectrodeTable, Firewall, HostSession, Rejection, SafetyLimits,
//!     StimulationCommand, StimulationGate, ValidatedPulse,
//! };
//! # use getrandom::SysRng;
//! # use rand_core::UnwrapErr;
//!
//! struct OutputStage;
//! impl StimulationGate for OutputStage {
//!     fn deliver(&mut self, _pulse: &ValidatedPulse) { /* close the output switch */ }
//!     fn force_open_circuit(&mut self) { /* open the output switch */ }
//! }
//!
//! let mut trng = UnwrapErr(SysRng);
//! let psk = [0x42; 32];
//! let electrodes = ElectrodeTable::<4>::try_new(&[ElectrodeSpec { id: 1, geometric_area_um2: 4_000_000 }])?;
//! let mut firewall = Firewall::new(psk, SafetyLimits::default(), electrodes, OutputStage)?;
//!
//! // Post-quantum handshake.
//! let ek = firewall.begin_handshake(&mut trng);
//! let (mut host, response) = HostSession::establish(&psk, &ek, &mut trng)?;
//! firewall.complete_handshake(&response.ciphertext, &response.confirmation)?;
//!
//! // A safe command is delivered…
//! let safe = StimulationCommand {
//!     electrode_id: 1,
//!     pulse: BiphasicPulse::symmetric(2_000, 200, 50),
//!     pulse_rate_hz: 100,
//!     pulse_count: 1,
//! };
//! assert_eq!(firewall.process(&host.sign(&safe)?)?.worst_phase.charge_pc, 400_000);
//!
//! // …a correctly signed but dangerous one is not.
//! let lethal = StimulationCommand { pulse: BiphasicPulse::symmetric(10_000, 1_000, 50), ..safe };
//! assert!(matches!(
//!     firewall.process(&host.sign(&lethal)?),
//!     Err(Rejection::ShannonLimitExceeded { .. })
//! ));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod config;
pub mod crypto;
pub mod entropy;
pub mod error;
pub mod firewall;
pub mod gate;
pub mod packet;
pub mod replay;
pub mod session;
pub mod shannon;

pub use config::{ConfigError, ElectrodeSpec, ElectrodeTable, SafetyLimits, ShannonK};
pub use crypto::{PSK_LEN, Psk};
pub use entropy::HardwareTrng;
pub use error::{EnvelopeParameter, REJECTION_CODES, Rejection, RejectionLayer, rejection_name};
pub use firewall::{Accepted, Firewall, FirewallStats};
pub use gate::StimulationGate;
pub use packet::{BiphasicPulse, PACKET_LEN, StimulationCommand};
pub use session::{CIPHERTEXT_LEN, CONFIRMATION_TAG_LEN, ENCAPSULATION_KEY_LEN, HandshakeResponse, HostSession};
pub use shannon::{PhaseAssessment, ValidatedPulse};
