//! The firewall pipeline: framing → MAC → counter → physics → gate.

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::config::{ConfigError, ElectrodeTable, SafetyLimits};
use crate::crypto::{Psk, SessionKeys};
use crate::error::{Rejection, RejectionLayer};
use crate::gate::StimulationGate;
use crate::packet;
use crate::replay::ReplayGuard;
use crate::session::{ENCAPSULATION_KEY_LEN, PendingHandshake};
use crate::shannon::{self, PhaseAssessment};

/// Summary of an accepted command, for logging and telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepted {
    /// Counter of the accepted packet.
    pub counter: u64,
    /// Target electrode.
    pub electrode_id: u16,
    /// Physical figures of the worst phase.
    pub worst_phase: PhaseAssessment,
}

/// Running counters of the pipeline outcome.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FirewallStats {
    /// Commands delivered to the gate.
    pub accepted: u64,
    /// Rejected at framing.
    pub rejected_framing: u64,
    /// Rejected at authentication (including "no session").
    pub rejected_authentication: u64,
    /// Rejected as replays.
    pub rejected_replay: u64,
    /// Rejected by the physical limiter.
    pub rejected_safety: u64,
    /// Handshakes completed successfully.
    pub handshakes_completed: u64,
    /// Handshakes that failed (wrong PSK, tampered transcript, …).
    pub handshakes_failed: u64,
}

impl FirewallStats {
    /// Total number of rejected packets.
    #[must_use]
    pub const fn rejected(&self) -> u64 {
        self.rejected_framing + self.rejected_authentication + self.rejected_replay + self.rejected_safety
    }
}

struct ActiveSession {
    keys: SessionKeys,
    replay: ReplayGuard,
}

/// The Bio-Neural Firewall.
///
/// `N` is the electrode-table capacity; `G` drives the stimulator output stage.
pub struct Firewall<G: StimulationGate, const N: usize> {
    psk: Zeroizing<Psk>,
    limits: SafetyLimits,
    electrodes: ElectrodeTable<N>,
    gate: G,
    pending: Option<PendingHandshake>,
    session: Option<ActiveSession>,
    stats: FirewallStats,
}

impl<G: StimulationGate, const N: usize> Firewall<G, N> {
    /// Creates a firewall with no active session. The gate is forced open-circuit
    /// before anything else happens, even if the configuration is rejected.
    ///
    /// # Errors
    /// [`ConfigError::InvalidLimit`] if `limits` fails [`SafetyLimits::validate`].
    pub fn new(
        psk: Psk,
        limits: SafetyLimits,
        electrodes: ElectrodeTable<N>,
        mut gate: G,
    ) -> Result<Self, ConfigError> {
        gate.force_open_circuit();
        limits.validate()?;
        Ok(Self {
            psk: Zeroizing::new(psk),
            limits,
            electrodes,
            gate,
            pending: None,
            session: None,
            stats: FirewallStats::default(),
        })
    }

    /// Starts a handshake: generates an ephemeral ML-KEM-768 key pair from the TRNG
    /// and returns the encapsulation key to send to the host.
    ///
    /// The currently active session (if any) keeps working until a new handshake
    /// *completes*, so an unauthenticated `begin_handshake` cannot tear it down.
    pub fn begin_handshake<R: CryptoRng + ?Sized>(&mut self, trng: &mut R) -> [u8; ENCAPSULATION_KEY_LEN] {
        let (pending, ek) = PendingHandshake::generate(trng);
        self.pending = Some(pending);
        ek
    }

    /// Completes the handshake with the host's ciphertext and confirmation tag.
    /// On success the new session replaces the old one and the counter restarts.
    /// The pending key pair is consumed either way (one attempt per key pair).
    ///
    /// # Errors
    /// [`Rejection::HandshakeNotStarted`] or [`Rejection::HandshakeFailed`].
    pub fn complete_handshake(&mut self, ciphertext: &[u8], confirmation: &[u8]) -> Result<(), Rejection> {
        let pending = self.pending.take().ok_or(Rejection::HandshakeNotStarted)?;
        match pending.complete(&self.psk, ciphertext, confirmation) {
            Ok(keys) => {
                self.session = Some(ActiveSession {
                    keys,
                    replay: ReplayGuard::new(),
                });
                self.stats.handshakes_completed += 1;
                Ok(())
            }
            Err(e) => {
                self.stats.handshakes_failed += 1;
                Err(e)
            }
        }
    }

    /// Drops the active session and any pending handshake; all further commands
    /// are rejected and the gate is forced open-circuit.
    pub fn end_session(&mut self) {
        self.session = None;
        self.pending = None;
        self.gate.force_open_circuit();
    }

    /// Processes one packet. On any rejection the gate is forced open-circuit and
    /// nothing is delivered.
    ///
    /// # Errors
    /// The [`Rejection`] produced by the first failing stage.
    pub fn process(&mut self, packet: &[u8]) -> Result<Accepted, Rejection> {
        let result = self.run_pipeline(packet);
        match &result {
            Ok(_) => self.stats.accepted += 1,
            Err(rejection) => {
                self.gate.force_open_circuit();
                let counter = match rejection.layer() {
                    RejectionLayer::Framing => &mut self.stats.rejected_framing,
                    RejectionLayer::Authentication => &mut self.stats.rejected_authentication,
                    RejectionLayer::Freshness => &mut self.stats.rejected_replay,
                    RejectionLayer::Safety => &mut self.stats.rejected_safety,
                };
                *counter += 1;
            }
        }
        result
    }

    fn run_pipeline(&mut self, packet: &[u8]) -> Result<Accepted, Rejection> {
        // 1. Framing (length, version, opcode). No field is trusted yet.
        let frame = packet::split_frame(packet)?;

        // 2. Authentication (constant-time MAC check).
        let session = self.session.as_mut().ok_or(Rejection::NoActiveSession)?;
        if !session.keys.verify_command(frame.body, frame.tag) {
            return Err(Rejection::AuthenticationFailed);
        }

        // 3. Freshness. The counter is consumed as soon as an authentic packet is
        //    seen, so an authentic-but-unsafe command cannot be retried either.
        let counter = packet::decode_counter(frame.body);
        session.replay.accept(counter)?;

        // 4. Physics. Electrode geometry comes from firmware, never from the packet.
        let command = packet::decode_command(frame.body);
        let electrode = self
            .electrodes
            .get(command.electrode_id)
            .ok_or(Rejection::UnknownElectrode {
                electrode_id: command.electrode_id,
            })?;
        let validated = shannon::validate(&command, electrode, &self.limits)?;

        // 5. Only now may the output stage leave open-circuit.
        self.gate.deliver(&validated);
        Ok(Accepted {
            counter,
            electrode_id: command.electrode_id,
            worst_phase: *validated.worst_phase(),
        })
    }

    /// `true` when an authenticated session is active.
    #[must_use]
    pub const fn has_session(&self) -> bool {
        self.session.is_some()
    }

    /// `true` while a handshake has been started but not completed.
    #[must_use]
    pub const fn has_pending_handshake(&self) -> bool {
        self.pending.is_some()
    }

    /// Highest accepted counter of the active session.
    #[must_use]
    pub fn last_accepted_counter(&self) -> Option<u64> {
        self.session.as_ref().map(|s| s.replay.last_accepted())
    }

    /// Pipeline statistics.
    #[must_use]
    pub const fn stats(&self) -> &FirewallStats {
        &self.stats
    }

    /// Active safety limits.
    #[must_use]
    pub const fn limits(&self) -> &SafetyLimits {
        &self.limits
    }

    /// Provisioned electrode table.
    #[must_use]
    pub const fn electrodes(&self) -> &ElectrodeTable<N> {
        &self.electrodes
    }

    /// The output gate (e.g. for telemetry).
    #[must_use]
    pub const fn gate(&self) -> &G {
        &self.gate
    }
}
