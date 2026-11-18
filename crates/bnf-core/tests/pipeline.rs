//! End-to-end tests of the firewall pipeline: handshake, authentication,
//! replay protection, physical limiter, statistics and open-circuit behaviour.

use bnf_core::packet::{BODY_LEN, PACKET_LEN};
use bnf_core::{
    BiphasicPulse, ConfigError, ElectrodeSpec, ElectrodeTable, Firewall, HostSession, Rejection, SafetyLimits,
    StimulationCommand, StimulationGate, ValidatedPulse,
};
use getrandom::SysRng;
use proptest::prelude::*;
use rand_core::UnwrapErr;

#[derive(Default)]
struct RecordingGate {
    delivered: Vec<StimulationCommand>,
    open_circuit_calls: usize,
}

impl StimulationGate for RecordingGate {
    fn deliver(&mut self, pulse: &ValidatedPulse) {
        self.delivered.push(*pulse.command());
    }
    fn force_open_circuit(&mut self) {
        self.open_circuit_calls += 1;
    }
}

/// Gate that only counts open-circuit calls and must never deliver.
struct Probe<'a>(&'a mut usize);

impl StimulationGate for Probe<'_> {
    fn deliver(&mut self, _: &ValidatedPulse) {
        unreachable!("nothing may be delivered");
    }
    fn force_open_circuit(&mut self) {
        *self.0 += 1;
    }
}

type Fw = Firewall<RecordingGate, 8>;

const PSK: [u8; 32] = [0x42; 32];
const ECOG: ElectrodeSpec = ElectrodeSpec {
    id: 7,
    geometric_area_um2: 4_000_000,
};
const NOMINAL: StimulationCommand = StimulationCommand {
    electrode_id: 7,
    pulse: BiphasicPulse::symmetric(2_000, 200, 50),
    pulse_rate_hz: 100,
    pulse_count: 1,
};

fn trng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

fn firewall() -> Fw {
    Firewall::new(
        PSK,
        SafetyLimits::default(),
        ElectrodeTable::try_new(&[ECOG]).unwrap(),
        RecordingGate::default(),
    )
    .unwrap()
}

fn handshake(fw: &mut Fw) -> HostSession {
    let ek = fw.begin_handshake(&mut trng());
    let (host, resp) = HostSession::establish(&PSK, &ek, &mut trng()).unwrap();
    fw.complete_handshake(&resp.ciphertext, &resp.confirmation).unwrap();
    host
}

fn setup() -> (Fw, HostSession) {
    let mut fw = firewall();
    let host = handshake(&mut fw);
    (fw, host)
}

fn sign(host: &mut HostSession, cmd: &StimulationCommand) -> [u8; PACKET_LEN] {
    host.sign(cmd).unwrap()
}

// ------------------------------------------------------------- construction

#[test]
fn construction_forces_open_circuit_and_validates_limits() {
    let fw = firewall();
    assert_eq!(fw.gate().open_circuit_calls, 1);
    assert!(!fw.has_session());
    assert!(!fw.has_pending_handshake());
    assert_eq!(fw.last_accepted_counter(), None);
    assert_eq!(fw.limits(), &SafetyLimits::default());
    assert_eq!(fw.electrodes().get(7), Some(&ECOG));

    let bad = SafetyLimits {
        max_current_ua: 0,
        ..SafetyLimits::default()
    };
    let mut gate_calls = 0;
    let result = Firewall::<_, 8>::new(
        PSK,
        bad,
        ElectrodeTable::try_new(&[ECOG]).unwrap(),
        Probe(&mut gate_calls),
    );
    assert_eq!(
        result.err(),
        Some(ConfigError::InvalidLimit {
            field: "max_current_ua"
        })
    );
    assert_eq!(gate_calls, 1, "gate must be opened even when configuration is rejected");
}

// ---------------------------------------------------------------- handshake

#[test]
fn nominal_command_is_delivered() {
    let (mut fw, mut host) = setup();
    let ok = fw.process(&sign(&mut host, &NOMINAL)).unwrap();
    assert_eq!(ok.counter, 1);
    assert_eq!(ok.electrode_id, 7);
    assert_eq!(ok.worst_phase.charge_pc, 400_000);
    assert_eq!(ok.worst_phase.density_nc_per_cm2, 10_000);
    assert_eq!(ok.worst_phase.dq_micro, 4_000_000);
    assert_eq!(fw.gate().delivered, vec![NOMINAL]);
    assert_eq!(fw.stats().accepted, 1);
    assert_eq!(fw.stats().handshakes_completed, 1);
    assert_eq!(fw.last_accepted_counter(), Some(1));
}

#[test]
fn commands_before_handshake_are_dropped() {
    let mut fw = firewall();
    let (_, mut other_host) = setup();
    assert_eq!(
        fw.process(&sign(&mut other_host, &NOMINAL)).unwrap_err(),
        Rejection::NoActiveSession
    );
    assert_eq!(fw.gate().delivered, []);
}

#[test]
fn complete_without_begin_is_rejected() {
    let mut fw = firewall();
    assert_eq!(
        fw.complete_handshake(&[0; 1088], &[0; 32]).unwrap_err(),
        Rejection::HandshakeNotStarted
    );
}

#[test]
fn rogue_host_with_wrong_psk_fails_handshake() {
    let mut fw = firewall();
    let ek = fw.begin_handshake(&mut trng());
    assert!(fw.has_pending_handshake());
    let (mut rogue, resp) = HostSession::establish(&[0x13; 32], &ek, &mut trng()).unwrap();
    assert_eq!(
        fw.complete_handshake(&resp.ciphertext, &resp.confirmation).unwrap_err(),
        Rejection::HandshakeFailed
    );
    assert!(!fw.has_session());
    assert!(!fw.has_pending_handshake());
    assert_eq!(fw.stats().handshakes_failed, 1);
    // The key pair is single-use.
    assert_eq!(
        fw.complete_handshake(&resp.ciphertext, &resp.confirmation).unwrap_err(),
        Rejection::HandshakeNotStarted
    );
    // And the rogue host's commands go nowhere.
    assert_eq!(
        fw.process(&sign(&mut rogue, &NOMINAL)).unwrap_err(),
        Rejection::NoActiveSession
    );
}

#[test]
fn tampered_handshake_messages_fail() {
    for byte in [0usize, 100, 1087] {
        let mut fw = firewall();
        let ek = fw.begin_handshake(&mut trng());
        let (_, mut resp) = HostSession::establish(&PSK, &ek, &mut trng()).unwrap();
        resp.ciphertext[byte] ^= 0x01;
        assert_eq!(
            fw.complete_handshake(&resp.ciphertext, &resp.confirmation).unwrap_err(),
            Rejection::HandshakeFailed,
            "ciphertext byte {byte}"
        );
    }
    let mut fw = firewall();
    let ek = fw.begin_handshake(&mut trng());
    let (_, mut resp) = HostSession::establish(&PSK, &ek, &mut trng()).unwrap();
    resp.confirmation[0] ^= 0x80;
    assert_eq!(
        fw.complete_handshake(&resp.ciphertext, &resp.confirmation).unwrap_err(),
        Rejection::HandshakeFailed
    );
}

#[test]
fn response_for_a_different_key_pair_fails() {
    let mut fw = firewall();
    let ek_old = fw.begin_handshake(&mut trng());
    let _ek_new = fw.begin_handshake(&mut trng()); // replaces the pending key pair
    let (_, resp) = HostSession::establish(&PSK, &ek_old, &mut trng()).unwrap();
    assert_eq!(
        fw.complete_handshake(&resp.ciphertext, &resp.confirmation).unwrap_err(),
        Rejection::HandshakeFailed
    );
}

#[test]
fn begin_handshake_does_not_tear_down_the_active_session() {
    let (mut fw, mut host) = setup();
    fw.process(&sign(&mut host, &NOMINAL)).unwrap();
    // An attacker starts (and fails) a handshake…
    let ek = fw.begin_handshake(&mut trng());
    let (_, resp) = HostSession::establish(&[0; 32], &ek, &mut trng()).unwrap();
    assert!(fw.complete_handshake(&resp.ciphertext, &resp.confirmation).is_err());
    // …but the legitimate session keeps working.
    assert!(fw.has_session());
    fw.process(&sign(&mut host, &NOMINAL)).unwrap();
    assert_eq!(fw.gate().delivered.len(), 2);
}

#[test]
fn rekeying_restarts_the_counter_and_invalidates_old_packets() {
    let (mut fw, mut host) = setup();
    let old = sign(&mut host, &NOMINAL);
    fw.process(&old).unwrap();
    for _ in 0..10 {
        fw.process(&sign(&mut host, &NOMINAL)).unwrap();
    }
    assert_eq!(fw.last_accepted_counter(), Some(11));

    let mut host2 = handshake(&mut fw);
    assert_eq!(fw.last_accepted_counter(), Some(0));
    assert_eq!(fw.process(&old).unwrap_err(), Rejection::AuthenticationFailed);
    assert_eq!(
        fw.process(&sign(&mut host, &NOMINAL)).unwrap_err(),
        Rejection::AuthenticationFailed
    );
    assert_eq!(fw.process(&sign(&mut host2, &NOMINAL)).unwrap().counter, 1);
    assert_eq!(fw.stats().handshakes_completed, 2);
}

#[test]
fn end_session_drops_everything() {
    let (mut fw, mut host) = setup();
    let pending_ek = fw.begin_handshake(&mut trng());
    let before = fw.gate().open_circuit_calls;
    fw.end_session();
    assert!(!fw.has_session());
    assert!(!fw.has_pending_handshake());
    assert_eq!(fw.gate().open_circuit_calls, before + 1);
    assert_eq!(
        fw.process(&sign(&mut host, &NOMINAL)).unwrap_err(),
        Rejection::NoActiveSession
    );
    let (_, resp) = HostSession::establish(&PSK, &pending_ek, &mut trng()).unwrap();
    assert_eq!(
        fw.complete_handshake(&resp.ciphertext, &resp.confirmation).unwrap_err(),
        Rejection::HandshakeNotStarted
    );
}

// ----------------------------------------------------------- authentication

#[test]
fn forged_and_tampered_packets_fail_authentication() {
    let (mut fw, mut host) = setup();
    let mut forged = sign(&mut host, &NOMINAL);
    forged[BODY_LEN..].fill(0xAA);
    assert_eq!(fw.process(&forged).unwrap_err(), Rejection::AuthenticationFailed);

    let mut tampered = sign(&mut host, &NOMINAL);
    tampered[12] = 0xFF; // raise cathodic current after signing
    assert_eq!(fw.process(&tampered).unwrap_err(), Rejection::AuthenticationFailed);
    assert_eq!(fw.gate().delivered, []);
    assert_eq!(fw.stats().rejected_authentication, 2);
}

#[test]
fn every_single_bit_flip_is_rejected() {
    let (mut fw, mut host) = setup();
    let packet = sign(&mut host, &NOMINAL);
    for bit in 0..PACKET_LEN * 8 {
        let mut m = packet;
        m[bit / 8] ^= 1 << (bit % 8);
        assert!(fw.process(&m).is_err(), "bit {bit}");
    }
    assert_eq!(fw.gate().delivered, []);
    // The untouched packet still works: no flipped variant consumed its counter.
    assert_eq!(fw.process(&packet).unwrap().counter, 1);
}

// ---------------------------------------------------------------- freshness

#[test]
fn replayed_and_reordered_packets_are_rejected() {
    let (mut fw, mut host) = setup();
    let p1 = sign(&mut host, &NOMINAL);
    let p2 = sign(&mut host, &NOMINAL);
    let p3 = sign(&mut host, &NOMINAL);
    fw.process(&p1).unwrap();
    fw.process(&p3).unwrap(); // gap is allowed (p2 "lost")
    assert_eq!(
        fw.process(&p1).unwrap_err(),
        Rejection::ReplayDetected {
            counter: 1,
            last_accepted: 3
        }
    );
    assert_eq!(
        fw.process(&p2).unwrap_err(),
        Rejection::ReplayDetected {
            counter: 2,
            last_accepted: 3
        }
    );
    assert_eq!(fw.gate().delivered.len(), 2);
    assert_eq!(fw.stats().rejected_replay, 2);
}

// ------------------------------------------------------------------ physics

#[test]
fn signed_lethal_command_is_blocked_and_not_retryable() {
    let (mut fw, mut host) = setup();
    let lethal = StimulationCommand {
        pulse: BiphasicPulse::symmetric(10_000, 1_000, 50),
        ..NOMINAL
    };
    let pkt = sign(&mut host, &lethal);
    assert!(matches!(
        fw.process(&pkt).unwrap_err(),
        Rejection::ShannonLimitExceeded { .. }
    ));
    // Retrying the same authentic packet is now a replay.
    assert!(matches!(
        fw.process(&pkt).unwrap_err(),
        Rejection::ReplayDetected { .. }
    ));
    assert_eq!(fw.gate().delivered, []);
    // Legitimate traffic continues.
    fw.process(&sign(&mut host, &NOMINAL)).unwrap();
    assert_eq!(fw.gate().delivered.len(), 1);
}

#[test]
fn every_safety_rejection_is_reachable_end_to_end() {
    let (mut fw, mut host) = setup();
    let with = |pulse| StimulationCommand { pulse, ..NOMINAL };
    let cases: [(StimulationCommand, u16); 6] = [
        (
            StimulationCommand {
                electrode_id: 99,
                ..NOMINAL
            },
            401,
        ),
        (with(BiphasicPulse::symmetric(10_001, 100, 0)), 402),
        (
            with(BiphasicPulse {
                anodic_current_ua: 0,
                ..BiphasicPulse::symmetric(1_000, 100, 0)
            }),
            404,
        ),
        (
            with(BiphasicPulse {
                anodic_current_ua: 900,
                ..BiphasicPulse::symmetric(1_000, 100, 0)
            }),
            405,
        ),
        (with(BiphasicPulse::symmetric(10_000, 1_000, 50)), 406),
        (with(BiphasicPulse::symmetric(2_600, 500, 50)), 407),
    ];
    for (cmd, code) in cases {
        assert_eq!(fw.process(&sign(&mut host, &cmd)).unwrap_err().code(), code, "{cmd:?}");
    }
    assert_eq!(fw.stats().rejected_safety, 6);
    assert_eq!(fw.gate().delivered, []);
}

#[test]
fn every_rejection_forces_open_circuit_and_stats_add_up() {
    let (mut fw, mut host) = setup();
    let before = fw.gate().open_circuit_calls;
    let _ = fw.process(&[0u8; 3]); // framing
    let mut forged = sign(&mut host, &NOMINAL);
    forged[40] ^= 1;
    let _ = fw.process(&forged); // authentication
    let p = sign(&mut host, &NOMINAL);
    fw.process(&p).unwrap();
    let _ = fw.process(&p); // replay
    let mono = StimulationCommand {
        pulse: BiphasicPulse {
            anodic_current_ua: 0,
            ..BiphasicPulse::symmetric(1_000, 100, 0)
        },
        ..NOMINAL
    };
    let _ = fw.process(&sign(&mut host, &mono)); // safety
    let s = *fw.stats();
    assert_eq!(fw.gate().open_circuit_calls, before + 4);
    assert_eq!(
        (
            s.rejected_framing,
            s.rejected_authentication,
            s.rejected_replay,
            s.rejected_safety
        ),
        (1, 1, 1, 1)
    );
    assert_eq!(s.rejected(), 4);
    assert_eq!(s.accepted, 1);
}

#[test]
fn multiple_electrodes_use_their_own_area() {
    let small = ElectrodeSpec {
        id: 1,
        geometric_area_um2: 1_000_000,
    }; // 0.01 cm²
    let large = ElectrodeSpec {
        id: 2,
        geometric_area_um2: 10_000_000,
    }; // 0.1 cm²
    let mut fw: Fw = Firewall::new(
        PSK,
        SafetyLimits::default(),
        ElectrodeTable::try_new(&[small, large]).unwrap(),
        RecordingGate::default(),
    )
    .unwrap();
    let mut host = handshake(&mut fw);
    // 1 mA × 500 µs = 0.5 µC: 50 µC/cm² on the small contact, 5 µC/cm² on the large one.
    let on = |id| StimulationCommand {
        electrode_id: id,
        pulse: BiphasicPulse::symmetric(1_000, 500, 50),
        ..NOMINAL
    };
    assert!(matches!(
        fw.process(&sign(&mut host, &on(1))).unwrap_err(),
        Rejection::ChargeDensityExceeded { .. }
    ));
    assert_eq!(fw.process(&sign(&mut host, &on(2))).unwrap().electrode_id, 2);
}

// --------------------------------------------------------------- properties

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Arbitrary bytes from an attacker without the key never reach the gate.
    #[test]
    fn prop_random_bytes_are_never_delivered(bytes in proptest::collection::vec(any::<u8>(), 0..160)) {
        let (mut fw, _host) = setup();
        prop_assert!(fw.process(&bytes).is_err());
        prop_assert_eq!(fw.gate().delivered.len(), 0);
    }

    /// Any non-empty XOR mask applied to a signed packet is rejected.
    #[test]
    fn prop_any_mutation_of_a_signed_packet_is_rejected(
        index in 0..PACKET_LEN,
        mask in 1u8..=255,
        extra in proptest::collection::vec((0..PACKET_LEN, any::<u8>()), 0..4),
    ) {
        let (mut fw, mut host) = setup();
        let original = sign(&mut host, &NOMINAL);
        let mut m = original;
        m[index] ^= mask;
        for (i, x) in extra {
            if i != index {
                m[i] ^= x;
            }
        }
        prop_assert!(fw.process(&m).is_err());
        prop_assert_eq!(fw.gate().delivered.len(), 0);
    }

    /// Signed commands are delivered iff the standalone limiter accepts them.
    #[test]
    fn prop_signed_commands_match_the_limiter(
        i in 0u32..=12_000, w in 0u32..=1_200, gap in 0u32..=250, rate in 0u16..=400, count in 0u16..=50,
    ) {
        let (mut fw, mut host) = setup();
        let cmd = StimulationCommand {
            electrode_id: 7,
            pulse: BiphasicPulse::symmetric(i, w, gap),
            pulse_rate_hz: rate,
            pulse_count: count,
        };
        let expected = bnf_core::shannon::validate(&cmd, &ECOG, &SafetyLimits::default());
        let got = fw.process(&sign(&mut host, &cmd));
        prop_assert_eq!(got.is_ok(), expected.is_ok());
        if let (Err(g), Err(e)) = (got, expected) {
            prop_assert_eq!(g, e);
        }
        prop_assert_eq!(fw.gate().delivered.len(), usize::from(expected.is_ok()));
    }
}
