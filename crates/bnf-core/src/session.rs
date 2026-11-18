//! Post-quantum session establishment (ML-KEM-768, FIPS 203) — host side,
//! plus the implant-side pending state used by [`crate::Firewall`].
//!
//! ```text
//!  Implant (firewall)                                Host (BCI computer)
//!  ------------------                                -------------------
//!  (dk, ek) <- ML-KEM-768.KeyGen(TRNG)
//!                         ---- ek (1184 B) ---->
//!                                                    (ct, ss) <- Encaps(ek)
//!                                                    keys = KDF(PSK, ss, H(ek)||ct)
//!                         <--- ct (1088 B), confirm = MAC(k_confirm, transcript) ---
//!  ss = Decaps(dk, ct)
//!  keys = KDF(PSK, ss, H(ek)||ct)
//!  verify confirm  -> session active, counter = 0
//! ```
//!
//! The ephemeral key pair gives forward secrecy; the PSK authenticates the host;
//! the confirmation tag rejects a rogue host during the handshake instead of on
//! the first command. Shared secrets are wiped as soon as the keys are derived.

use ml_kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, Generate, KeyExport, MlKem768, TryKeyInit};
use rand_core::CryptoRng;
use zeroize::Zeroize;

use crate::crypto::{self, Psk, SessionKeys};
use crate::error::Rejection;
use crate::packet::{self, PACKET_LEN, StimulationCommand};

/// Serialized ML-KEM-768 encapsulation key length.
pub const ENCAPSULATION_KEY_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length.
pub const CIPHERTEXT_LEN: usize = 1088;
/// Host key-confirmation tag length.
pub const CONFIRMATION_TAG_LEN: usize = 32;

/// Implant-side state between `begin_handshake` and `complete_handshake`.
/// The decapsulation key is wiped on drop (`ml-kem` `zeroize` feature).
pub(crate) struct PendingHandshake {
    dk: DecapsulationKey<MlKem768>,
    ek_digest: [u8; 32],
}

impl PendingHandshake {
    /// Generates a fresh ephemeral key pair from the TRNG.
    pub(crate) fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> (Self, [u8; ENCAPSULATION_KEY_LEN]) {
        let dk = DecapsulationKey::<MlKem768>::generate_from_rng(rng);
        let encoded = dk.encapsulation_key().to_bytes();
        let mut ek = [0u8; ENCAPSULATION_KEY_LEN];
        ek.copy_from_slice(encoded.as_slice());
        let pending = Self {
            dk,
            ek_digest: crypto::encapsulation_key_digest(&ek),
        };
        (pending, ek)
    }

    /// Decapsulates, derives the session keys and verifies the host confirmation.
    pub(crate) fn complete(self, psk: &Psk, ciphertext: &[u8], confirmation: &[u8]) -> Result<SessionKeys, Rejection> {
        let confirmation: &[u8; CONFIRMATION_TAG_LEN] =
            confirmation.try_into().map_err(|_| Rejection::HandshakeFailed)?;
        let mut shared = self
            .dk
            .decapsulate_slice(ciphertext)
            .map_err(|_| Rejection::HandshakeFailed)?;
        let transcript = crypto::transcript_hash(&self.ek_digest, ciphertext);
        let keys = crypto::derive_session_keys(psk, shared.as_slice(), &transcript);
        shared.as_mut_slice().zeroize();
        // ML-KEM uses implicit rejection: a forged ciphertext still yields a
        // (pseudo-random) shared secret, so the confirmation tag is what fails.
        if keys.verify_confirmation(&transcript, confirmation) {
            Ok(keys)
        } else {
            Err(Rejection::HandshakeFailed)
        }
    }
}

/// Handshake message sent from the host back to the implant.
pub struct HandshakeResponse {
    /// ML-KEM-768 ciphertext.
    pub ciphertext: [u8; CIPHERTEXT_LEN],
    /// Key-confirmation tag proving knowledge of the PSK.
    pub confirmation: [u8; CONFIRMATION_TAG_LEN],
}

/// Host-side session: signs stimulation commands with a strictly increasing counter.
pub struct HostSession {
    keys: SessionKeys,
    last_counter: u64,
}

impl HostSession {
    /// Encapsulates to the implant's ephemeral key and derives the session keys.
    ///
    /// # Errors
    /// [`Rejection::HandshakeFailed`] if the encapsulation key is malformed.
    pub fn establish<R: CryptoRng + ?Sized>(
        psk: &Psk,
        implant_encapsulation_key: &[u8],
        rng: &mut R,
    ) -> Result<(Self, HandshakeResponse), Rejection> {
        let ek = EncapsulationKey::<MlKem768>::new_from_slice(implant_encapsulation_key)
            .map_err(|_| Rejection::HandshakeFailed)?;
        let (ct, mut shared) = ek.encapsulate_with_rng(rng);
        let mut ciphertext = [0u8; CIPHERTEXT_LEN];
        ciphertext.copy_from_slice(ct.as_slice());

        let ek_digest = crypto::encapsulation_key_digest(implant_encapsulation_key);
        let transcript = crypto::transcript_hash(&ek_digest, &ciphertext);
        let keys = crypto::derive_session_keys(psk, shared.as_slice(), &transcript);
        shared.as_mut_slice().zeroize();
        let confirmation = keys.confirmation_tag(&transcript);
        Ok((
            Self { keys, last_counter: 0 },
            HandshakeResponse {
                ciphertext,
                confirmation,
            },
        ))
    }

    /// Serialises and MACs a command using the next counter value.
    ///
    /// # Errors
    /// [`Rejection::CounterExhausted`] once counter `u64::MAX` has been used;
    /// the counter never wraps or repeats.
    pub fn sign(&mut self, cmd: &StimulationCommand) -> Result<[u8; PACKET_LEN], Rejection> {
        let counter = self.last_counter.checked_add(1).ok_or(Rejection::CounterExhausted)?;
        self.last_counter = counter;
        let body = packet::encode_body(cmd, counter);
        Ok(packet::assemble(&body, &self.keys.command_tag(&body)))
    }

    /// Counter used by the most recent successful [`HostSession::sign`] call.
    #[must_use]
    pub const fn last_counter(&self) -> u64 {
        self.last_counter
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{BiphasicPulse, decode_counter, split_frame};
    use getrandom::SysRng;
    use rand_core::UnwrapErr;

    const PSK: Psk = [0x11; 32];
    const CMD: StimulationCommand = StimulationCommand {
        electrode_id: 1,
        pulse: BiphasicPulse::symmetric(1_000, 100, 10),
        pulse_rate_hz: 50,
        pulse_count: 1,
    };

    fn pair() -> (PendingHandshake, HostSession, HandshakeResponse) {
        let mut rng = UnwrapErr(SysRng);
        let (pending, ek) = PendingHandshake::generate(&mut rng);
        let (host, resp) = HostSession::establish(&PSK, &ek, &mut rng).unwrap();
        (pending, host, resp)
    }

    #[test]
    fn wire_sizes_match_fips_203_ml_kem_768() {
        let (_, ek) = PendingHandshake::generate(&mut UnwrapErr(SysRng));
        assert_eq!(ek.len(), 1184);
        let (_, _, resp) = pair();
        assert_eq!(resp.ciphertext.len(), 1088);
    }

    #[test]
    fn both_sides_derive_the_same_keys() {
        let (pending, mut host, resp) = pair();
        let implant_keys = pending.complete(&PSK, &resp.ciphertext, &resp.confirmation).unwrap();
        let packet = host.sign(&CMD).unwrap();
        let frame = split_frame(&packet).unwrap();
        assert!(implant_keys.verify_command(frame.body, frame.tag));
    }

    #[test]
    fn complete_rejects_wrong_lengths_and_wrong_psk() {
        let (pending, _, resp) = pair();
        assert_eq!(
            pending
                .complete(&PSK, &resp.ciphertext[..100], &resp.confirmation)
                .err(),
            Some(Rejection::HandshakeFailed)
        );
        let (pending, _, resp) = pair();
        assert_eq!(
            pending.complete(&PSK, &resp.ciphertext, &resp.confirmation[..31]).err(),
            Some(Rejection::HandshakeFailed)
        );
        let (pending, _, resp) = pair();
        assert_eq!(
            pending.complete(&[0; 32], &resp.ciphertext, &resp.confirmation).err(),
            Some(Rejection::HandshakeFailed)
        );
    }

    #[test]
    fn establish_rejects_malformed_encapsulation_keys() {
        let mut rng = UnwrapErr(SysRng);
        for len in [0, 32, ENCAPSULATION_KEY_LEN - 1, ENCAPSULATION_KEY_LEN + 1] {
            assert!(
                HostSession::establish(&PSK, &vec![0u8; len], &mut rng).is_err(),
                "len {len}"
            );
        }
    }

    #[test]
    fn counters_start_at_one_and_increase() {
        let (_, mut host, _) = pair();
        assert_eq!(host.last_counter(), 0);
        for expected in 1..=5 {
            let p = host.sign(&CMD).unwrap();
            assert_eq!(decode_counter(split_frame(&p).unwrap().body), expected);
            assert_eq!(host.last_counter(), expected);
        }
    }

    #[test]
    fn counter_never_wraps() {
        let (_, mut host, _) = pair();
        host.last_counter = u64::MAX - 1;
        let p = host.sign(&CMD).unwrap();
        assert_eq!(decode_counter(split_frame(&p).unwrap().body), u64::MAX);
        assert_eq!(host.sign(&CMD), Err(Rejection::CounterExhausted));
        assert_eq!(host.last_counter(), u64::MAX);
    }

    #[test]
    fn sessions_are_independent() {
        let (_, mut a, _) = pair();
        let (_, mut b, _) = pair();
        assert_ne!(a.sign(&CMD).unwrap(), b.sign(&CMD).unwrap());
    }
}
