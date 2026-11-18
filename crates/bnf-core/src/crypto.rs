//! Key derivation and message authentication (BLAKE3).
//!
//! Key schedule:
//!
//! ```text
//! transcript = BLAKE3-derive("…transcript", BLAKE3(ek) || ct)
//! master     = BLAKE3-derive("…session secret", PSK || ML-KEM shared secret || transcript)
//! k_cmd      = BLAKE3-derive("…command MAC key", master)
//! k_confirm  = BLAKE3-derive("…host key confirmation", master)
//! ```
//!
//! Mixing the provisioning PSK into the KDF is what authenticates the host:
//! ML-KEM on its own only provides confidentiality of the shared secret, so
//! anyone in radio range could otherwise complete a handshake with the implant.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::packet::{BODY_LEN, TAG_LEN};

/// Length of the provisioning pre-shared key.
pub const PSK_LEN: usize = 32;

/// Provisioning pre-shared key, installed at implantation (out of band, in clinic).
pub type Psk = [u8; PSK_LEN];

const CTX_TRANSCRIPT: &str = "bio-neural-firewall v1 2026-11 handshake transcript";
const CTX_SESSION: &str = "bio-neural-firewall v1 2026-11 session secret";
const CTX_COMMAND_MAC: &str = "bio-neural-firewall v1 2026-11 command MAC key";
const CTX_CONFIRM: &str = "bio-neural-firewall v1 2026-11 host key confirmation";

/// Symmetric keys of one authenticated session. Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SessionKeys {
    command_mac_key: [u8; 32],
    confirmation_key: [u8; 32],
}

/// Digest of the implant's ephemeral encapsulation key.
pub(crate) fn encapsulation_key_digest(ek: &[u8]) -> [u8; 32] {
    *blake3::hash(ek).as_bytes()
}

/// Binds the handshake transcript (encapsulation key digest and ciphertext).
pub(crate) fn transcript_hash(ek_digest: &[u8; 32], ciphertext: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(CTX_TRANSCRIPT);
    h.update(ek_digest);
    h.update(ciphertext);
    *h.finalize().as_bytes()
}

/// Derives the session keys from PSK, ML-KEM shared secret and transcript.
/// All intermediate secrets are wiped before returning.
pub(crate) fn derive_session_keys(psk: &Psk, shared_secret: &[u8], transcript: &[u8; 32]) -> SessionKeys {
    let mut h = blake3::Hasher::new_derive_key(CTX_SESSION);
    h.update(psk);
    h.update(shared_secret);
    h.update(transcript);
    let mut master = *h.finalize().as_bytes();
    h.zeroize();
    let keys = SessionKeys {
        command_mac_key: blake3::derive_key(CTX_COMMAND_MAC, &master),
        confirmation_key: blake3::derive_key(CTX_CONFIRM, &master),
    };
    master.zeroize();
    keys
}

impl SessionKeys {
    /// Tag sent by the host to prove it derived the same keys (i.e. knows the PSK).
    pub(crate) fn confirmation_tag(&self, transcript: &[u8; 32]) -> [u8; 32] {
        *blake3::keyed_hash(&self.confirmation_key, transcript).as_bytes()
    }

    /// Constant-time check of the host's confirmation tag.
    pub(crate) fn verify_confirmation(&self, transcript: &[u8; 32], tag: &[u8; 32]) -> bool {
        // `blake3::Hash` implements constant-time equality.
        blake3::keyed_hash(&self.confirmation_key, transcript) == blake3::Hash::from(*tag)
    }

    /// MAC over a command body.
    pub(crate) fn command_tag(&self, body: &[u8; BODY_LEN]) -> [u8; TAG_LEN] {
        *blake3::keyed_hash(&self.command_mac_key, body).as_bytes()
    }

    /// Constant-time check of a command MAC.
    pub(crate) fn verify_command(&self, body: &[u8; BODY_LEN], tag: &[u8; TAG_LEN]) -> bool {
        blake3::keyed_hash(&self.command_mac_key, body) == blake3::Hash::from(*tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: [u8; 32] = [7u8; 32];
    const BODY: [u8; BODY_LEN] = [0u8; BODY_LEN];

    #[test]
    fn every_kdf_input_changes_the_keys() {
        let base = derive_session_keys(&[1; 32], &[9; 32], &T);
        let tag = base.command_tag(&BODY);
        for other in [
            derive_session_keys(&[2; 32], &[9; 32], &T),
            derive_session_keys(&[1; 32], &[8; 32], &T),
            derive_session_keys(&[1; 32], &[9; 32], &[6; 32]),
        ] {
            assert_ne!(other.command_tag(&BODY), tag);
            assert!(!other.verify_command(&BODY, &tag));
        }
        assert!(base.verify_command(&BODY, &tag));
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = derive_session_keys(&[1; 32], &[9; 32], &T);
        let b = derive_session_keys(&[1; 32], &[9; 32], &T);
        assert_eq!(a.command_tag(&BODY), b.command_tag(&BODY));
        assert_eq!(a.confirmation_tag(&T), b.confirmation_tag(&T));
    }

    #[test]
    fn command_and_confirmation_keys_are_separated() {
        let k = derive_session_keys(&[1; 32], &[9; 32], &[0; 32]);
        assert_ne!(k.command_mac_key, k.confirmation_key);
        // A confirmation tag must never verify as a command tag (domain separation).
        let mut body = [0u8; BODY_LEN];
        body[..32].copy_from_slice(&T);
        assert!(!k.verify_command(&body, &k.confirmation_tag(&T)));
    }

    #[test]
    fn confirmation_binds_the_transcript() {
        let k = derive_session_keys(&[1; 32], &[9; 32], &T);
        let tag = k.confirmation_tag(&T);
        assert!(k.verify_confirmation(&T, &tag));
        assert!(!k.verify_confirmation(&[8; 32], &tag));
        let mut flipped = tag;
        flipped[31] ^= 1;
        assert!(!k.verify_confirmation(&T, &flipped));
    }

    #[test]
    fn transcript_depends_on_both_inputs() {
        let a = transcript_hash(&[1; 32], &[2; 10]);
        assert_ne!(a, transcript_hash(&[0; 32], &[2; 10]));
        assert_ne!(a, transcript_hash(&[1; 32], &[3; 10]));
        assert_ne!(encapsulation_key_digest(&[1]), encapsulation_key_digest(&[2]));
    }
}
