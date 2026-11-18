//! Entropy source abstraction (hardware TRNG).
//!
//! The kernel accepts any [`rand_core::CryptoRng`]. On a microcontroller, wrap the
//! TRNG data register with [`HardwareTrng`]; on a host, use the OS generator
//! (e.g. `rand_core::UnwrapErr(getrandom::SysRng)`).
//!
//! The TRNG is used for the ephemeral ML-KEM-768 key pair generated at the start
//! of every session. Replay protection itself comes from the monotonic counter;
//! the TRNG guarantees that each session has a fresh, unpredictable key so that
//! packets recorded in one session are worthless in every other session.

use core::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};

/// Adapter turning a "read one 32-bit word from the TRNG" closure into a
/// [`rand_core::CryptoRng`].
///
/// # Requirements on the closure
///
/// The closure **must** block until fresh entropy is available and **must** only
/// return words that passed the peripheral's continuous health tests
/// (NIST SP 800-90B repetition-count and adaptive-proportion tests, or the
/// vendor equivalent). If a health test fails, the closure must not return —
/// latch the stimulation output open-circuit and reset instead.
pub struct HardwareTrng<F: FnMut() -> u32> {
    read_word: F,
}

impl<F: FnMut() -> u32> HardwareTrng<F> {
    /// Wraps a TRNG word reader.
    pub const fn new(read_word: F) -> Self {
        Self { read_word }
    }
}

impl<F: FnMut() -> u32> TryRng for HardwareTrng<F> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok((self.read_word)())
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let lo = u64::from((self.read_word)());
        let hi = u64::from((self.read_word)());
        Ok((hi << 32) | lo)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(4) {
            let word = (self.read_word)().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        Ok(())
    }
}

impl<F: FnMut() -> u32> TryCryptoRng for HardwareTrng<F> {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::Rng;

    fn counting_trng() -> HardwareTrng<impl FnMut() -> u32> {
        let mut n = 0u32;
        HardwareTrng::new(move || {
            n += 1;
            0x0403_0201 * n
        })
    }

    #[test]
    fn fills_partial_words() {
        let mut buf = [0u8; 6];
        counting_trng().fill_bytes(&mut buf);
        assert_eq!(buf, [0x01, 0x02, 0x03, 0x04, 0x02, 0x04]);
    }

    #[test]
    fn empty_fill_reads_nothing() {
        let reads = core::cell::Cell::new(0);
        let mut trng = HardwareTrng::new(|| {
            reads.set(reads.get() + 1);
            0
        });
        trng.fill_bytes(&mut []);
        assert_eq!(reads.get(), 0);
    }

    #[test]
    fn u32_and_u64_words() {
        let mut t = counting_trng();
        assert_eq!(t.next_u32(), 0x0403_0201);
        // second word is the low half, third word the high half
        assert_eq!(
            t.next_u64(),
            (u64::from(0x0403_0201u32 * 3) << 32) | u64::from(0x0403_0201u32 * 2)
        );
    }

    #[test]
    fn drives_ml_kem_key_generation() {
        // Any CryptoRng works for the handshake; a deterministic source gives a
        // deterministic key, proving the TRNG is the sole entropy input.
        let ek = |seed: u32| {
            let mut s = seed;
            let mut trng = HardwareTrng::new(move || {
                s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                s
            });
            crate::session::PendingHandshake::generate(&mut trng).1
        };
        assert_eq!(ek(1), ek(1));
        assert_ne!(ek(1), ek(2));
    }
}
