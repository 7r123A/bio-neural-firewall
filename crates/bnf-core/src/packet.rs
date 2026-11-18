//! Fixed-length binary wire format for stimulation commands.
//!
//! All integers are little-endian. The 32-byte tag authenticates bytes `0..36`.
//!
//! ```text
//! offset  size  field
//! ------  ----  -----------------------------------------------
//!      0     1  version              (0x01)
//!      1     1  opcode               (0x10 = STIMULATE)
//!      2     2  electrode_id
//!      4     8  counter              (strictly monotonic per session)
//!     12     4  cathodic_current_ua
//!     16     4  cathodic_width_us
//!     20     4  interphase_gap_us
//!     24     4  anodic_current_ua
//!     28     4  anodic_width_us
//!     32     2  pulse_rate_hz
//!     34     2  pulse_count
//!     36    32  tag = BLAKE3-keyed(command_mac_key, bytes[0..36])
//! ------  ----
//!     68        total
//! ```

use crate::error::Rejection;

/// Protocol version accepted by this kernel.
pub const PROTOCOL_VERSION: u8 = 0x01;
/// Opcode of a stimulation command.
pub const OPCODE_STIMULATE: u8 = 0x10;
/// Length of the authenticated body.
pub const BODY_LEN: usize = 36;
/// Length of the MAC tag.
pub const TAG_LEN: usize = 32;
/// Total packet length.
pub const PACKET_LEN: usize = BODY_LEN + TAG_LEN;

/// One charge-balanced biphasic pulse (cathodic phase first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BiphasicPulse {
    /// Cathodic amplitude (µA).
    pub cathodic_current_ua: u32,
    /// Cathodic width (µs).
    pub cathodic_width_us: u32,
    /// Interphase gap (µs).
    pub interphase_gap_us: u32,
    /// Anodic amplitude (µA).
    pub anodic_current_ua: u32,
    /// Anodic width (µs).
    pub anodic_width_us: u32,
}

impl BiphasicPulse {
    /// Symmetric pulse: identical amplitude and width in both phases.
    #[must_use]
    pub const fn symmetric(current_ua: u32, width_us: u32, interphase_gap_us: u32) -> Self {
        Self {
            cathodic_current_ua: current_ua,
            cathodic_width_us: width_us,
            interphase_gap_us,
            anodic_current_ua: current_ua,
            anodic_width_us: width_us,
        }
    }
}

/// A decoded stimulation command (still untrusted until the firewall accepts it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StimulationCommand {
    /// Target electrode id.
    pub electrode_id: u16,
    /// Pulse shape.
    pub pulse: BiphasicPulse,
    /// Repetition rate of the train (Hz).
    pub pulse_rate_hz: u16,
    /// Number of pulses in the train.
    pub pulse_count: u16,
}

/// A length-, version- and opcode-checked view of a packet.
#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    /// Authenticated bytes.
    pub body: &'a [u8; BODY_LEN],
    /// MAC tag.
    pub tag: &'a [u8; TAG_LEN],
}

/// Checks framing and splits the packet into body and tag.
///
/// # Errors
/// [`Rejection::MalformedPacket`], [`Rejection::UnsupportedVersion`] or
/// [`Rejection::UnknownOpcode`].
pub fn split_frame(packet: &[u8]) -> Result<Frame<'_>, Rejection> {
    let malformed = Rejection::MalformedPacket {
        expected_len: PACKET_LEN,
        actual_len: packet.len(),
    };
    // Too short for a body → None; body present but remainder != 32 bytes → Err.
    let (body, rest) = packet.split_first_chunk::<BODY_LEN>().ok_or(malformed)?;
    let tag: &[u8; TAG_LEN] = rest.try_into().map_err(|_| malformed)?;
    if body[0] != PROTOCOL_VERSION {
        return Err(Rejection::UnsupportedVersion { version: body[0] });
    }
    if body[1] != OPCODE_STIMULATE {
        return Err(Rejection::UnknownOpcode { opcode: body[1] });
    }
    Ok(Frame { body, tag })
}

const fn le_u16(b: &[u8; BODY_LEN], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

const fn le_u32(b: &[u8; BODY_LEN], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

const fn le_u64(b: &[u8; BODY_LEN], o: usize) -> u64 {
    u64::from_le_bytes([
        b[o],
        b[o + 1],
        b[o + 2],
        b[o + 3],
        b[o + 4],
        b[o + 5],
        b[o + 6],
        b[o + 7],
    ])
}

/// Reads the counter field.
#[must_use]
pub const fn decode_counter(body: &[u8; BODY_LEN]) -> u64 {
    le_u64(body, 4)
}

/// Reads the command fields.
#[must_use]
pub const fn decode_command(body: &[u8; BODY_LEN]) -> StimulationCommand {
    StimulationCommand {
        electrode_id: le_u16(body, 2),
        pulse: BiphasicPulse {
            cathodic_current_ua: le_u32(body, 12),
            cathodic_width_us: le_u32(body, 16),
            interphase_gap_us: le_u32(body, 20),
            anodic_current_ua: le_u32(body, 24),
            anodic_width_us: le_u32(body, 28),
        },
        pulse_rate_hz: le_u16(body, 32),
        pulse_count: le_u16(body, 34),
    }
}

/// Serialises the authenticated body.
#[must_use]
pub fn encode_body(cmd: &StimulationCommand, counter: u64) -> [u8; BODY_LEN] {
    let mut b = [0u8; BODY_LEN];
    b[0] = PROTOCOL_VERSION;
    b[1] = OPCODE_STIMULATE;
    b[2..4].copy_from_slice(&cmd.electrode_id.to_le_bytes());
    b[4..12].copy_from_slice(&counter.to_le_bytes());
    b[12..16].copy_from_slice(&cmd.pulse.cathodic_current_ua.to_le_bytes());
    b[16..20].copy_from_slice(&cmd.pulse.cathodic_width_us.to_le_bytes());
    b[20..24].copy_from_slice(&cmd.pulse.interphase_gap_us.to_le_bytes());
    b[24..28].copy_from_slice(&cmd.pulse.anodic_current_ua.to_le_bytes());
    b[28..32].copy_from_slice(&cmd.pulse.anodic_width_us.to_le_bytes());
    b[32..34].copy_from_slice(&cmd.pulse_rate_hz.to_le_bytes());
    b[34..36].copy_from_slice(&cmd.pulse_count.to_le_bytes());
    b
}

/// Concatenates body and tag into a wire packet.
#[must_use]
pub fn assemble(body: &[u8; BODY_LEN], tag: &[u8; TAG_LEN]) -> [u8; PACKET_LEN] {
    let mut out = [0u8; PACKET_LEN];
    out[..BODY_LEN].copy_from_slice(body);
    out[BODY_LEN..].copy_from_slice(tag);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const SAMPLE: StimulationCommand = StimulationCommand {
        electrode_id: 0xBEEF,
        pulse: BiphasicPulse {
            cathodic_current_ua: 2_000,
            cathodic_width_us: 200,
            interphase_gap_us: 50,
            anodic_current_ua: 1_000,
            anodic_width_us: 400,
        },
        pulse_rate_hz: 100,
        pulse_count: 3,
    };

    #[test]
    fn round_trip_and_exact_layout() {
        let body = encode_body(&SAMPLE, 0x0102_0304_0506_0708);
        assert_eq!(decode_command(&body), SAMPLE);
        assert_eq!(decode_counter(&body), 0x0102_0304_0506_0708);
        // Spot-check the documented offsets.
        assert_eq!(&body[0..2], &[PROTOCOL_VERSION, OPCODE_STIMULATE]);
        assert_eq!(&body[2..4], &0xBEEFu16.to_le_bytes());
        assert_eq!(&body[4..12], &[8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(&body[12..16], &2_000u32.to_le_bytes());
        assert_eq!(&body[34..36], &3u16.to_le_bytes());
    }

    #[test]
    fn symmetric_pulse_mirrors_phases() {
        let p = BiphasicPulse::symmetric(123, 45, 6);
        assert_eq!(p.cathodic_current_ua, p.anodic_current_ua);
        assert_eq!(p.cathodic_width_us, p.anodic_width_us);
        assert_eq!(p.interphase_gap_us, 6);
    }

    #[test]
    fn every_wrong_length_is_malformed() {
        let buf = [0u8; 256];
        for len in (0..=buf.len()).filter(|&l| l != PACKET_LEN) {
            assert_eq!(
                split_frame(&buf[..len]).unwrap_err(),
                Rejection::MalformedPacket {
                    expected_len: PACKET_LEN,
                    actual_len: len
                },
                "len {len}"
            );
        }
    }

    #[test]
    fn version_and_opcode_are_checked() {
        let tag = [0xAB; TAG_LEN];
        let mut p = assemble(&encode_body(&SAMPLE, 1), &tag);
        let frame = split_frame(&p).unwrap();
        assert_eq!(frame.tag, &tag);
        assert_eq!(decode_command(frame.body), SAMPLE);
        p[0] = 0x02;
        assert_eq!(
            split_frame(&p).unwrap_err(),
            Rejection::UnsupportedVersion { version: 2 }
        );
        p[0] = PROTOCOL_VERSION;
        p[1] = 0x99;
        assert_eq!(split_frame(&p).unwrap_err(), Rejection::UnknownOpcode { opcode: 0x99 });
    }

    fn any_command() -> impl Strategy<Value = StimulationCommand> {
        (any::<u16>(), any::<[u32; 5]>(), any::<u16>(), any::<u16>()).prop_map(
            |(electrode_id, p, pulse_rate_hz, pulse_count)| StimulationCommand {
                electrode_id,
                pulse: BiphasicPulse {
                    cathodic_current_ua: p[0],
                    cathodic_width_us: p[1],
                    interphase_gap_us: p[2],
                    anodic_current_ua: p[3],
                    anodic_width_us: p[4],
                },
                pulse_rate_hz,
                pulse_count,
            },
        )
    }

    proptest! {
        #[test]
        fn prop_encode_decode_round_trip(cmd in any_command(), counter in any::<u64>()) {
            let body = encode_body(&cmd, counter);
            prop_assert_eq!(decode_command(&body), cmd);
            prop_assert_eq!(decode_counter(&body), counter);
        }

        #[test]
        fn prop_split_frame_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
            let r = split_frame(&bytes);
            if bytes.len() != PACKET_LEN {
                let is_malformed = matches!(r, Err(Rejection::MalformedPacket { .. }));
                prop_assert!(is_malformed);
            }
        }
    }
}
