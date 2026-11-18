//! C ABI bridge for the Bio-Neural Firewall.
//!
//! Exposes two roles so that a test harness (the Python simulation) can drive
//! the *real* Rust kernel instead of a re-implementation:
//!
//! * **Implant** — `bnf_implant_*`: the firewall with a simulated output stage.
//! * **Host**    — `bnf_host_*`: the legitimate BCI computer that signs commands.
//!
//! Timing (`elapsed_ns`) is measured inside Rust around the kernel call only,
//! so it excludes Python/ctypes overhead.
//!
//! All functions are null-safe and never unwind across the ABI boundary
//! (`panic = "abort"` in release builds; no function in this file panics on
//! well-formed or malformed input).
//!
//! Return convention: `0` = success, a positive value = a stable rejection code
//! (see `bnf_core::REJECTION_CODES`), a negative value = an API misuse status
//! (`BNF_ERR_*`).

use std::fmt::Write as _;
use std::time::Instant;

use bnf_core::session::{CIPHERTEXT_LEN, CONFIRMATION_TAG_LEN, ENCAPSULATION_KEY_LEN};
use bnf_core::shannon::assess_phase;
use bnf_core::{
    BiphasicPulse, ElectrodeSpec, ElectrodeTable, Firewall, HostSession, PACKET_LEN, PSK_LEN, Psk, Rejection,
    SafetyLimits, StimulationCommand, StimulationGate, ValidatedPulse, rejection_name,
};
use getrandom::SysRng;
use rand_core::UnwrapErr;
use zeroize::Zeroizing;

/// Electrode-table capacity of the simulated implant.
pub const MAX_ELECTRODES: usize = 64;
/// Version of this C ABI. Bump on any breaking change.
pub const ABI_VERSION: u32 = 2;

/// Status: success.
pub const BNF_OK: i32 = 0;
/// Status: a required pointer was null.
pub const BNF_ERR_NULL: i32 = -1;
/// Status: a buffer has the wrong length.
pub const BNF_ERR_BUFFER: i32 = -2;
/// Status: the rejection code is unknown.
pub const BNF_ERR_UNKNOWN_CODE: i32 = -3;

const MESSAGE_LEN: usize = 256;

/// Simulated stimulator output stage: counts what would have reached tissue.
#[derive(Default)]
struct SimulatedOutputStage {
    delivered_commands: u64,
    delivered_pulses: u64,
    open_circuit_events: u64,
}

impl StimulationGate for SimulatedOutputStage {
    fn deliver(&mut self, pulse: &ValidatedPulse) {
        self.delivered_commands += 1;
        self.delivered_pulses += u64::from(pulse.command().pulse_count);
    }

    fn force_open_circuit(&mut self) {
        self.open_circuit_events += 1;
    }
}

/// Opaque implant handle.
pub struct BnfImplant {
    firewall: Firewall<SimulatedOutputStage, MAX_ELECTRODES>,
}

/// Opaque host handle.
pub struct BnfHost {
    session: HostSession,
}

/// Result of processing one packet.
#[repr(C)]
pub struct BnfVerdict {
    /// 0 = accepted, otherwise the stable rejection code.
    pub code: u32,
    /// Accepted counter, or the offending counter for a replay.
    pub counter: u64,
    /// Worst-phase charge in pC (when known).
    pub charge_pc: u64,
    /// Worst-phase charge density in nC/cm² (when known).
    pub density_nc_per_cm2: u64,
    /// D·Q × 10⁶ in µC²/cm² (when known).
    pub dq_micro: u64,
    /// Shannon limit 10^k × 10⁶ in µC²/cm².
    pub limit_dq_micro: u64,
    /// Time spent inside `Firewall::process`, in nanoseconds.
    pub elapsed_ns: u64,
    /// NUL-terminated English description.
    pub message: [u8; MESSAGE_LEN],
}

/// Safety limits in force (mirror of `bnf_core::SafetyLimits`).
#[repr(C)]
pub struct BnfLimits {
    /// 10^k × 10⁶ in µC²/cm².
    pub limit_dq_micro: u64,
    /// Charge-density cap in nC/cm².
    pub max_charge_density_nc_per_cm2: u64,
    /// Shannon k × 1000.
    pub shannon_k_milli: u32,
    /// Charge-balance tolerance in ppm.
    pub charge_balance_tolerance_ppm: u32,
    /// Maximum current per phase in µA.
    pub max_current_ua: u32,
    /// Maximum phase width in µs.
    pub max_phase_width_us: u32,
    /// Maximum interphase gap in µs.
    pub max_interphase_gap_us: u32,
    /// Maximum pulse rate in Hz.
    pub max_pulse_rate_hz: u32,
    /// Maximum pulses per command.
    pub max_pulse_count: u32,
    /// Maximum train duration in µs.
    pub max_train_duration_us: u32,
}

/// Pipeline statistics (mirror of `bnf_core::FirewallStats` plus gate counters).
#[repr(C)]
pub struct BnfStats {
    /// Commands accepted by the firewall.
    pub accepted: u64,
    /// Rejected at framing.
    pub rejected_framing: u64,
    /// Rejected at authentication.
    pub rejected_authentication: u64,
    /// Rejected as replays.
    pub rejected_replay: u64,
    /// Rejected by the physical limiter.
    pub rejected_safety: u64,
    /// Successful handshakes.
    pub handshakes_completed: u64,
    /// Failed handshakes.
    pub handshakes_failed: u64,
    /// Commands that reached the simulated output stage.
    pub delivered_commands: u64,
    /// Pulses that reached the simulated output stage.
    pub delivered_pulses: u64,
    /// Times the output stage was forced open-circuit.
    pub open_circuit_events: u64,
}

/// `fmt::Write` sink into a fixed, NUL-terminated byte buffer. Truncates on a
/// UTF-8 character boundary and always leaves room for the terminator.
struct MessageBuf<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl std::fmt::Write for MessageBuf<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let room = self.buf.len().saturating_sub(1 + self.len);
        let mut n = s.len().min(room);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// Writes `args` into `buf` (NUL-terminated, truncated) and returns the length.
fn write_message(buf: &mut [u8], args: std::fmt::Arguments<'_>) -> usize {
    buf.fill(0);
    if buf.is_empty() {
        return 0;
    }
    let mut w = MessageBuf { buf, len: 0 };
    let _ = w.write_fmt(args);
    w.len
}

/// # Safety
/// `ptr` must be null or valid for reads of `len` elements.
unsafe fn slice<'a, T>(ptr: *const T, len: usize) -> Option<&'a [T]> {
    // SAFETY: non-null is checked; validity for `len` reads is the caller's contract.
    (!ptr.is_null()).then(|| unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// # Safety
/// `ptr` must be null or valid for writes of `len` elements.
unsafe fn slice_mut<'a, T>(ptr: *mut T, len: usize) -> Option<&'a mut [T]> {
    // SAFETY: non-null is checked; validity for `len` writes is the caller's contract.
    (!ptr.is_null()).then(|| unsafe { std::slice::from_raw_parts_mut(ptr, len) })
}

/// Copies a PSK out of a caller buffer into memory that is wiped on drop.
fn psk_from(bytes: &[u8]) -> Zeroizing<Psk> {
    let mut key = Zeroizing::new([0u8; PSK_LEN]);
    key.copy_from_slice(bytes);
    key
}

fn os_trng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

fn elapsed_ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn status(result: Result<(), Rejection>) -> i32 {
    result.map_or_else(|r| i32::from(r.code()), |()| BNF_OK)
}

// ------------------------------------------------------------------ constants

/// ABI version.
#[unsafe(no_mangle)]
pub extern "C" fn bnf_abi_version() -> u32 {
    ABI_VERSION
}

/// Stimulation packet length (68).
#[unsafe(no_mangle)]
pub extern "C" fn bnf_packet_len() -> usize {
    PACKET_LEN
}

/// ML-KEM-768 encapsulation key length (1184).
#[unsafe(no_mangle)]
pub extern "C" fn bnf_encapsulation_key_len() -> usize {
    ENCAPSULATION_KEY_LEN
}

/// ML-KEM-768 ciphertext length (1088).
#[unsafe(no_mangle)]
pub extern "C" fn bnf_ciphertext_len() -> usize {
    CIPHERTEXT_LEN
}

/// Key-confirmation tag length (32).
#[unsafe(no_mangle)]
pub extern "C" fn bnf_confirmation_len() -> usize {
    CONFIRMATION_TAG_LEN
}

/// Electrode-table capacity of the simulated implant.
#[unsafe(no_mangle)]
pub extern "C" fn bnf_max_electrodes() -> usize {
    MAX_ELECTRODES
}

/// Writes the default safety profile into `out`.
///
/// # Safety
/// `out` must be null or valid for one `BnfLimits` write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bnf_default_limits(out: *mut BnfLimits) -> i32 {
    // SAFETY: caller contract.
    let Some(out) = (unsafe { out.as_mut() }) else {
        return BNF_ERR_NULL;
    };
    let l = SafetyLimits::default();
    *out = BnfLimits {
        limit_dq_micro: l.shannon_k.limit_dq_micro(),
        max_charge_density_nc_per_cm2: l.max_charge_density_nc_per_cm2,
        shannon_k_milli: u32::from(l.shannon_k.k_milli()),
        charge_balance_tolerance_ppm: l.charge_balance_tolerance_ppm,
        max_current_ua: l.max_current_ua,
        max_phase_width_us: l.max_phase_width_us,
        max_interphase_gap_us: l.max_interphase_gap_us,
        max_pulse_rate_hz: u32::from(l.max_pulse_rate_hz),
        max_pulse_count: u32::from(l.max_pulse_count),
        max_train_duration_us: l.max_train_duration_us,
    };
    BNF_OK
}

/// Writes the stable name of `code` (e.g. `"REPLAY_DETECTED"`, `0` → `"ACCEPTED"`)
/// as a NUL-terminated string. Returns the name length, `BNF_ERR_UNKNOWN_CODE`
/// for an unknown code, or `BNF_ERR_BUFFER` if `cap` cannot hold name + NUL.
///
/// # Safety
/// `out` must be null or valid for `cap` byte writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bnf_rejection_name(code: u32, out: *mut u8, cap: usize) -> i32 {
    let Some(name) = u16::try_from(code).ok().and_then(rejection_name) else {
        return BNF_ERR_UNKNOWN_CODE;
    };
    // SAFETY: caller contract.
    let Some(out) = (unsafe { slice_mut(out, cap) }) else {
        return BNF_ERR_NULL;
    };
    if cap <= name.len() {
        return BNF_ERR_BUFFER;
    }
    let len = write_message(out, format_args!("{name}"));
    i32::try_from(len).unwrap_or(i32::MAX)
}

// -------------------------------------------------------------------- implant

/// Creates an implant firewall with the default (platinum macro-electrode) limits.
///
/// Returns null if a pointer is null, `count` is 0 or above `MAX_ELECTRODES`,
/// or the electrode table is invalid (zero area, duplicate id).
///
/// # Safety
/// `psk` must point to 32 readable bytes; `ids` and `areas_um2` must each point to
/// `count` readable, properly aligned elements.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bnf_implant_new(
    psk: *const u8,
    ids: *const u16,
    areas_um2: *const u64,
    count: usize,
) -> *mut BnfImplant {
    if count > MAX_ELECTRODES {
        return std::ptr::null_mut();
    }
    // SAFETY: caller contract.
    let (Some(psk), Some(ids), Some(areas)) =
        (unsafe { (slice(psk, PSK_LEN), slice(ids, count), slice(areas_um2, count)) })
    else {
        return std::ptr::null_mut();
    };
    let mut specs = [ElectrodeSpec {
        id: 0,
        geometric_area_um2: 0,
    }; MAX_ELECTRODES];
    for ((spec, &id), &geometric_area_um2) in specs.iter_mut().zip(ids).zip(areas) {
        *spec = ElectrodeSpec { id, geometric_area_um2 };
    }
    let Ok(table) = ElectrodeTable::try_new(&specs[..count]) else {
        return std::ptr::null_mut();
    };
    let psk = psk_from(psk);
    match Firewall::new(*psk, SafetyLimits::default(), table, SimulatedOutputStage::default()) {
        Ok(firewall) => Box::into_raw(Box::new(BnfImplant { firewall })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Frees an implant handle (null is ignored).
///
/// # Safety
/// `implant` must be null or a handle returned by `bnf_implant_new` and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bnf_implant_free(implant: *mut BnfImplant) {
    if !implant.is_null() {
        // SAFETY: caller contract.
        drop(unsafe { Box::from_raw(implant) });
    }
}

/// Generates the implant's ephemeral ML-KEM-768 key pair and writes the
/// encapsulation key (1184 bytes) to `ek_out`.
///
/// # Safety
/// `implant` must be a live handle; `ek_out` must be writable for `ek_out_len`
/// bytes; `elapsed_ns_out` must be null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bnf_implant_begin_handshake(
    implant: *mut BnfImplant,
    ek_out: *mut u8,
    ek_out_len: usize,
    elapsed_ns_out: *mut u64,
) -> i32 {
    // SAFETY: caller contract.
    let Some(implant) = (unsafe { implant.as_mut() }) else {
        return BNF_ERR_NULL;
    };
    if ek_out_len != ENCAPSULATION_KEY_LEN {
        return BNF_ERR_BUFFER;
    }
    // SAFETY: caller contract.
    let Some(out) = (unsafe { slice_mut(ek_out, ek_out_len) }) else {
        return BNF_ERR_NULL;
    };
    let start = Instant::now();
    let ek = implant.firewall.begin_handshake(&mut os_trng());
    let ns = elapsed_ns(start);
    out.copy_from_slice(&ek);
    // SAFETY: caller contract.
    if let Some(t) = unsafe { elapsed_ns_out.as_mut() } {
        *t = ns;
    }
    BNF_OK
}

/// Completes the handshake. Returns 0 on success or a positive rejection code.
///
/// # Safety
/// `implant` must be a live handle; `ct`/`confirm` must be readable for their
/// lengths; `elapsed_ns_out` must be null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bnf_implant_complete_handshake(
    implant: *mut BnfImplant,
    ct: *const u8,
    ct_len: usize,
    confirm: *const u8,
    confirm_len: usize,
    elapsed_ns_out: *mut u64,
) -> i32 {
    // SAFETY: caller contract.
    let (Some(implant), Some(ct), Some(confirm)) =
        (unsafe { (implant.as_mut(), slice(ct, ct_len), slice(confirm, confirm_len)) })
    else {
        return BNF_ERR_NULL;
    };
    let start = Instant::now();
    let result = implant.firewall.complete_handshake(ct, confirm);
    let ns = elapsed_ns(start);
    // SAFETY: caller contract.
    if let Some(t) = unsafe { elapsed_ns_out.as_mut() } {
        *t = ns;
    }
    status(result)
}

/// Drops the implant's active session and pending handshake.
///
/// # Safety
/// `implant` must be null or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bnf_implant_end_session(implant: *mut BnfImplant) -> i32 {
    // SAFETY: caller contract.
    let Some(implant) = (unsafe { implant.as_mut() }) else {
        return BNF_ERR_NULL;
    };
    implant.firewall.end_session();
    BNF_OK
}

fn fill_verdict(v: &mut BnfVerdict, result: Result<bnf_core::Accepted, Rejection>) {
    v.counter = 0;
    v.charge_pc = 0;
    v.density_nc_per_cm2 = 0;
    v.dq_micro = 0;
    match result {
        Ok(accepted) => {
            v.code = 0;
            v.counter = accepted.counter;
            v.charge_pc = accepted.worst_phase.charge_pc;
            v.density_nc_per_cm2 = accepted.worst_phase.density_nc_per_cm2;
            v.dq_micro = accepted.worst_phase.dq_micro;
            write_message(
                &mut v.message,
                format_args!(
                    "accepted: counter {} delivered to electrode {}",
                    accepted.counter, accepted.electrode_id
                ),
            );
        }
        Err(rejection) => {
            v.code = u32::from(rejection.code());
            match rejection {
                Rejection::ReplayDetected { counter, .. } => v.counter = counter,
                Rejection::ShannonLimitExceeded {
                    charge_pc, area_um2, ..
                }
                | Rejection::ChargeDensityExceeded {
                    charge_pc, area_um2, ..
                } => {
                    let phase = assess_phase(charge_pc, area_um2);
                    v.charge_pc = phase.charge_pc;
                    v.density_nc_per_cm2 = phase.density_nc_per_cm2;
                    v.dq_micro = phase.dq_micro;
                }
                _ => {}
            }
            write_message(&mut v.message, format_args!("{rejection}"));
        }
    }
}

/// Runs one packet through the firewall and fills `verdict`.
/// Returns `verdict.code` (0 = accepted) or a negative status on bad arguments.
///
/// # Safety
/// `implant` must be a live handle; `packet` must be readable for `packet_len`
/// bytes; `verdict` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bnf_implant_process(
    implant: *mut BnfImplant,
    packet: *const u8,
    packet_len: usize,
    verdict: *mut BnfVerdict,
) -> i32 {
    // SAFETY: caller contract.
    let (Some(implant), Some(v), Some(packet)) =
        (unsafe { (implant.as_mut(), verdict.as_mut(), slice(packet, packet_len)) })
    else {
        return BNF_ERR_NULL;
    };
    let start = Instant::now();
    let result = implant.firewall.process(packet);
    v.elapsed_ns = elapsed_ns(start);
    v.limit_dq_micro = implant.firewall.limits().shannon_k.limit_dq_micro();
    fill_verdict(v, result);
    i32::try_from(v.code).unwrap_or(i32::MAX)
}

/// Writes the implant's pipeline statistics into `out`.
///
/// # Safety
/// `implant` must be null or a live handle; `out` must be null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bnf_implant_stats(implant: *const BnfImplant, out: *mut BnfStats) -> i32 {
    // SAFETY: caller contract.
    let (Some(implant), Some(out)) = (unsafe { (implant.as_ref(), out.as_mut()) }) else {
        return BNF_ERR_NULL;
    };
    let s = implant.firewall.stats();
    let g = implant.firewall.gate();
    *out = BnfStats {
        accepted: s.accepted,
        rejected_framing: s.rejected_framing,
        rejected_authentication: s.rejected_authentication,
        rejected_replay: s.rejected_replay,
        rejected_safety: s.rejected_safety,
        handshakes_completed: s.handshakes_completed,
        handshakes_failed: s.handshakes_failed,
        delivered_commands: g.delivered_commands,
        delivered_pulses: g.delivered_pulses,
        open_circuit_events: g.open_circuit_events,
    };
    BNF_OK
}

// ----------------------------------------------------------------------- host

/// Performs the host side of the handshake. Writes the ciphertext (1088 bytes)
/// and confirmation tag (32 bytes). Returns null on failure.
///
/// # Safety
/// `psk` must point to 32 readable bytes; `ek` must be readable for `ek_len`
/// bytes; `ct_out`/`confirm_out` must be writable for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bnf_host_establish(
    psk: *const u8,
    ek: *const u8,
    ek_len: usize,
    ct_out: *mut u8,
    ct_out_len: usize,
    confirm_out: *mut u8,
    confirm_out_len: usize,
) -> *mut BnfHost {
    if ct_out_len != CIPHERTEXT_LEN || confirm_out_len != CONFIRMATION_TAG_LEN {
        return std::ptr::null_mut();
    }
    // SAFETY: caller contract.
    let (Some(psk), Some(ek), Some(ct_out), Some(confirm_out)) = (unsafe {
        (
            slice(psk, PSK_LEN),
            slice(ek, ek_len),
            slice_mut(ct_out, ct_out_len),
            slice_mut(confirm_out, confirm_out_len),
        )
    }) else {
        return std::ptr::null_mut();
    };
    let psk = psk_from(psk);
    let Ok((session, response)) = HostSession::establish(&psk, ek, &mut os_trng()) else {
        return std::ptr::null_mut();
    };
    ct_out.copy_from_slice(&response.ciphertext);
    confirm_out.copy_from_slice(&response.confirmation);
    Box::into_raw(Box::new(BnfHost { session }))
}

/// Frees a host handle (null is ignored).
///
/// # Safety
/// `host` must be null or a handle returned by `bnf_host_establish` and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bnf_host_free(host: *mut BnfHost) {
    if !host.is_null() {
        // SAFETY: caller contract.
        drop(unsafe { Box::from_raw(host) });
    }
}

/// Signs a stimulation command with the next counter and writes the 68-byte packet.
/// Returns 0, `COUNTER_EXHAUSTED` (302) or a negative status.
///
/// # Safety
/// `host` must be a live handle; `packet_out` must be writable for `packet_out_len` bytes.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bnf_host_sign(
    host: *mut BnfHost,
    electrode_id: u16,
    cathodic_current_ua: u32,
    cathodic_width_us: u32,
    interphase_gap_us: u32,
    anodic_current_ua: u32,
    anodic_width_us: u32,
    pulse_rate_hz: u16,
    pulse_count: u16,
    packet_out: *mut u8,
    packet_out_len: usize,
) -> i32 {
    // SAFETY: caller contract.
    let Some(host) = (unsafe { host.as_mut() }) else {
        return BNF_ERR_NULL;
    };
    if packet_out_len != PACKET_LEN {
        return BNF_ERR_BUFFER;
    }
    // SAFETY: caller contract.
    let Some(out) = (unsafe { slice_mut(packet_out, packet_out_len) }) else {
        return BNF_ERR_NULL;
    };
    let cmd = StimulationCommand {
        electrode_id,
        pulse: BiphasicPulse {
            cathodic_current_ua,
            cathodic_width_us,
            interphase_gap_us,
            anodic_current_ua,
            anodic_width_us,
        },
        pulse_rate_hz,
        pulse_count,
    };
    status(host.session.sign(&cmd).map(|packet| out.copy_from_slice(&packet)))
}

/// Counter used by the most recent successful `bnf_host_sign` call.
///
/// # Safety
/// `host` must be null or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bnf_host_last_counter(host: *const BnfHost) -> u64 {
    // SAFETY: caller contract.
    unsafe { host.as_ref() }.map_or(0, |h| h.session.last_counter())
}

#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks)]
mod tests {
    use super::*;
    use std::ptr::{null, null_mut};

    const PSK: [u8; 32] = [7u8; 32];

    struct Pair {
        imp: *mut BnfImplant,
        host: *mut BnfHost,
    }

    impl Drop for Pair {
        fn drop(&mut self) {
            unsafe {
                bnf_host_free(self.host);
                bnf_implant_free(self.imp);
            }
        }
    }

    fn implant() -> *mut BnfImplant {
        let ids = [1u16, 2];
        let areas = [4_000_000u64, 25_000_000];
        let imp = unsafe { bnf_implant_new(PSK.as_ptr(), ids.as_ptr(), areas.as_ptr(), 2) };
        assert!(!imp.is_null());
        imp
    }

    fn pair() -> Pair {
        let imp = implant();
        let mut ek = [0u8; ENCAPSULATION_KEY_LEN];
        let mut ns = 0u64;
        unsafe {
            assert_eq!(
                bnf_implant_begin_handshake(imp, ek.as_mut_ptr(), ek.len(), &raw mut ns),
                0
            );
            let mut ct = [0u8; CIPHERTEXT_LEN];
            let mut cf = [0u8; CONFIRMATION_TAG_LEN];
            let host = bnf_host_establish(
                PSK.as_ptr(),
                ek.as_ptr(),
                ek.len(),
                ct.as_mut_ptr(),
                ct.len(),
                cf.as_mut_ptr(),
                cf.len(),
            );
            assert!(!host.is_null());
            assert_eq!(
                bnf_implant_complete_handshake(imp, ct.as_ptr(), ct.len(), cf.as_ptr(), cf.len(), null_mut()),
                0
            );
            Pair { imp, host }
        }
    }

    fn sign(p: &Pair, electrode: u16, ua: u32, us: u32) -> [u8; PACKET_LEN] {
        let mut pkt = [0u8; PACKET_LEN];
        let rc = unsafe {
            bnf_host_sign(
                p.host,
                electrode,
                ua,
                us,
                50,
                ua,
                us,
                100,
                1,
                pkt.as_mut_ptr(),
                pkt.len(),
            )
        };
        assert_eq!(rc, 0);
        pkt
    }

    fn process(p: &Pair, pkt: &[u8]) -> BnfVerdict {
        let mut v: BnfVerdict = unsafe { std::mem::zeroed() };
        let rc = unsafe { bnf_implant_process(p.imp, pkt.as_ptr(), pkt.len(), &raw mut v) };
        assert_eq!(rc, i32::try_from(v.code).unwrap());
        v
    }

    fn message(v: &BnfVerdict) -> String {
        let end = v.message.iter().position(|&b| b == 0).unwrap();
        String::from_utf8(v.message[..end].to_vec()).unwrap()
    }

    fn stats(p: &Pair) -> BnfStats {
        let mut s: BnfStats = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { bnf_implant_stats(p.imp, &raw mut s) }, 0);
        s
    }

    #[test]
    fn constants() {
        assert_eq!(bnf_abi_version(), ABI_VERSION);
        assert_eq!(bnf_packet_len(), 68);
        assert_eq!(bnf_encapsulation_key_len(), 1184);
        assert_eq!(bnf_ciphertext_len(), 1088);
        assert_eq!(bnf_confirmation_len(), 32);
        assert_eq!(bnf_max_electrodes(), MAX_ELECTRODES);
    }

    #[test]
    fn default_limits_mirror_the_core() {
        let mut l: BnfLimits = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { bnf_default_limits(&raw mut l) }, 0);
        let core = SafetyLimits::default();
        assert_eq!(l.limit_dq_micro, core.shannon_k.limit_dq_micro());
        assert_eq!(l.shannon_k_milli, 1_750);
        assert_eq!(l.max_charge_density_nc_per_cm2, 30_000);
        assert_eq!(l.max_train_duration_us, core.max_train_duration_us);
        assert_eq!(unsafe { bnf_default_limits(null_mut()) }, BNF_ERR_NULL);
    }

    #[test]
    fn rejection_names() {
        let mut buf = [0xFFu8; 64];
        let n = unsafe { bnf_rejection_name(301, buf.as_mut_ptr(), buf.len()) };
        assert_eq!(n, 15);
        assert_eq!(&buf[..16], b"REPLAY_DETECTED\0");
        assert_eq!(unsafe { bnf_rejection_name(0, buf.as_mut_ptr(), buf.len()) }, 8);
        assert_eq!(
            unsafe { bnf_rejection_name(999, buf.as_mut_ptr(), buf.len()) },
            BNF_ERR_UNKNOWN_CODE
        );
        assert_eq!(
            unsafe { bnf_rejection_name(u32::MAX, buf.as_mut_ptr(), buf.len()) },
            BNF_ERR_UNKNOWN_CODE
        );
        assert_eq!(unsafe { bnf_rejection_name(301, buf.as_mut_ptr(), 15) }, BNF_ERR_BUFFER);
        assert_eq!(unsafe { bnf_rejection_name(301, null_mut(), 64) }, BNF_ERR_NULL);
        for (code, name) in bnf_core::REJECTION_CODES {
            let n = unsafe { bnf_rejection_name(u32::from(code), buf.as_mut_ptr(), buf.len()) };
            assert_eq!(usize::try_from(n).unwrap(), name.len());
        }
    }

    #[test]
    fn message_buffer_truncates_on_char_boundary() {
        let mut buf = [0xFFu8; 6];
        // "aé…" = a(1) é(2) …(3): 5 bytes of room → "aé" (3 bytes), not a split "…"
        assert_eq!(write_message(&mut buf, format_args!("aé…")), 3);
        assert_eq!(&buf, b"a\xc3\xa9\0\0\0");
        let mut empty: [u8; 0] = [];
        assert_eq!(write_message(&mut empty, format_args!("x")), 0);
        let mut one = [0xFFu8; 1];
        assert_eq!(write_message(&mut one, format_args!("xyz")), 0);
        assert_eq!(one, [0]);
    }

    #[test]
    fn full_round_trip_through_the_c_abi() {
        let p = pair();
        let pkt = sign(&p, 1, 2_000, 200);
        let v = process(&p, &pkt);
        assert_eq!(v.code, 0);
        assert_eq!(v.counter, 1);
        assert_eq!(v.charge_pc, 400_000);
        assert_eq!(v.density_nc_per_cm2, 10_000);
        assert_eq!(v.dq_micro, 4_000_000);
        assert!(message(&v).starts_with("accepted: counter 1"));
        assert_eq!(unsafe { bnf_host_last_counter(p.host) }, 1);

        let replay = process(&p, &pkt);
        assert_eq!(replay.code, 301);
        assert_eq!(replay.counter, 1);
        assert!(message(&replay).starts_with("replay detected"));

        let s = stats(&p);
        assert_eq!(
            (s.accepted, s.rejected_replay, s.delivered_commands, s.delivered_pulses),
            (1, 1, 1, 1)
        );
        assert_eq!(s.handshakes_completed, 1);
        assert_eq!(s.open_circuit_events, 2); // construction + one rejection
    }

    #[test]
    fn physics_fields_are_reported_for_safety_rejections() {
        let p = pair();
        let shannon = process(&p, &sign(&p, 1, 10_000, 1_000));
        assert_eq!(shannon.code, 406);
        assert_eq!(
            (shannon.charge_pc, shannon.density_nc_per_cm2, shannon.dq_micro),
            (10_000_000, 250_000, 2_500_000_000)
        );
        assert_eq!(shannon.limit_dq_micro, 56_234_130);
        let density = process(&p, &sign(&p, 1, 2_600, 500));
        assert_eq!(density.code, 407);
        assert_eq!(density.density_nc_per_cm2, 32_500);
        assert_eq!(density.dq_micro, 42_250_000);
        // Electrode 2 (0.25 cm²) accepts what electrode 1 rejects.
        assert_eq!(process(&p, &sign(&p, 2, 2_600, 500)).code, 0);
    }

    #[test]
    fn handshake_failures_return_codes() {
        let imp = implant();
        let mut ek = [0u8; ENCAPSULATION_KEY_LEN];
        let (mut ct, mut cf) = ([0u8; CIPHERTEXT_LEN], [0u8; CONFIRMATION_TAG_LEN]);
        unsafe {
            assert_eq!(
                bnf_implant_complete_handshake(imp, ct.as_ptr(), ct.len(), cf.as_ptr(), cf.len(), null_mut()),
                202
            );
            assert_eq!(
                bnf_implant_begin_handshake(imp, ek.as_mut_ptr(), ek.len(), null_mut()),
                0
            );
            let rogue = bnf_host_establish(
                [9u8; 32].as_ptr(),
                ek.as_ptr(),
                ek.len(),
                ct.as_mut_ptr(),
                ct.len(),
                cf.as_mut_ptr(),
                cf.len(),
            );
            assert!(!rogue.is_null());
            assert_eq!(
                bnf_implant_complete_handshake(imp, ct.as_ptr(), ct.len(), cf.as_ptr(), cf.len(), null_mut()),
                203
            );
            let mut s: BnfStats = std::mem::zeroed();
            bnf_implant_stats(imp, &raw mut s);
            assert_eq!(s.handshakes_failed, 1);
            bnf_host_free(rogue);
            bnf_implant_free(imp);
        }
    }

    #[test]
    fn end_session_drops_the_session() {
        let p = pair();
        assert_eq!(unsafe { bnf_implant_end_session(p.imp) }, 0);
        assert_eq!(process(&p, &sign(&p, 1, 2_000, 200)).code, 201);
        assert_eq!(unsafe { bnf_implant_end_session(null_mut()) }, BNF_ERR_NULL);
    }

    #[test]
    fn invalid_arguments_are_rejected() {
        let ids = [1u16, 1];
        let areas = [10u64, 10];
        let zero = [0u64];
        unsafe {
            assert!(bnf_implant_new(null(), ids.as_ptr(), areas.as_ptr(), 1).is_null());
            assert!(bnf_implant_new(PSK.as_ptr(), null(), areas.as_ptr(), 1).is_null());
            assert!(bnf_implant_new(PSK.as_ptr(), ids.as_ptr(), areas.as_ptr(), 0).is_null());
            assert!(bnf_implant_new(PSK.as_ptr(), ids.as_ptr(), areas.as_ptr(), 2).is_null());
            assert!(bnf_implant_new(PSK.as_ptr(), ids.as_ptr(), zero.as_ptr(), 1).is_null());
            assert!(bnf_implant_new(PSK.as_ptr(), ids.as_ptr(), areas.as_ptr(), MAX_ELECTRODES + 1).is_null());

            let mut v: BnfVerdict = std::mem::zeroed();
            assert_eq!(bnf_implant_process(null_mut(), null(), 0, &raw mut v), BNF_ERR_NULL);
            let p = pair();
            assert_eq!(bnf_implant_process(p.imp, null(), 0, &raw mut v), BNF_ERR_NULL);
            assert_eq!(bnf_implant_process(p.imp, [0u8].as_ptr(), 1, null_mut()), BNF_ERR_NULL);
            let mut ek = [0u8; 10];
            assert_eq!(
                bnf_implant_begin_handshake(p.imp, ek.as_mut_ptr(), ek.len(), null_mut()),
                BNF_ERR_BUFFER
            );
            assert_eq!(
                bnf_implant_begin_handshake(null_mut(), ek.as_mut_ptr(), 1184, null_mut()),
                BNF_ERR_NULL
            );
            let mut pkt = [0u8; 10];
            assert_eq!(
                bnf_host_sign(p.host, 1, 1, 1, 1, 1, 1, 1, 1, pkt.as_mut_ptr(), pkt.len()),
                BNF_ERR_BUFFER
            );
            assert_eq!(
                bnf_host_sign(null_mut(), 1, 1, 1, 1, 1, 1, 1, 1, pkt.as_mut_ptr(), 68),
                BNF_ERR_NULL
            );
            let (mut ct, mut cf) = ([0u8; CIPHERTEXT_LEN], [0u8; CONFIRMATION_TAG_LEN]);
            assert!(
                bnf_host_establish(
                    PSK.as_ptr(),
                    ek.as_ptr(),
                    10,
                    ct.as_mut_ptr(),
                    1088,
                    cf.as_mut_ptr(),
                    32
                )
                .is_null()
            );
            assert!(
                bnf_host_establish(PSK.as_ptr(), ek.as_ptr(), 10, ct.as_mut_ptr(), 1, cf.as_mut_ptr(), 32).is_null()
            );
            assert_eq!(bnf_host_last_counter(null()), 0);
            assert_eq!(bnf_implant_stats(null(), null_mut()), BNF_ERR_NULL);
            bnf_implant_free(null_mut());
            bnf_host_free(null_mut());
        }
    }
}
