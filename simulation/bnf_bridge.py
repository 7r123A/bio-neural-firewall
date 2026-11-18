"""ctypes bridge to the Rust Bio-Neural Firewall kernel (crates/bnf-ffi).

The simulation drives the *compiled Rust kernel*; nothing security-relevant is
re-implemented in Python. Python only plays the roles of the BCI host, the
attacker and the test oracle.
"""

from __future__ import annotations

import ctypes
import enum
import math
import os
import sys
import time
from dataclasses import dataclass
from functools import cache
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MESSAGE_LEN = 256
EXPECTED_ABI_VERSION = 2


class Code(enum.IntEnum):
    """Stable verdict codes. Names and values are verified against the Rust
    kernel at load time (see ``load_library``), so they cannot drift."""

    ACCEPTED = 0
    MALFORMED_PACKET = 101
    UNSUPPORTED_VERSION = 102
    UNKNOWN_OPCODE = 103
    NO_ACTIVE_SESSION = 201
    HANDSHAKE_NOT_STARTED = 202
    HANDSHAKE_FAILED = 203
    AUTHENTICATION_FAILED = 204
    REPLAY_DETECTED = 301
    COUNTER_EXHAUSTED = 302
    UNKNOWN_ELECTRODE = 401
    ENVELOPE_EXCEEDED = 402
    PULSE_TIMING_INVALID = 403
    MONOPHASIC_PULSE = 404
    CHARGE_IMBALANCE = 405
    SHANNON_LIMIT_EXCEEDED = 406
    CHARGE_DENSITY_EXCEEDED = 407


def code_name(code: int) -> str:
    """Stable name of a verdict code, or ``CODE_<n>`` if unknown."""
    try:
        return Code(code).name
    except ValueError:
        return f"CODE_{code}"


class BnfError(RuntimeError):
    """Raised when the native library is missing or a call fails unexpectedly."""


class _Verdict(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint32),
        ("counter", ctypes.c_uint64),
        ("charge_pc", ctypes.c_uint64),
        ("density_nc_per_cm2", ctypes.c_uint64),
        ("dq_micro", ctypes.c_uint64),
        ("limit_dq_micro", ctypes.c_uint64),
        ("elapsed_ns", ctypes.c_uint64),
        ("message", ctypes.c_char * MESSAGE_LEN),
    ]


class _Limits(ctypes.Structure):
    _fields_ = [
        ("limit_dq_micro", ctypes.c_uint64),
        ("max_charge_density_nc_per_cm2", ctypes.c_uint64),
        ("shannon_k_milli", ctypes.c_uint32),
        ("charge_balance_tolerance_ppm", ctypes.c_uint32),
        ("max_current_ua", ctypes.c_uint32),
        ("max_phase_width_us", ctypes.c_uint32),
        ("max_interphase_gap_us", ctypes.c_uint32),
        ("max_pulse_rate_hz", ctypes.c_uint32),
        ("max_pulse_count", ctypes.c_uint32),
        ("max_train_duration_us", ctypes.c_uint32),
    ]


class _Stats(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_uint64)
        for name in (
            "accepted",
            "rejected_framing",
            "rejected_authentication",
            "rejected_replay",
            "rejected_safety",
            "handshakes_completed",
            "handshakes_failed",
            "delivered_commands",
            "delivered_pulses",
            "open_circuit_events",
        )
    ]


def _to_dict(raw: ctypes.Structure) -> dict[str, int]:
    return {name: getattr(raw, name) for name, _ in raw._fields_}


@dataclass(frozen=True)
class Limits:
    """Default safety profile reported by the kernel."""

    limit_dq_micro: int
    max_charge_density_nc_per_cm2: int
    shannon_k_milli: int
    charge_balance_tolerance_ppm: int
    max_current_ua: int
    max_phase_width_us: int
    max_interphase_gap_us: int
    max_pulse_rate_hz: int
    max_pulse_count: int
    max_train_duration_us: int

    @property
    def shannon_k(self) -> float:
        return self.shannon_k_milli / 1000

    @property
    def max_density_uc_per_cm2(self) -> float:
        return self.max_charge_density_nc_per_cm2 / 1000

    @property
    def balance_tolerance_percent(self) -> float:
        return self.charge_balance_tolerance_ppm / 10_000


@dataclass(frozen=True)
class Stats:
    """Pipeline and output-stage counters of one implant."""

    accepted: int
    rejected_framing: int
    rejected_authentication: int
    rejected_replay: int
    rejected_safety: int
    handshakes_completed: int
    handshakes_failed: int
    delivered_commands: int
    delivered_pulses: int
    open_circuit_events: int

    @property
    def rejected(self) -> int:
        return self.rejected_framing + self.rejected_authentication + self.rejected_replay + self.rejected_safety


@dataclass(frozen=True)
class Verdict:
    """Outcome of one packet, as reported by the Rust kernel."""

    code: int
    counter: int
    charge_pc: int
    density_nc_per_cm2: int
    dq_micro: int
    limit_dq_micro: int
    core_ns: int
    round_trip_ns: int
    message: str

    @property
    def accepted(self) -> bool:
        return self.code == Code.ACCEPTED

    @property
    def name(self) -> str:
        return code_name(self.code)

    @property
    def charge_uc(self) -> float:
        return self.charge_pc / 1e6

    @property
    def density_uc_per_cm2(self) -> float:
        return self.density_nc_per_cm2 / 1e3

    @property
    def shannon_k(self) -> float | None:
        """k = log10(D·Q) of the worst phase, or None if not computed."""
        if self.dq_micro == 0:
            return None
        return math.log10(self.dq_micro / 1e6)

    @property
    def core_us(self) -> float:
        return self.core_ns / 1e3

    @property
    def round_trip_us(self) -> float:
        return self.round_trip_ns / 1e3


def default_library_path() -> Path:
    """Platform-specific location of the release build of ``bnf-ffi``."""
    if sys.platform.startswith("win"):
        name = "bnf_ffi.dll"
    elif sys.platform == "darwin":
        name = "libbnf_ffi.dylib"
    else:
        name = "libbnf_ffi.so"
    return REPO_ROOT / "target" / "release" / name


_U8P = ctypes.POINTER(ctypes.c_uint8)
_U16P = ctypes.POINTER(ctypes.c_uint16)
_U64P = ctypes.POINTER(ctypes.c_uint64)
_SZ = ctypes.c_size_t
_VP = ctypes.c_void_p
_I32 = ctypes.c_int32

_SIGNATURES: dict[str, tuple[list[object], object]] = {
    "bnf_abi_version": ([], ctypes.c_uint32),
    "bnf_packet_len": ([], _SZ),
    "bnf_encapsulation_key_len": ([], _SZ),
    "bnf_ciphertext_len": ([], _SZ),
    "bnf_confirmation_len": ([], _SZ),
    "bnf_max_electrodes": ([], _SZ),
    "bnf_default_limits": ([ctypes.POINTER(_Limits)], _I32),
    "bnf_rejection_name": ([ctypes.c_uint32, _U8P, _SZ], _I32),
    "bnf_implant_new": ([_U8P, _U16P, _U64P, _SZ], _VP),
    "bnf_implant_free": ([_VP], None),
    "bnf_implant_begin_handshake": ([_VP, _U8P, _SZ, _U64P], _I32),
    "bnf_implant_complete_handshake": ([_VP, _U8P, _SZ, _U8P, _SZ, _U64P], _I32),
    "bnf_implant_end_session": ([_VP], _I32),
    "bnf_implant_process": ([_VP, _U8P, _SZ, ctypes.POINTER(_Verdict)], _I32),
    "bnf_implant_stats": ([_VP, ctypes.POINTER(_Stats)], _I32),
    "bnf_host_establish": ([_U8P, _U8P, _SZ, _U8P, _SZ, _U8P, _SZ], _VP),
    "bnf_host_free": ([_VP], None),
    "bnf_host_sign": (
        [_VP, ctypes.c_uint16] + [ctypes.c_uint32] * 5 + [ctypes.c_uint16, ctypes.c_uint16, _U8P, _SZ],
        _I32,
    ),
    "bnf_host_last_counter": ([_VP], ctypes.c_uint64),
}


def native_rejection_name(lib: ctypes.CDLL, code: int) -> str | None:
    """Name of ``code`` as defined by the Rust kernel, or None if unknown."""
    buf = (ctypes.c_uint8 * 64)()
    n = lib.bnf_rejection_name(code, _ptr(buf), len(buf))
    return bytes(buf[:n]).decode("ascii") if n >= 0 else None


@cache
def _load_cached(path: str) -> ctypes.CDLL:
    lib = ctypes.CDLL(path)
    for name, (argtypes, restype) in _SIGNATURES.items():
        fn = getattr(lib, name)
        fn.argtypes = argtypes
        fn.restype = restype

    version = lib.bnf_abi_version()
    if version != EXPECTED_ABI_VERSION:
        raise BnfError(f"ABI mismatch: library v{version}, bridge expects v{EXPECTED_ABI_VERSION}")
    for code in Code:
        native = native_rejection_name(lib, code.value)
        if native != code.name:
            raise BnfError(f"code table drift: Python {code.name}={code.value}, Rust says {native!r}")
    return lib


def load_library(path: str | os.PathLike[str] | None = None) -> ctypes.CDLL:
    """Loads and validates the native kernel.

    Search order: explicit ``path``, ``$BNF_FFI_LIB``, ``target/release``.
    """
    candidate = Path(path or os.environ.get("BNF_FFI_LIB") or default_library_path()).resolve()
    if not candidate.is_file():
        raise BnfError(
            f"native library not found at '{candidate}'. Build it first with: cargo build --release -p bnf-ffi"
        )
    return _load_cached(str(candidate))


def default_limits(lib: ctypes.CDLL) -> Limits:
    raw = _Limits()
    if lib.bnf_default_limits(ctypes.byref(raw)) != 0:
        raise BnfError("bnf_default_limits failed")
    return Limits(**_to_dict(raw))


def _buf(data: bytes) -> ctypes.Array:
    return (ctypes.c_uint8 * max(1, len(data))).from_buffer_copy(data.ljust(1, b"\0"))


def _ptr(buf: ctypes.Array) -> ctypes._Pointer:
    return ctypes.cast(buf, _U8P)


class Implant:
    """The implanted firewall (Rust kernel + simulated open-circuit output stage)."""

    def __init__(self, lib: ctypes.CDLL, psk: bytes, electrodes: dict[int, int]) -> None:
        if len(psk) != 32:
            raise ValueError("PSK must be 32 bytes")
        self._lib = lib
        self._h: int | None = None
        ids = (ctypes.c_uint16 * max(1, len(electrodes)))(*electrodes.keys())
        areas = (ctypes.c_uint64 * max(1, len(electrodes)))(*electrodes.values())
        handle = lib.bnf_implant_new(_ptr(_buf(psk)), ids, areas, len(electrodes))
        if not handle:
            raise BnfError("bnf_implant_new failed (empty, oversized or invalid electrode table)")
        self._h = handle

    def close(self) -> None:
        if self._h:
            self._lib.bnf_implant_free(self._h)
            self._h = None

    def __enter__(self) -> Implant:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def begin_handshake(self) -> tuple[bytes, int]:
        n = self._lib.bnf_encapsulation_key_len()
        out = (ctypes.c_uint8 * n)()
        ns = ctypes.c_uint64(0)
        rc = self._lib.bnf_implant_begin_handshake(self._h, _ptr(out), n, ctypes.byref(ns))
        if rc != 0:
            raise BnfError(f"begin_handshake failed with status {rc}")
        return bytes(out), ns.value

    def complete_handshake(self, ciphertext: bytes, confirmation: bytes) -> tuple[int, int]:
        """Returns (code, elapsed_ns); code 0 means the session is active."""
        ns = ctypes.c_uint64(0)
        rc = self._lib.bnf_implant_complete_handshake(
            self._h,
            _ptr(_buf(ciphertext)),
            len(ciphertext),
            _ptr(_buf(confirmation)),
            len(confirmation),
            ctypes.byref(ns),
        )
        return rc, ns.value

    def end_session(self) -> None:
        if self._lib.bnf_implant_end_session(self._h) != 0:
            raise BnfError("bnf_implant_end_session failed")

    def process(self, packet: bytes) -> Verdict:
        pkt = _buf(packet)
        raw = _Verdict()
        t0 = time.perf_counter_ns()
        rc = self._lib.bnf_implant_process(self._h, _ptr(pkt), len(packet), ctypes.byref(raw))
        t1 = time.perf_counter_ns()
        if rc < 0:
            raise BnfError(f"bnf_implant_process failed with status {rc}")
        return Verdict(
            code=raw.code,
            counter=raw.counter,
            charge_pc=raw.charge_pc,
            density_nc_per_cm2=raw.density_nc_per_cm2,
            dq_micro=raw.dq_micro,
            limit_dq_micro=raw.limit_dq_micro,
            core_ns=raw.elapsed_ns,
            round_trip_ns=t1 - t0,
            message=raw.message.decode("utf-8", "replace"),
        )

    def stats(self) -> Stats:
        raw = _Stats()
        if self._lib.bnf_implant_stats(self._h, ctypes.byref(raw)) != 0:
            raise BnfError("bnf_implant_stats failed")
        return Stats(**_to_dict(raw))

    @property
    def delivered_commands(self) -> int:
        return self.stats().delivered_commands


class Host:
    """The legitimate BCI computer holding the provisioning PSK."""

    def __init__(self, lib: ctypes.CDLL, psk: bytes, encapsulation_key: bytes) -> None:
        if len(psk) != 32:
            raise ValueError("PSK must be 32 bytes")
        self._lib = lib
        self._h: int | None = None
        ct = (ctypes.c_uint8 * lib.bnf_ciphertext_len())()
        cf = (ctypes.c_uint8 * lib.bnf_confirmation_len())()
        handle = lib.bnf_host_establish(
            _ptr(_buf(psk)),
            _ptr(_buf(encapsulation_key)),
            len(encapsulation_key),
            _ptr(ct),
            len(ct),
            _ptr(cf),
            len(cf),
        )
        if not handle:
            raise BnfError("bnf_host_establish failed (invalid encapsulation key?)")
        self._h = handle
        self.ciphertext = bytes(ct)
        self.confirmation = bytes(cf)

    def close(self) -> None:
        if self._h:
            self._lib.bnf_host_free(self._h)
            self._h = None

    def __enter__(self) -> Host:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def sign(
        self,
        electrode_id: int,
        cathodic_ua: int,
        cathodic_us: int,
        anodic_ua: int | None = None,
        anodic_us: int | None = None,
        interphase_gap_us: int = 50,
        rate_hz: int = 100,
        count: int = 1,
    ) -> bytes:
        """Signs a command. The anodic phase defaults to a mirror of the cathodic phase."""
        anodic_ua = cathodic_ua if anodic_ua is None else anodic_ua
        anodic_us = cathodic_us if anodic_us is None else anodic_us
        n = self._lib.bnf_packet_len()
        out = (ctypes.c_uint8 * n)()
        rc = self._lib.bnf_host_sign(
            self._h,
            electrode_id,
            cathodic_ua,
            cathodic_us,
            interphase_gap_us,
            anodic_ua,
            anodic_us,
            rate_hz,
            count,
            _ptr(out),
            n,
        )
        if rc != 0:
            raise BnfError(f"bnf_host_sign failed with status {rc}")
        return bytes(out)

    @property
    def last_counter(self) -> int:
        return self._lib.bnf_host_last_counter(self._h)


def open_session(lib: ctypes.CDLL, implant: Implant, psk: bytes) -> tuple[Host, int, int]:
    """Runs a full handshake. Returns (host, keygen_ns, completion_ns)."""
    ek, keygen_ns = implant.begin_handshake()
    host = Host(lib, psk, ek)
    rc, completion_ns = implant.complete_handshake(host.ciphertext, host.confirmation)
    if rc != Code.ACCEPTED:
        host.close()
        raise BnfError(f"handshake failed with code {rc}")
    return host, keygen_ns, completion_ns
