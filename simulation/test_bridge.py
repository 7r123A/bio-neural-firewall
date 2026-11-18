"""Kernel behaviour tests through the C ABI (stdlib unittest only).

Run from the repository root after `cargo build --release -p bnf-ffi`:

    python -m unittest discover -s simulation -v
"""

from __future__ import annotations

import ctypes
import random
import secrets
import struct
import sys
import unittest
from decimal import Decimal, getcontext
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bnf_bridge import (  # noqa: E402
    BnfError,
    Code,
    Host,
    Implant,
    code_name,
    default_limits,
    load_library,
    native_rejection_name,
    open_session,
)
from run_simulation import BODY_FORMAT, ELECTRODES, LATENCY_BUDGET_US, PACKET_LEN, forge_packet  # noqa: E402

getcontext().prec = 50
SHANNON_LIMIT = Decimal(10) ** Decimal("1.75")  # exact reference, 10^1.75
DENSITY_LIMIT = Decimal(30)  # µC/cm²

ECOG = 1  # electrode id, 0.04 cm²
LARGE = 9  # electrode id, 0.25 cm²
AREAS = {**ELECTRODES, LARGE: 25_000_000}


class KernelTestCase(unittest.TestCase):
    """Shared fixtures: a loaded library and a fresh implant + session per test."""

    lib: ctypes.CDLL

    @classmethod
    def setUpClass(cls) -> None:
        cls.lib = load_library()

    def new_implant(self, psk: bytes | None = None, electrodes: dict[int, int] | None = None) -> Implant:
        implant = Implant(self.lib, psk or secrets.token_bytes(32), electrodes or AREAS)
        self.addCleanup(implant.close)
        return implant

    def session(self, electrodes: dict[int, int] | None = None) -> tuple[Implant, Host, bytes]:
        psk = secrets.token_bytes(32)
        implant = self.new_implant(psk, electrodes)
        host, _, _ = open_session(self.lib, implant, psk)
        self.addCleanup(host.close)
        return implant, host, psk

    def assertCode(self, implant: Implant, packet: bytes, code: Code) -> None:  # noqa: N802
        verdict = implant.process(packet)
        self.assertEqual(verdict.code, code, f"{verdict.name}: {verdict.message}")


class LibraryTests(KernelTestCase):
    def test_constants(self) -> None:
        self.assertEqual(self.lib.bnf_abi_version(), 2)
        self.assertEqual(self.lib.bnf_packet_len(), PACKET_LEN)
        self.assertEqual(self.lib.bnf_encapsulation_key_len(), 1184)
        self.assertEqual(self.lib.bnf_ciphertext_len(), 1088)
        self.assertEqual(self.lib.bnf_confirmation_len(), 32)
        self.assertEqual(self.lib.bnf_max_electrodes(), 64)
        self.assertEqual(struct.calcsize(BODY_FORMAT) + 32, PACKET_LEN)

    def test_default_limits(self) -> None:
        limits = default_limits(self.lib)
        self.assertEqual(limits.shannon_k_milli, 1750)
        self.assertAlmostEqual(limits.shannon_k, 1.75)
        self.assertEqual(limits.limit_dq_micro, 56_234_130)
        self.assertEqual(limits.max_charge_density_nc_per_cm2, 30_000)
        self.assertEqual(limits.max_density_uc_per_cm2, 30.0)
        self.assertEqual(limits.charge_balance_tolerance_ppm, 10_000)
        self.assertEqual(limits.balance_tolerance_percent, 1.0)
        self.assertEqual(
            (limits.max_current_ua, limits.max_phase_width_us, limits.max_interphase_gap_us),
            (10_000, 1_000, 200),
        )
        self.assertEqual((limits.max_pulse_rate_hz, limits.max_pulse_count), (300, 1_000))
        self.assertEqual(limits.max_train_duration_us, 1_000_000)

    def test_python_code_table_matches_rust(self) -> None:
        for code in Code:
            self.assertEqual(native_rejection_name(self.lib, code.value), code.name)
        for unknown in (1, 100, 205, 999, 2**32 - 1):
            self.assertIsNone(native_rejection_name(self.lib, unknown))
        self.assertEqual(code_name(301), "REPLAY_DETECTED")
        self.assertEqual(code_name(555), "CODE_555")

    def test_missing_library_raises(self) -> None:
        with self.assertRaises(BnfError):
            load_library(Path(__file__).with_name("does-not-exist.dll"))

    def test_library_is_loaded_once(self) -> None:
        self.assertIs(load_library(), self.lib)


class ConstructionTests(KernelTestCase):
    def test_psk_length_is_checked(self) -> None:
        with self.assertRaises(ValueError):
            Implant(self.lib, b"short", ELECTRODES)
        ek, _ = self.new_implant().begin_handshake()
        with self.assertRaises(ValueError):
            Host(self.lib, b"short", ek)

    def test_invalid_electrode_tables_are_refused(self) -> None:
        for table in ({}, {1: 0}, {i: 1 for i in range(65)}):
            with self.assertRaises(BnfError, msg=str(table)[:40]):
                Implant(self.lib, secrets.token_bytes(32), table)

    def test_maximum_table_size_is_accepted(self) -> None:
        self.new_implant(electrodes={i: 1_000 for i in range(64)})

    def test_invalid_encapsulation_keys_are_refused(self) -> None:
        for ek in (b"", b"\x00" * 1183, b"\x00" * 1185):
            with self.assertRaises(BnfError):
                Host(self.lib, secrets.token_bytes(32), ek)

    def test_fresh_implant_is_open_circuit_with_no_session(self) -> None:
        implant = self.new_implant()
        stats = implant.stats()
        self.assertEqual(stats.open_circuit_events, 1)
        self.assertEqual(stats.rejected, 0)
        with Host(self.lib, secrets.token_bytes(32), implant.begin_handshake()[0]) as stranger:
            self.assertCode(implant, stranger.sign(ECOG, 2_000, 200), Code.NO_ACTIVE_SESSION)


class HandshakeTests(KernelTestCase):
    def test_legitimate_handshake(self) -> None:
        implant, host, _ = self.session()
        self.assertEqual(implant.stats().handshakes_completed, 1)
        self.assertEqual(host.last_counter, 0)

    def test_wrong_psk_is_rejected(self) -> None:
        implant = self.new_implant()
        ek, _ = implant.begin_handshake()
        with Host(self.lib, secrets.token_bytes(32), ek) as rogue:
            code, _ = implant.complete_handshake(rogue.ciphertext, rogue.confirmation)
            self.assertEqual(code, Code.HANDSHAKE_FAILED)
            self.assertCode(implant, rogue.sign(ECOG, 2_000, 200), Code.NO_ACTIVE_SESSION)
        self.assertEqual(implant.stats().handshakes_failed, 1)

    def test_tampered_or_truncated_messages_are_rejected(self) -> None:
        psk = secrets.token_bytes(32)
        for mutate in (
            lambda ct, cf: (bytes([ct[0] ^ 1]) + ct[1:], cf),
            lambda ct, cf: (ct, cf[:-1] + bytes([cf[-1] ^ 1])),
            lambda ct, cf: (ct[:-1], cf),
            lambda ct, cf: (ct, cf[:31]),
            lambda ct, cf: (ct + b"\x00", cf),
            lambda ct, cf: (b"", b""),
        ):
            implant = self.new_implant(psk)
            ek, _ = implant.begin_handshake()
            with Host(self.lib, psk, ek) as host:
                ct, cf = mutate(host.ciphertext, host.confirmation)
                self.assertEqual(implant.complete_handshake(ct, cf)[0], Code.HANDSHAKE_FAILED)

    def test_completion_requires_a_pending_key_pair(self) -> None:
        implant = self.new_implant()
        self.assertEqual(implant.complete_handshake(b"\x00" * 1088, b"\x00" * 32)[0], Code.HANDSHAKE_NOT_STARTED)

    def test_key_pair_is_single_use(self) -> None:
        psk = secrets.token_bytes(32)
        implant = self.new_implant(psk)
        ek, _ = implant.begin_handshake()
        with Host(self.lib, psk, ek) as host:
            self.assertEqual(implant.complete_handshake(host.ciphertext, host.confirmation)[0], 0)
            self.assertEqual(
                implant.complete_handshake(host.ciphertext, host.confirmation)[0], Code.HANDSHAKE_NOT_STARTED
            )

    def test_failed_rogue_handshake_keeps_the_active_session(self) -> None:
        implant, host, _ = self.session()
        self.assertCode(implant, host.sign(ECOG, 2_000, 200), Code.ACCEPTED)
        ek, _ = implant.begin_handshake()
        with Host(self.lib, secrets.token_bytes(32), ek) as rogue:
            self.assertEqual(implant.complete_handshake(rogue.ciphertext, rogue.confirmation)[0], 203)
        self.assertCode(implant, host.sign(ECOG, 2_000, 200), Code.ACCEPTED)

    def test_rekey_invalidates_previous_session(self) -> None:
        implant, old_host, psk = self.session()
        old_packet = old_host.sign(ECOG, 2_000, 200)
        self.assertCode(implant, old_packet, Code.ACCEPTED)
        new_host, _, _ = open_session(self.lib, implant, psk)
        self.addCleanup(new_host.close)
        self.assertCode(implant, old_packet, Code.AUTHENTICATION_FAILED)
        self.assertCode(implant, old_host.sign(ECOG, 2_000, 200), Code.AUTHENTICATION_FAILED)
        verdict = implant.process(new_host.sign(ECOG, 2_000, 200))
        self.assertEqual((verdict.code, verdict.counter), (0, 1))

    def test_end_session(self) -> None:
        implant, host, _ = self.session()
        implant.end_session()
        self.assertCode(implant, host.sign(ECOG, 2_000, 200), Code.NO_ACTIVE_SESSION)


class AuthenticationAndFreshnessTests(KernelTestCase):
    def test_nominal_command_reports_physics(self) -> None:
        implant, host, _ = self.session()
        v = implant.process(host.sign(ECOG, 2_000, 200))
        self.assertTrue(v.accepted)
        self.assertEqual((v.counter, v.charge_pc, v.density_nc_per_cm2, v.dq_micro), (1, 400_000, 10_000, 4_000_000))
        self.assertAlmostEqual(v.shannon_k, 0.60206, places=5)
        self.assertEqual(v.limit_dq_micro, 56_234_130)
        self.assertIn("accepted: counter 1", v.message)

    def test_counters_match_host(self) -> None:
        implant, host, _ = self.session()
        for _ in range(25):
            v = implant.process(host.sign(ECOG, 1_000, 100))
            self.assertEqual(v.counter, host.last_counter)

    def test_random_tags_never_authenticate(self) -> None:
        implant, host, _ = self.session()
        for _ in range(2_000):
            self.assertCode(implant, forge_packet(host.last_counter + 1, ECOG, 2_000, 200, 2_000, 200), Code.AUTHENTICATION_FAILED)
        self.assertEqual(implant.delivered_commands, 0)

    def test_every_single_bit_flip_is_detected(self) -> None:
        implant, host, _ = self.session()
        packet = host.sign(ECOG, 2_000, 200)
        for bit in range(len(packet) * 8):
            mutated = bytearray(packet)
            mutated[bit // 8] ^= 1 << (bit % 8)
            self.assertNotEqual(implant.process(bytes(mutated)).code, 0, f"bit {bit}")
        self.assertCode(implant, packet, Code.ACCEPTED)

    def test_framing_errors(self) -> None:
        implant, host, _ = self.session()
        packet = host.sign(ECOG, 2_000, 200)
        for length in (0, 1, 35, 36, 67, 69, 136, 4096):
            self.assertCode(implant, packet.ljust(length, b"\0")[:length], Code.MALFORMED_PACKET)
        self.assertCode(implant, b"\x02" + packet[1:], Code.UNSUPPORTED_VERSION)
        self.assertCode(implant, packet[:1] + b"\x11" + packet[2:], Code.UNKNOWN_OPCODE)
        self.assertCode(implant, packet, Code.ACCEPTED)

    def test_replays_and_reordering(self) -> None:
        implant, host, _ = self.session()
        p1, p2, p3 = (host.sign(ECOG, 2_000, 200) for _ in range(3))
        self.assertCode(implant, p1, Code.ACCEPTED)
        self.assertCode(implant, p3, Code.ACCEPTED)  # gap allowed
        self.assertCode(implant, p2, Code.REPLAY_DETECTED)  # older than last accepted
        self.assertCode(implant, p3, Code.REPLAY_DETECTED)
        v = implant.process(p1)
        self.assertEqual((v.code, v.counter), (Code.REPLAY_DETECTED, 1))
        self.assertIn("last accepted counter 3", v.message)

    def test_unsafe_authentic_packet_cannot_be_retried(self) -> None:
        implant, host, _ = self.session()
        lethal = host.sign(ECOG, 10_000, 1_000)
        self.assertCode(implant, lethal, Code.SHANNON_LIMIT_EXCEEDED)
        self.assertCode(implant, lethal, Code.REPLAY_DETECTED)


class PhysicsTests(KernelTestCase):
    def test_shannon_violation_details(self) -> None:
        implant, host, _ = self.session()
        v = implant.process(host.sign(ECOG, 10_000, 1_000))
        self.assertEqual(v.code, Code.SHANNON_LIMIT_EXCEEDED)
        self.assertEqual((v.charge_pc, v.density_nc_per_cm2, v.dq_micro), (10_000_000, 250_000, 2_500_000_000))
        self.assertAlmostEqual(v.shannon_k, 3.39794, places=5)

    def test_density_boundary_is_exact(self) -> None:
        implant, host, _ = self.session()
        # 30 µC/cm² × 0.04 cm² = 1.2 µC = 2.4 mA × 500 µs exactly.
        self.assertCode(implant, host.sign(ECOG, 2_400, 500), Code.ACCEPTED)
        v = implant.process(host.sign(ECOG, 2_401, 500))
        self.assertEqual(v.code, Code.CHARGE_DENSITY_EXCEEDED)
        self.assertEqual(v.density_nc_per_cm2, 30_012)

    def test_shannon_boundary_is_exact(self) -> None:
        implant, host, _ = self.session()
        # On 0.25 cm² the Shannon limit is sqrt(56.234 × 0.25) = 3.74947 µC.
        self.assertCode(implant, host.sign(LARGE, 3_749, 1_000), Code.ACCEPTED)
        self.assertCode(implant, host.sign(LARGE, 3_750, 1_000), Code.SHANNON_LIMIT_EXCEEDED)

    def test_biphasic_and_balance_rules(self) -> None:
        implant, host, _ = self.session()
        self.assertCode(implant, host.sign(ECOG, 1_000, 100, anodic_ua=0), Code.MONOPHASIC_PULSE)
        self.assertCode(implant, host.sign(ECOG, 0, 100, anodic_ua=1_000), Code.MONOPHASIC_PULSE)
        self.assertCode(implant, host.sign(ECOG, 1_000, 100, anodic_us=0), Code.MONOPHASIC_PULSE)
        self.assertCode(implant, host.sign(ECOG, 1_000, 100, anodic_ua=980), Code.CHARGE_IMBALANCE)
        self.assertCode(implant, host.sign(ECOG, 1_000, 100, anodic_ua=990), Code.ACCEPTED)  # exactly 1 %
        self.assertCode(implant, host.sign(ECOG, 1_000, 100, anodic_ua=250, anodic_us=400), Code.ACCEPTED)

    def test_every_envelope_limit(self) -> None:
        implant, host, _ = self.session()
        rejected = [
            dict(cathodic_ua=10_001, cathodic_us=100),
            dict(cathodic_ua=1_000, cathodic_us=100, anodic_ua=10_001, anodic_us=10),
            dict(cathodic_ua=1_000, cathodic_us=1_001),
            dict(cathodic_ua=1_000, cathodic_us=100, anodic_ua=100, anodic_us=1_001),
            dict(cathodic_ua=1_000, cathodic_us=100, interphase_gap_us=201),
            dict(cathodic_ua=1_000, cathodic_us=100, rate_hz=0),
            dict(cathodic_ua=1_000, cathodic_us=100, rate_hz=301),
            dict(cathodic_ua=1_000, cathodic_us=100, count=0),
            dict(cathodic_ua=1_000, cathodic_us=100, count=1_001, rate_hz=300),
            dict(cathodic_ua=1_000, cathodic_us=100, count=101, rate_hz=100),  # 1.01 s train
        ]
        for kwargs in rejected:
            self.assertCode(implant, host.sign(ECOG, **kwargs), Code.ENVELOPE_EXCEEDED)
        accepted = [
            dict(cathodic_ua=1_000, cathodic_us=100, count=100, rate_hz=100),  # exactly 1 s
            dict(cathodic_ua=1_000, cathodic_us=100, interphase_gap_us=200, rate_hz=300),
            dict(cathodic_ua=1_000, cathodic_us=1_000, rate_hz=1),
        ]
        for kwargs in accepted:
            self.assertCode(implant, host.sign(ECOG, **kwargs), Code.ACCEPTED)

    def test_unknown_electrode(self) -> None:
        implant, host, _ = self.session()
        self.assertCode(implant, host.sign(77, 1_000, 100), Code.UNKNOWN_ELECTRODE)

    def test_electrodes_use_their_own_area(self) -> None:
        implant, host, _ = self.session()
        self.assertCode(implant, host.sign(ECOG, 2_600, 500), Code.CHARGE_DENSITY_EXCEEDED)
        self.assertCode(implant, host.sign(LARGE, 2_600, 500), Code.ACCEPTED)

    def test_differential_against_exact_decimal_model(self) -> None:
        """5 000 random pulses on 64 log-uniform electrode areas: the kernel's
        integer decision must match an exact 50-digit decimal model of
        D·Q ≤ 10^1.75 and D ≤ 30 µC/cm², except within 1 ppm of a boundary."""
        rng = random.Random(1992)
        areas = {i: round(10 ** rng.uniform(5, 9)) for i in range(64)}  # 0.001 … 10 cm²
        implant, host, _ = self.session(areas)
        checked = 0
        for _ in range(5_000):
            electrode = rng.randrange(64)
            current, width = rng.randint(1, 10_000), rng.randint(1, 1_000)
            q_uc = Decimal(current * width) / Decimal(10**6)
            d = q_uc / (Decimal(areas[electrode]) / Decimal(10**8))
            dq = d * q_uc
            if abs(dq / SHANNON_LIMIT - 1) < Decimal("1e-6") or abs(d / DENSITY_LIMIT - 1) < Decimal("1e-9"):
                continue
            if dq > SHANNON_LIMIT:
                expected = Code.SHANNON_LIMIT_EXCEEDED
            elif d > DENSITY_LIMIT:
                expected = Code.CHARGE_DENSITY_EXCEEDED
            else:
                expected = Code.ACCEPTED
            self.assertCode(implant, host.sign(electrode, current, width), expected)
            checked += 1
        self.assertGreater(checked, 4_900)
        stats = implant.stats()
        self.assertGreater(stats.accepted, 100)
        self.assertGreater(stats.rejected_safety, 100)


class AccountingAndLatencyTests(KernelTestCase):
    def test_stats_and_open_circuit_accounting(self) -> None:
        implant, host, _ = self.session()
        implant.process(b"")  # framing
        implant.process(forge_packet(1, ECOG, 1, 1, 1, 1))  # authentication
        good = host.sign(ECOG, 1_000, 100, count=5, rate_hz=100)
        implant.process(good)
        implant.process(good)  # replay
        implant.process(host.sign(ECOG, 10_000, 1_000))  # safety
        s = implant.stats()
        self.assertEqual(
            (s.rejected_framing, s.rejected_authentication, s.rejected_replay, s.rejected_safety), (1, 1, 1, 1)
        )
        self.assertEqual((s.accepted, s.delivered_commands, s.delivered_pulses), (1, 1, 5))
        self.assertEqual(s.open_circuit_events, 1 + s.rejected)

    def test_nominal_latency_is_within_budget(self) -> None:
        implant, host, _ = self.session()
        worst = max(implant.process(host.sign(1 + i % 4, 2_000, 200)).core_us for i in range(1_000))
        self.assertLess(worst, LATENCY_BUDGET_US)


if __name__ == "__main__":
    unittest.main(verbosity=2)
