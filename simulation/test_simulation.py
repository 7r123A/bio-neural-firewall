"""Scenario, helper and CLI tests for run_simulation.py (stdlib unittest only).

Run from the repository root after `cargo build --release -p bnf-ffi`:

    python -m unittest discover -s simulation -v
"""

from __future__ import annotations

import contextlib
import io
import random
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bnf_bridge import BnfError, Code, load_library, open_session, Implant  # noqa: E402
from run_simulation import (  # noqa: E402
    BODY_FORMAT,
    ELECTRODES,
    PACKET_LEN,
    Report,
    decoded_motor_intent,
    forge_packet,
    fuzz_packet,
    main,
    percentile,
    simulate,
    tamper_amplitude,
)


def quiet(fn, *args, **kwargs):
    """Runs fn with stdout/stderr captured; returns (result, stdout)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        result = fn(*args, **kwargs)
    return result, out.getvalue() + err.getvalue()


class ScenarioTests(unittest.TestCase):
    report: Report
    output: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.report, cls.output = quiet(simulate, nominal_steps=80, recovery_steps=20, verbose_rows=2, fuzz_count=500)

    def test_overall_pass(self) -> None:
        self.assertTrue(self.report.passed)
        self.assertIn("OVERALL: PASS", self.output)

    def test_all_legitimate_commands_accepted(self) -> None:
        self.assertEqual(len(self.report.nominal), 80)
        self.assertEqual(len(self.report.recovery), 20)
        self.assertTrue(self.report.nominal_all_accepted)

    def test_every_attack_gets_its_specific_code(self) -> None:
        expected = {
            "1a": Code.AUTHENTICATION_FAILED,
            "1b": Code.AUTHENTICATION_FAILED,
            "1c": Code.HANDSHAKE_FAILED,
            "2a": Code.REPLAY_DETECTED,
            "2b": Code.REPLAY_DETECTED,
            "3a": Code.SHANNON_LIMIT_EXCEEDED,
            "3b": Code.CHARGE_DENSITY_EXCEEDED,
            "3c": Code.MONOPHASIC_PULSE,
            "3d": Code.ENVELOPE_EXCEEDED,
        }
        got = {a.title.split()[0]: a.code for a in self.report.attacks}
        self.assertEqual(got, expected)
        for attack in self.report.attacks:
            self.assertTrue(attack.passed, attack.title)
            self.assertEqual(attack.delivered_before, attack.delivered_after, attack.title)

    def test_fuzz_burst_fully_rejected(self) -> None:
        fuzz = self.report.fuzz
        self.assertEqual(fuzz.total, 500)
        self.assertEqual(fuzz.rejected, 500)
        self.assertNotIn(Code.ACCEPTED, fuzz.by_code)
        self.assertTrue(fuzz.passed)

    def test_kernel_accounting(self) -> None:
        s = self.report.stats
        assert s is not None
        self.assertTrue(self.report.accounting_ok)
        self.assertEqual(s.delivered_commands, 100)
        self.assertEqual(s.rejected, 8 + 500)
        self.assertEqual(s.open_circuit_events, 1 + s.rejected)
        self.assertEqual((s.handshakes_completed, s.handshakes_failed), (1, 1))

    def test_latency(self) -> None:
        self.assertTrue(self.report.latency_ok)
        self.assertLess(self.report.worst_core_us, 1_000)
        self.assertGreater(self.report.keygen_us, 0)
        self.assertGreater(self.report.handshake_us, 0)

    def test_physics_printed_for_lethal_command(self) -> None:
        self.assertIn("k = 3.398", self.output)
        self.assertIn("D = 250.00 uC/cm2", self.output)

    def test_invalid_scenario_sizes(self) -> None:
        for kwargs in (dict(nominal_steps=7), dict(recovery_steps=0), dict(fuzz_count=-1)):
            with self.assertRaises(ValueError):
                simulate(**kwargs)


class HelperTests(unittest.TestCase):
    def test_forged_packet_layout_matches_kernel_wire_format(self) -> None:
        packet = forge_packet(0x0102030405060708, 7, 1, 2, 3, 4, interphase_gap_us=5, rate_hz=6, count=8, tag=b"T" * 32)
        self.assertEqual(len(packet), PACKET_LEN)
        self.assertEqual(
            struct.unpack(BODY_FORMAT, packet[:36]), (1, 0x10, 7, 0x0102030405060708, 1, 2, 5, 3, 4, 6, 8)
        )
        self.assertEqual(packet[36:], b"T" * 32)
        self.assertNotEqual(forge_packet(1, 1, 1, 1, 1, 1)[36:], forge_packet(1, 1, 1, 1, 1, 1)[36:])

    def test_host_signed_packet_decodes_with_the_same_layout(self) -> None:
        lib = load_library()
        psk = bytes(range(32))
        with Implant(lib, psk, ELECTRODES) as implant:
            host, _, _ = open_session(lib, implant, psk)
            with host:
                packet = host.sign(3, 1_500, 250, anodic_ua=750, anodic_us=500, interphase_gap_us=40, rate_hz=20, count=2)
        self.assertEqual(struct.unpack(BODY_FORMAT, packet[:36]), (1, 0x10, 3, 1, 1_500, 250, 40, 750, 500, 20, 2))

    def test_tamper_changes_only_amplitudes(self) -> None:
        original = forge_packet(9, 1, 2_000, 200, 2_000, 200, tag=b"\xaa" * 32)
        tampered = tamper_amplitude(original, 10_000)
        diff = [i for i in range(PACKET_LEN) if original[i] != tampered[i]]
        self.assertTrue(set(diff) <= set(range(12, 16)) | set(range(24, 28)))
        fields = struct.unpack(BODY_FORMAT, tampered[:36])
        self.assertEqual((fields[4], fields[7]), (10_000, 10_000))
        self.assertEqual(tampered[36:], original[36:])

    def test_fuzz_packets_are_deterministic_and_varied(self) -> None:
        a = [fuzz_packet(random.Random(5)) for _ in range(3)]
        b = [fuzz_packet(random.Random(5)) for _ in range(3)]
        self.assertEqual(a, b)
        rng = random.Random(1)
        lengths = {len(fuzz_packet(rng)) for _ in range(400)}
        self.assertIn(PACKET_LEN, lengths)
        self.assertGreater(len(lengths), 50)

    def test_motor_intent_stays_in_the_safe_band(self) -> None:
        for step in range(1_000):
            electrode, current, width = decoded_motor_intent(step)
            self.assertIn(electrode, ELECTRODES)
            self.assertTrue(1_500 <= current <= 2_500, current)
            self.assertEqual(width, 200)

    def test_percentile(self) -> None:
        values = [5.0, 1.0, 3.0, 2.0, 4.0]
        self.assertEqual(percentile(values, 0), 1.0)
        self.assertEqual(percentile(values, 50), 3.0)
        self.assertEqual(percentile(values, 99), 5.0)
        self.assertEqual(percentile(values, 100), 5.0)
        self.assertEqual(percentile([7.0], 50), 7.0)
        with self.assertRaises(ValueError):
            percentile([], 50)


class CliTests(unittest.TestCase):
    def test_success_exit_code(self) -> None:
        code, out = quiet(main, ["--commands", "10", "--recovery", "2", "--rows", "0", "--fuzz", "50"])
        self.assertEqual(code, 0)
        self.assertIn("OVERALL: PASS", out)
        self.assertIn("... 10 further commands", out)

    def test_no_suppressed_rows_line_when_everything_is_printed(self) -> None:
        code, out = quiet(main, ["--commands", "8", "--recovery", "1", "--rows", "8", "--fuzz", "0"])
        self.assertEqual(code, 0)
        self.assertNotIn("further commands", out.split("ATTACK 1")[0])
        self.assertIn("4 fuzzing burst: 0 random packets", out)

    def test_invalid_arguments_exit_2(self) -> None:
        for argv in (["--commands", "3"], ["--recovery", "0"], ["--rows", "-1"], ["--fuzz", "-5"], ["--bogus"]):
            with self.assertRaises(SystemExit) as ctx:
                quiet(main, argv)
            self.assertEqual(ctx.exception.code, 2, argv)

    def test_missing_library_exit_2(self) -> None:
        code, out = quiet(main, ["--lib", str(Path(__file__).with_name("missing.dll"))])
        self.assertEqual(code, 2)
        self.assertIn("native library not found", out)

    def test_failed_report_exit_1(self) -> None:
        def failing_run(*_args: object) -> Report:
            return Report()  # no stats: accounting fails

        self.assertEqual(quiet(main, [], run=failing_run)[0], 1)

    def test_bridge_errors_exit_2(self) -> None:
        def broken_run(*_args: object) -> Report:
            raise BnfError("boom")

        code, out = quiet(main, [], run=broken_run)
        self.assertEqual(code, 2)
        self.assertIn("error: boom", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
