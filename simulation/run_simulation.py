#!/usr/bin/env python3
"""Bio-Neural Firewall - closed-loop attack simulation.

Scenario
--------
1. Provisioning : a 32-byte PSK is shared between implant and host (in clinic).
2. Handshake    : ML-KEM-768 session establishment with PSK-bound key confirmation.
3. Nominal      : a motor-decoder stream of signed biphasic commands at 100 Hz.
4. Attack 1     : forged command, command tampered in flight, rogue handshake (MITM).
5. Attack 2     : replay of previously captured authentic commands.
6. Attack 3     : correctly signed commands (compromised host) carrying unsafe charge.
7. Attack 4     : fuzzing burst of random / malformed packets.
8. Recovery     : nominal stream resumes; the original session must still be healthy.

Every packet is processed by the compiled Rust kernel through the C ABI.
The script exits with status 0 only if every expectation holds.
"""

from __future__ import annotations

import argparse
import math
import random
import secrets
import struct
import sys
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bnf_bridge import (  # noqa: E402
    BnfError,
    Code,
    Host,
    Implant,
    Limits,
    Stats,
    Verdict,
    code_name,
    default_limits,
    load_library,
    open_session,
)

# --------------------------------------------------------------------------- setup

#: 0.04 cm² platinum ECoG contact (≈ 2.26 mm diameter disc), in µm².
ELECTRODE_AREA_UM2 = 4_000_000
ELECTRODES = dict.fromkeys((1, 2, 3, 4), ELECTRODE_AREA_UM2)

CONTROL_RATE_HZ = 100
LATENCY_BUDGET_US = 1_000.0

#: Wire layout of the authenticated body (see crates/bnf-core/src/packet.rs).
BODY_FORMAT = "<BBHQIIIIIHH"
BODY_LEN = struct.calcsize(BODY_FORMAT)
TAG_LEN = 32
PACKET_LEN = BODY_LEN + TAG_LEN
OFFSET_CATHODIC_CURRENT = 12
OFFSET_ANODIC_CURRENT = 24

WIDTH = 100


@dataclass
class AttackResult:
    """One attack attempt and the kernel's response."""

    title: str
    payload: str
    expected: Code
    code: int
    message: str
    core_us: float
    round_trip_us: float
    delivered_before: int
    delivered_after: int
    verdict: Verdict | None = None

    @property
    def passed(self) -> bool:
        return self.code == self.expected and self.delivered_after == self.delivered_before


@dataclass
class FuzzResult:
    """Outcome of a burst of random packets."""

    total: int = 0
    by_code: Counter[int] = field(default_factory=Counter)
    worst_core_us: float = 0.0
    delivered_before: int = 0
    delivered_after: int = 0

    @property
    def rejected(self) -> int:
        return self.total - self.by_code.get(Code.ACCEPTED, 0)

    @property
    def passed(self) -> bool:
        return self.rejected == self.total and self.delivered_after == self.delivered_before


@dataclass
class Report:
    """Everything the scenario measured; `passed` is the overall verdict."""

    keygen_us: float = 0.0
    handshake_us: float = 0.0
    nominal: list[Verdict] = field(default_factory=list)
    recovery: list[Verdict] = field(default_factory=list)
    attacks: list[AttackResult] = field(default_factory=list)
    fuzz: FuzzResult = field(default_factory=FuzzResult)
    stats: Stats | None = None

    @property
    def legitimate(self) -> list[Verdict]:
        return self.nominal + self.recovery

    @property
    def nominal_all_accepted(self) -> bool:
        return all(v.accepted for v in self.legitimate)

    @property
    def attacks_all_blocked(self) -> bool:
        return all(a.passed for a in self.attacks) and self.fuzz.passed

    @property
    def worst_core_us(self) -> float:
        cores = [v.core_us for v in self.legitimate] + [a.core_us for a in self.attacks if a.verdict]
        return max([*cores, self.fuzz.worst_core_us])

    @property
    def latency_ok(self) -> bool:
        return self.worst_core_us < LATENCY_BUDGET_US

    @property
    def packet_attacks(self) -> int:
        return sum(1 for a in self.attacks if a.verdict is not None)

    @property
    def accounting_ok(self) -> bool:
        """Kernel counters agree exactly with what the harness sent."""
        s = self.stats
        if s is None:
            return False
        return (
            s.delivered_commands == len(self.legitimate)
            and s.accepted == len(self.legitimate)
            and s.rejected == self.packet_attacks + self.fuzz.total
            and s.open_circuit_events == 1 + s.rejected  # 1 at power-up + 1 per rejection
            and s.handshakes_completed == 1
            and s.handshakes_failed == len(self.attacks) - self.packet_attacks
        )

    @property
    def passed(self) -> bool:
        return self.nominal_all_accepted and self.attacks_all_blocked and self.latency_ok and self.accounting_ok


# ------------------------------------------------------------------- helpers


def forge_packet(
    counter: int,
    electrode_id: int,
    cathodic_ua: int,
    cathodic_us: int,
    anodic_ua: int,
    anodic_us: int,
    interphase_gap_us: int = 50,
    rate_hz: int = 100,
    count: int = 1,
    tag: bytes | None = None,
) -> bytes:
    """Builds a well-formed packet WITHOUT the session key (attacker capability)."""
    body = struct.pack(
        BODY_FORMAT,
        0x01,
        0x10,
        electrode_id,
        counter,
        cathodic_ua,
        cathodic_us,
        interphase_gap_us,
        anodic_ua,
        anodic_us,
        rate_hz,
        count,
    )
    return body + (tag if tag is not None else secrets.token_bytes(TAG_LEN))


def tamper_amplitude(packet: bytes, new_current_ua: int) -> bytes:
    """Overwrites both phase amplitudes of an authentic packet, keeping its tag."""
    raw = bytearray(packet)
    struct.pack_into("<I", raw, OFFSET_CATHODIC_CURRENT, new_current_ua)
    struct.pack_into("<I", raw, OFFSET_ANODIC_CURRENT, new_current_ua)
    return bytes(raw)


def fuzz_packet(rng: random.Random) -> bytes:
    """Random packet: half are exactly 68 bytes with a valid header so they reach
    the MAC check; the rest have random lengths and contents."""
    if rng.random() < 0.5:
        return bytes([0x01, 0x10]) + rng.randbytes(PACKET_LEN - 2)
    return rng.randbytes(rng.randrange(0, 2 * PACKET_LEN + 1))


def decoded_motor_intent(step: int) -> tuple[int, int, int]:
    """Synthetic decoder output: a 1 Hz reach trajectory mapped to stimulation.

    Returns (electrode_id, current_ua, phase_width_us). Amplitude sweeps
    1.5 mA ... 2.5 mA at 200 µs/phase -> Q <= 0.5 µC, D <= 12.5 µC/cm², k <= 0.80.
    """
    phase = 2.0 * math.pi * step / CONTROL_RATE_HZ
    current_ua = 1_500 + round(1_000 * (0.5 + 0.5 * math.sin(phase)))
    electrode_id = 1 + step % len(ELECTRODES)
    return electrode_id, current_ua, 200


def percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile (pct in 0..100) of a non-empty list."""
    if not values:
        raise ValueError("percentile of an empty list")
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, math.ceil(pct / 100.0 * len(ordered)) - 1))
    return ordered[idx]


def rule(char: str = "-") -> None:
    print(char * WIDTH)


def heading(text: str) -> None:
    print()
    rule("=")
    print(text)
    rule("=")


def fmt_k(v: Verdict) -> str:
    k = v.shannon_k
    return "n/a" if k is None else f"{k:.3f}"


# ------------------------------------------------------------------ scenario


class Scenario:
    """Runs the closed-loop scenario against one implant and records a Report."""

    def __init__(self, lib, limits: Limits, implant: Implant, host: Host, verbose_rows: int) -> None:
        self.lib = lib
        self.limits = limits
        self.implant = implant
        self.host = host
        self.verbose_rows = verbose_rows
        self.report = Report()
        self.captured: list[bytes] = []
        self.step = 0

    # ---------------------------------------------------------------- streams

    def stream(self, steps: int, sink: list[Verdict], *, capture: bool) -> None:
        for i in range(steps):
            electrode_id, current_ua, width_us = decoded_motor_intent(self.step)
            packet = self.host.sign(electrode_id, current_ua, width_us)
            if capture:
                self.captured.append(packet)  # an eavesdropper records everything
            verdict = self.implant.process(packet)
            sink.append(verdict)
            if i < self.verbose_rows or not verdict.accepted:
                print(
                    f"  t={self.step * 10:6d} ms  ctr={verdict.counter:<4d} e{electrode_id}  "
                    f"I={current_ua / 1000:5.3f} mA  Q={verdict.charge_uc:5.3f} uC  "
                    f"D={verdict.density_uc_per_cm2:6.2f} uC/cm2  k={fmt_k(verdict):>6}  "
                    f"core={verdict.core_us:6.2f} us  -> {verdict.name}"
                )
            self.step += 1
        hidden = steps - min(steps, self.verbose_rows)
        if hidden:
            print(f"  ... {hidden} further commands processed (rows suppressed)")
        print(f"  accepted {sum(v.accepted for v in sink[-steps:])}/{steps}")

    # ---------------------------------------------------------------- attacks

    def _record(self, result: AttackResult) -> AttackResult:
        self.report.attacks.append(result)
        status = "BLOCKED" if result.passed else "FAILED "
        print(f"  [{status}] {result.title}")
        print(f"            payload  : {result.payload}")
        print(f"            expected : {result.expected.name} ({result.expected.value})")
        print(f"            kernel   : {code_name(result.code)} ({result.code}) - {result.message}")
        v = result.verdict
        if v is not None and v.charge_pc:
            print(
                f"            physics  : Q = {v.charge_uc:.3f} uC/phase, D = {v.density_uc_per_cm2:.2f} uC/cm2, "
                f"k = {fmt_k(v)} (limits: k <= {self.limits.shannon_k:.2f}, "
                f"D <= {self.limits.max_density_uc_per_cm2:.0f} uC/cm2)"
            )
        changed = result.delivered_after != result.delivered_before
        print(
            f"            output   : delivered {result.delivered_before} -> {result.delivered_after} "
            f"({'PULSE REACHED TISSUE' if changed else 'unchanged, stage held open-circuit'})"
        )
        print(f"            timing   : core {result.core_us:.2f} us, incl. ctypes {result.round_trip_us:.2f} us")
        return result

    def packet_attack(self, title: str, payload: str, packet: bytes, expected: Code) -> AttackResult:
        before = self.implant.delivered_commands
        v = self.implant.process(packet)
        return self._record(
            AttackResult(
                title, payload, expected, v.code, v.message, v.core_us, v.round_trip_us,
                before, self.implant.delivered_commands, v,
            )
        )

    def handshake_attack(self, title: str, payload: str, rogue_psk: bytes) -> AttackResult:
        before = self.implant.delivered_commands
        ek, _ = self.implant.begin_handshake()
        with Host(self.lib, rogue_psk, ek) as rogue:
            code, ns = self.implant.complete_handshake(rogue.ciphertext, rogue.confirmation)
        message = "rogue key confirmation rejected; original session left intact"
        return self._record(
            AttackResult(
                title, payload, Code.HANDSHAKE_FAILED, code, message, ns / 1e3, ns / 1e3,
                before, self.implant.delivered_commands,
            )
        )

    def fuzz(self, count: int, seed: int) -> FuzzResult:
        rng = random.Random(seed)
        result = FuzzResult(delivered_before=self.implant.delivered_commands)
        for _ in range(count):
            v = self.implant.process(fuzz_packet(rng))
            result.total += 1
            result.by_code[v.code] += 1
            result.worst_core_us = max(result.worst_core_us, v.core_us)
        result.delivered_after = self.implant.delivered_commands
        self.report.fuzz = result
        status = "BLOCKED" if result.passed else "FAILED "
        print(f"  [{status}] 4 fuzzing burst: {result.total} random packets (seed {seed})")
        for code, n in sorted(result.by_code.items()):
            print(f"            {code_name(code):<26} {n:6d}")
        print(
            f"            output   : delivered {result.delivered_before} -> {result.delivered_after}; "
            f"worst core {result.worst_core_us:.2f} us"
        )
        return result


def run_attacks(sc: Scenario, nominal_steps: int, fuzz_count: int, seed: int) -> None:
    host = sc.host
    heading("ATTACK 1 - FORGERY AND MAN-IN-THE-MIDDLE (attacker in radio range, no key)")
    sc.packet_attack(
        "1a forged packet with random MAC tag",
        "10.0 mA x 1000 us biphasic on e1, counter = next expected value, tag = 32 random bytes",
        forge_packet(host.last_counter + 1, 1, 10_000, 1_000, 10_000, 1_000),
        Code.AUTHENTICATION_FAILED,
    )
    sc.packet_attack(
        "1b authentic packet tampered in flight",
        "intercepted signed 2.0 mA command, amplitude rewritten to 10.0 mA, original tag kept",
        tamper_amplitude(host.sign(1, 2_000, 200), 10_000),
        Code.AUTHENTICATION_FAILED,
    )
    sc.handshake_attack(
        "1c rogue handshake (MITM without the PSK)",
        "attacker runs a full ML-KEM-768 exchange with the implant using a guessed PSK",
        secrets.token_bytes(32),
    )

    heading("ATTACK 2 - REPLAY OF CAPTURED AUTHENTIC COMMANDS")
    old = nominal_steps // 4
    sc.packet_attack(
        "2a replay of an old captured packet",
        f"byte-exact copy of nominal command #{old + 1} (valid MAC, stale counter)",
        sc.captured[old],
        Code.REPLAY_DETECTED,
    )
    sc.packet_attack(
        "2b replay of the most recently accepted packet",
        f"byte-exact copy of nominal command #{nominal_steps} (valid MAC, counter == last accepted)",
        sc.captured[-1],
        Code.REPLAY_DETECTED,
    )

    heading("ATTACK 3 - SIGNED BUT PHYSICALLY UNSAFE COMMANDS (compromised host / software bug)")
    sc.packet_attack(
        "3a lethal charge: Shannon criterion",
        "validly signed 10.0 mA x 1000 us = 10 uC/phase on a 0.04 cm2 contact",
        host.sign(1, 10_000, 1_000),
        Code.SHANNON_LIMIT_EXCEEDED,
    )
    sc.packet_attack(
        "3b charge-density cap (Shannon-compliant, above Pt limit)",
        "validly signed 2.6 mA x 500 us = 1.3 uC/phase -> 32.5 uC/cm2 (k = 1.63)",
        host.sign(2, 2_600, 500),
        Code.CHARGE_DENSITY_EXCEEDED,
    )
    sc.packet_attack(
        "3c monophasic DC pulse (no charge recovery)",
        "validly signed 3.0 mA x 300 us cathodic phase, anodic phase = 0",
        host.sign(3, 3_000, 300, anodic_ua=0, anodic_us=300),
        Code.MONOPHASIC_PULSE,
    )
    sc.packet_attack(
        "3d endless train (train-duration limit)",
        "validly signed 1.0 mA x 100 us, 1000 pulses at 1 Hz = 16.7 minutes of stimulation",
        host.sign(4, 1_000, 100, rate_hz=1, count=1_000),
        Code.ENVELOPE_EXCEEDED,
    )

    heading("ATTACK 4 - FUZZING BURST (random and malformed packets)")
    sc.fuzz(fuzz_count, seed)


def simulate(
    nominal_steps: int = 200,
    recovery_steps: int = 50,
    verbose_rows: int = 5,
    fuzz_count: int = 2_000,
    seed: int = 2026,
    library: str | None = None,
) -> Report:
    """Runs the full scenario and returns its Report (also printed to stdout)."""
    if nominal_steps < 8 or recovery_steps < 1 or fuzz_count < 0:
        raise ValueError("need nominal_steps >= 8, recovery_steps >= 1, fuzz_count >= 0")
    lib = load_library(library)
    limits = default_limits(lib)
    psk = secrets.token_bytes(32)

    heading("BIO-NEURAL FIREWALL - CLOSED-LOOP ATTACK SIMULATION")
    print(
        f"  kernel           : Rust bnf-core via C ABI (packet {lib.bnf_packet_len()} B, "
        f"ML-KEM-768 ek {lib.bnf_encapsulation_key_len()} B / ct {lib.bnf_ciphertext_len()} B)"
    )
    print(
        f"  electrodes       : {len(ELECTRODES)} x Pt ECoG contact, "
        f"A = {ELECTRODE_AREA_UM2:,} um2 = {ELECTRODE_AREA_UM2 / 1e8:.4f} cm2"
    )
    print(
        f"  safety limits    : Shannon k <= {limits.shannon_k:.2f}, D <= {limits.max_density_uc_per_cm2:.0f} uC/cm2, "
        f"charge balance <= {limits.balance_tolerance_percent:.0f} %, "
        f"train <= {limits.max_train_duration_us / 1e6:.0f} s"
    )
    print(
        f"  control loop     : {CONTROL_RATE_HZ} Hz ({1000 / CONTROL_RATE_HZ:.0f} ms period), "
        f"firewall budget {LATENCY_BUDGET_US:.0f} us"
    )

    with Implant(lib, psk, ELECTRODES) as implant:
        heading("PHASE 1 - POST-QUANTUM SESSION ESTABLISHMENT (ML-KEM-768 + PSK)")
        host, keygen_ns, hs_ns = open_session(lib, implant, psk)
        with host:
            sc = Scenario(lib, limits, implant, host, verbose_rows)
            sc.report.keygen_us, sc.report.handshake_us = keygen_ns / 1e3, hs_ns / 1e3
            print(f"  implant keygen (TRNG -> ML-KEM-768)    : {sc.report.keygen_us:9.2f} us")
            print(f"  implant decaps + KDF + key confirmation : {sc.report.handshake_us:9.2f} us")
            print("  result                                  : SESSION ACTIVE")

            heading(f"PHASE 2 - NOMINAL MOTOR STREAM ({nominal_steps} signed commands at {CONTROL_RATE_HZ} Hz)")
            sc.stream(nominal_steps, sc.report.nominal, capture=True)

            run_attacks(sc, nominal_steps, fuzz_count, seed)

            heading(f"PHASE 3 - RECOVERY ({recovery_steps} nominal commands after the attacks)")
            sc.stream(recovery_steps, sc.report.recovery, capture=False)

            sc.report.stats = implant.stats()
    print_summary(sc.report)
    return sc.report


def print_latency(label: str, values_us: list[float], rtt_us: list[float] | None = None) -> None:
    def line(prefix: str, vals: list[float]) -> str:
        return (
            f"{prefix} min {min(vals):7.2f}  p50 {percentile(vals, 50):7.2f}  "
            f"p99 {percentile(vals, 99):7.2f}  max {max(vals):7.2f} us"
        )

    print(f"  {label:<34} {line('core   ', values_us)}")
    if rtt_us:
        print(f"  {'':<34} {line('+ctypes', rtt_us)}")


def print_summary(r: Report) -> None:
    heading("SUMMARY")
    print_latency("legitimate commands", [v.core_us for v in r.legitimate], [v.round_trip_us for v in r.legitimate])
    packet_attacks = [a for a in r.attacks if a.verdict]
    print_latency("rejected attack packets", [a.core_us for a in packet_attacks], [a.round_trip_us for a in packet_attacks])
    print(
        f"  worst-case kernel latency : {r.worst_core_us:.2f} us (budget {LATENCY_BUDGET_US:.0f} us, "
        f"{r.worst_core_us / LATENCY_BUDGET_US * 100:.2f} % used; control period 10 000 us)"
    )
    print()
    print(f"  {'check':<62}{'expected':<26}result")
    rule()
    for a in r.attacks:
        print(f"  {a.title:<62}{a.expected.name:<26}{'BLOCKED' if a.passed else 'FAILED'}")
    fuzz_title = f"4 fuzzing burst ({r.fuzz.total} packets)"
    print(f"  {fuzz_title:<62}{'all rejected':<26}{'BLOCKED' if r.fuzz.passed else 'FAILED'}")
    rule()
    s = r.stats
    assert s is not None
    print(f"  legitimate commands accepted : {sum(v.accepted for v in r.legitimate)}/{len(r.legitimate)}")
    print(f"  attack scenarios blocked     : {sum(a.passed for a in r.attacks) + r.fuzz.passed}/{len(r.attacks) + 1}")
    print(f"  commands reaching tissue     : {s.delivered_commands} (expected {len(r.legitimate)})")
    print(
        f"  kernel rejections by layer   : framing {s.rejected_framing}, authentication "
        f"{s.rejected_authentication}, replay {s.rejected_replay}, safety {s.rejected_safety}"
    )
    print(f"  handshakes                   : {s.handshakes_completed} completed, {s.handshakes_failed} rejected")
    print(f"  open-circuit enforcements    : {s.open_circuit_events} (1 at power-up + {s.rejected} rejections)")
    print(f"  kernel accounting consistent : {'yes' if r.accounting_ok else 'NO'}")
    print(f"  latency within budget        : {'yes' if r.latency_ok else 'NO'}")
    print()
    print(f"  OVERALL: {'PASS' if r.passed else 'FAIL'}")
    rule("=")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--commands", type=int, default=200, help="nominal commands before the attacks (>= 8)")
    parser.add_argument("--recovery", type=int, default=50, help="nominal commands after the attacks (>= 1)")
    parser.add_argument("--rows", type=int, default=5, help="nominal rows to print (>= 0)")
    parser.add_argument("--fuzz", type=int, default=2_000, help="random packets in the fuzzing burst (>= 0)")
    parser.add_argument("--seed", type=int, default=2026, help="seed of the fuzzing burst")
    parser.add_argument("--lib", default=None, help="path to the bnf_ffi shared library")
    return parser


def main(argv: list[str] | None = None, run: Callable[..., Report] = simulate) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.commands < 8 or args.recovery < 1 or args.rows < 0 or args.fuzz < 0:
        parser.error("--commands must be >= 8, --recovery >= 1, --rows >= 0 and --fuzz >= 0")
    try:
        report = run(args.commands, args.recovery, args.rows, args.fuzz, args.seed, args.lib)
    except BnfError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
