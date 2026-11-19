# Bio-Neural Firewall (BNF)

**An open-source, `no_std` authentication and charge-safety kernel that sits between a BCI host computer and the stimulation front-end of a neural implant.**

[![CI](https://github.com/7r123A/bio-neural-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/7r123A/bio-neural-firewall/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/rust-1.87%2B-orange)
![no_std](https://img.shields.io/badge/no__std-no__alloc-blue)
![unsafe](https://img.shields.io/badge/kernel-forbid(unsafe__code)-success)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

> [!WARNING]
> **Research reference implementation. Not a medical device.**
> This code has not been audited, is not certified under IEC 60601-1, IEC 62304 or ISO 14708-3, and must
> not be used to stimulate human or animal tissue without independent hardware safety limits, a formal
> risk analysis (ISO 14971) and the approval of the responsible ethics/regulatory bodies. The `ml-kem`
> crate it depends on states that it has not been independently audited either.

> [!NOTE]
> **AI assistants and new maintainers: this file is the single source of truth.** Everything needed to
> build, run, test, debug or change the project is here. Start with the
> [AI agent and maintainer guide](#ai-agent-and-maintainer-guide), then read the section it points to.

---

## Table of contents

0. [AI agent and maintainer guide](#ai-agent-and-maintainer-guide)
1. [Motivation](#1-motivation)
2. [Design principles](#2-design-principles)
3. [Architecture](#3-architecture)
4. [Cryptographic protocol](#4-cryptographic-protocol)
5. [Physical safety limiter (Shannon criterion)](#5-physical-safety-limiter-shannon-criterion)
6. [Latency budget and measurements](#6-latency-budget-and-measurements)
7. [Installation and usage](#7-installation-and-usage)
8. [Testing strategy](#8-testing-strategy)
9. [Integrating the kernel on a microcontroller](#9-integrating-the-kernel-on-a-microcontroller)
10. [Rejection codes](#10-rejection-codes)
11. [Threat model and limitations](#11-threat-model-and-limitations)
12. [References](#12-references)
13. [Contributing and license](#13-contributing-and-license)

---

## AI agent and maintainer guide

This section is written for automated coding agents (Claude, Copilot, Cursor, …) and for humans who
are new to the codebase. `CLAUDE.md` only points here.

### G.1 Verify the whole project (run this first and last)

Run from the repository root. The commands are identical in bash and PowerShell.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build -p bnf-core --release --target thumbv7em-none-eabihf   # needs: rustup target add thumbv7em-none-eabihf
cargo build --release -p bnf-ffi                                    # must run before any Python step
python -m pyflakes simulation                                       # needs: pip install pyflakes
python simulation/run_simulation.py
python -m unittest discover -s simulation -v
```

`cargo doc` is also run in CI with `RUSTDOCFLAGS="-D warnings"` (bash: prefix the variable; PowerShell:
`$env:RUSTDOCFLAGS="-D warnings"; cargo doc --workspace --no-deps`).

**A healthy project produces exactly this:**

| Step | Expected result |
|---|---|
| `cargo fmt --check` | no output |
| `cargo clippy` | no warnings (`clippy::pedantic` is enabled workspace-wide) |
| `cargo test --workspace` | 84 tests passed: 54 kernel unit + 20 integration + 9 C ABI + 1 doc test |
| `thumbv7em-none-eabihf` build | `Finished` (proves `no_std`, no heap) |
| `run_simulation.py` | last line `OVERALL: PASS`, exit code 0 |
| `unittest discover` | `Ran 55 tests … OK` |

If any of these numbers changes, the change must be intentional. Update this table and
[§8 Testing strategy](#8-testing-strategy) in the same commit.

### G.2 Project facts

| Fact | Value |
|---|---|
| Languages | Rust 2024 edition (MSRV 1.87) for the kernel and C ABI; Python ≥ 3.10, standard library only, for the simulation |
| Kernel crate | `crates/bnf-core`: `#![no_std]`, no heap, `#![forbid(unsafe_code)]` |
| C ABI crate | `crates/bnf-ffi`: the only place with `unsafe`; every `unsafe` block outside the test module has a `// SAFETY:` comment (enforced by `clippy::undocumented_unsafe_blocks`) |
| Python ↔ Rust | `simulation/bnf_bridge.py` loads `target/release/bnf_ffi.{dll,so,dylib}` with `ctypes` |
| Network | needed only for the first `cargo` build (crates.io); nothing else uses the network |
| Lint policy | `[workspace.lints]` in the root `Cargo.toml`; CI fails on any warning |
| Versioning | `CHANGELOG.md` (Keep a Changelog + SemVer); crate version in the root `Cargo.toml` |

### G.3 Where to change what

| Task | Files that must change together |
|---|---|
| Add or change a **physical safety check** | `crates/bnf-core/src/shannon.rs` (`validate`, tests) → if it needs a new rejection, follow the next row |
| Add a **rejection code** | `error.rs`: enum variant, `code()`, `name()`, `REJECTION_CODES` (and its length), `every_variant()` in tests · `simulation/bnf_bridge.py`: `Code` enum · README [§10](#10-rejection-codes) and §3.2 diagram |
| Add a **`SafetyLimits` field** | `config.rs`: struct, `PLATINUM_MACRO_DEFAULT`, `validate()`, tests · `bnf-ffi`: `BnfLimits`, `bnf_default_limits`, test · `bnf_bridge.py`: `_Limits`, `Limits` · bump `ABI_VERSION` (Rust) **and** `EXPECTED_ABI_VERSION` (Python) · README §5.7 |
| Change the **wire format** | `packet.rs` (layout doc, `encode_body`, `decode_*`, tests) · bump `PROTOCOL_VERSION` · `BODY_FORMAT` and offsets in `run_simulation.py` · README §4.4 |
| Change **crypto / handshake** | `crypto.rs`, `session.rs` · change the `CTX_*` domain-separation strings if key derivation changes · README §4 |
| Change the **C ABI** | `crates/bnf-ffi/src/lib.rs` · `_SIGNATURES` in `bnf_bridge.py` · bump both ABI version constants · C ABI tests |
| Add a **simulation attack** | `run_simulation.py` (`run_attacks`) · `test_simulation.py` (`test_every_attack_gets_its_specific_code`, `test_kernel_accounting`) · README §7.4 |
| Change **default limits** | `config.rs` · numbers in README §5, §7.4 and the tests that assert them (`test_default_limits`, `default_limits_are_valid_and_documented_values`) |

### G.4 Invariants: never break these

1. **No floating point on the decision path.** Safety decisions in `shannon.rs` use exact integer
   cross-multiplication in `u128`; overflow must reject (fail closed). Floats are allowed only in tests
   and reporting.
2. **Units:** `Q[pC] = I[µA] × t[µs]`; areas are µm²; densities are nC/cm². Never treat `µA × µs` as µC.
3. **Electrode geometry comes from firmware** (`ElectrodeTable`), never from a packet field.
4. **Order of the pipeline** (`firewall.rs::run_pipeline`): framing → session → MAC → counter commit →
   physics → `deliver`. The counter is committed **before** physics, so an unsafe authentic packet
   cannot be retried.
5. **Every rejection forces open-circuit** (`Firewall::process`), and the gate is opened in
   `Firewall::new` *before* configuration validation.
6. **`StimulationGate::deliver` only receives `ValidatedPulse`**, whose fields are private to `shannon.rs`.
7. **No `unsafe` in `bnf-core`.** Keep `#![forbid(unsafe_code)]`.
8. **Secrets are zeroized.** Do not copy keys into types that are not wiped on drop.
9. **Rejection codes and names are stable.** They are public API in three places (Rust, C ABI,
   Python), and the Python bridge refuses to load if they disagree.
10. **`k` cannot exceed 1.85.** Only the `ShannonK` presets exist; do not add a free-form constructor.

### G.5 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `error: native library not found at '…/target/release/…'` | the C ABI was not built in release mode | `cargo build --release -p bnf-ffi` |
| `BnfError: ABI mismatch` | the DLL/SO is older or newer than `bnf_bridge.py` | rebuild with the command above; if you changed the ABI, bump both version constants |
| `BnfError: code table drift` | a rejection code or name differs between `error.rs` and `Code` in `bnf_bridge.py` | make both match (see G.3) |
| Windows: `failed to remove file …bnf_ffi.dll` / `Access is denied (os error 5)` | a Python process still has the DLL loaded | close that Python process, then rebuild |
| ``can't find crate for `core` `` when building for `thumbv7em-none-eabihf` | the target is not installed | `rustup target add thumbv7em-none-eabihf` |
| `cargo` cannot download crates (HTTP 503 / timeout) | crates.io unavailable or offline | retry; after the first successful build `cargo build --offline` works |
| A `proptest` failure | a property found a counter-example | the minimal input is printed and saved under `proptest-regressions/`; commit that file with the fix so the case is re-tested forever |
| Integration tests are slow | debug build of ML-KEM | already mitigated by `[profile.dev.package."*"] opt-level = 3`; do not remove it |
| `rustfmt` reports diffs on every file after checkout on Windows | line-ending conversion | `.gitattributes` forces LF; run `git add --renormalize .` once |
| Simulation prints `FAILED` or exits 1 | an expectation broke | read the `[FAILED ]` block: it shows expected vs. kernel code and message |

### G.6 Debugging recipes

```bash
cargo test -p bnf-core shannon::tests::lethal_pulse_violates_shannon -- --nocapture   # one Rust test
cargo test -p bnf-core --test pipeline                                                 # integration tests only
PROPTEST_CASES=50000 cargo test -p bnf-core --lib -- prop_                             # stress the properties
RUST_BACKTRACE=1 cargo test --workspace                                                # backtraces on panic
python -m unittest simulation.test_bridge.PhysicsTests.test_shannon_boundary_is_exact -v   # one Python test
python simulation/run_simulation.py --rows 200 --fuzz 0                                # print every nominal command
python simulation/run_simulation.py --seed 7 --fuzz 20000                              # different fuzz corpus
```

Every rejection carries numbers. `Display` for `Rejection` and the `message` field of a Python `Verdict`
include the computed charge, density, `D·Q` and the violated limit.

### G.7 Definition of done for any change

1. Every command in [G.1](#g1-verify-the-whole-project-run-this-first-and-last) passes with the
   expected results.
2. New behaviour has tests in Rust **and**, if it is visible through the C ABI, in Python.
3. `CHANGELOG.md` has an entry under a new version, and the version in the root `Cargo.toml` is bumped.
4. This README is updated wherever the change is visible: G.1 numbers, §5 limits, §7.4 scenario,
   §8 test counts and §10 codes.

---

## 1. Motivation

Open research platforms focus on **reading** and decoding neural signals. Commercial implants that also
**write** to the brain keep their safety and security layers closed. Experimental stimulation hardware
is therefore often left exposed to two failure classes that end in the same place, current flowing
into tissue that should not:

| Failure class | Example |
|---|---|
| **Adversarial** | A forged, tampered or replayed command injected over the wireless link ("neural injection"). |
| **Accidental** | A correctly authenticated host whose software has a bug, a unit-conversion error or a compromised dependency, and sends a charge that damages tissue. |

BNF addresses both with a single middleware kernel. It authenticates every command cryptographically,
then independently checks every authenticated command against physical charge-safety limits before the
output stage is allowed to leave its open-circuit state.

## 2. Design principles

1. **Block, never absorb.** A rejected command is not "absorbed" or dissipated as heat; it simply never
   closes the output switch. The output stage is forced open-circuit at power-up, after every rejection
   and when a session ends.
2. **Authentication and physics are independent.** A valid signature proves who sent a command, not
   that the command is safe. Physics is checked *after* authentication, on every command.
3. **The host is never trusted with geometry.** Electrode surface areas live in firmware configuration.
   If the host could declare the area, it could declare an arbitrarily large one and push any charge
   through the density check.
4. **Integer-exact, fail-closed safety math.** No floating point and no logarithms on the decision path.
   Arithmetic overflow is treated as a violation.
5. **Fail safe on misconfiguration.** Inconsistent limits (e.g. a zero current limit) and empty or
   invalid electrode tables are refused at construction, *after* the gate has already been opened.
6. **Secrets never linger.** The PSK, the ML-KEM decapsulation key, the shared secret, the KDF state and
   the session keys are wiped (`zeroize`) as soon as they are no longer needed.
7. **`no_std`, no heap, no `unsafe`.** The kernel (`bnf-core`) is `#![no_std]`, allocation-free and
   `#![forbid(unsafe_code)]`. It cross-compiles for `thumbv7em-none-eabihf` (Cortex-M4F) in CI.
8. **Type-level guarantee.** The output gate only accepts a `ValidatedPulse`, which can only be
   constructed by the limiter. Code that skips a check does not compile.

## 3. Architecture

### 3.1 Repository layout

```text
bio-neural-firewall/
├── Cargo.toml                    # Workspace, pinned dependencies, strict lint policy (clippy::pedantic)
├── Cargo.lock                    # Exact dependency versions (committed for reproducible builds)
├── README.md                     # This file: the single source of truth
├── CLAUDE.md                     # Points AI assistants to README.md
├── CHANGELOG.md
├── LICENSE                       # MIT
├── rustfmt.toml                  # max_width = 120
├── .gitattributes                # LF line endings everywhere
├── .gitignore                    # target/, __pycache__/, editor folders
├── crates/
│   ├── bnf-core/                 # The no_std kernel (what runs on the implant MCU)
│   │   ├── src/
│   │   │   ├── lib.rs            # Crate root, unit conventions, runnable example
│   │   │   ├── firewall.rs       # Pipeline: framing → MAC → counter → physics → gate
│   │   │   ├── session.rs        # ML-KEM-768 handshake (implant + host roles)
│   │   │   ├── crypto.rs         # BLAKE3 key schedule, MAC, key confirmation
│   │   │   ├── replay.rs         # Strictly monotonic counter guard
│   │   │   ├── shannon.rs        # Charge, density, Shannon k, balance, timing, train checks
│   │   │   ├── config.rs         # SafetyLimits (+ validation), ShannonK presets, electrode table
│   │   │   ├── packet.rs         # 68-byte wire format
│   │   │   ├── gate.rs           # StimulationGate trait (open-circuit output stage)
│   │   │   ├── entropy.rs        # HardwareTrng adapter for MCU TRNG peripherals
│   │   │   └── error.rs          # Rejection reasons, stable codes and names
│   │   └── tests/pipeline.rs     # End-to-end and property-based integration tests
│   └── bnf-ffi/                  # C ABI (cdylib) used by the Python simulation
│       └── src/lib.rs
├── simulation/
│   ├── bnf_bridge.py             # ctypes bindings to the compiled Rust kernel
│   ├── run_simulation.py         # Closed-loop scenario: 4 attack classes, 10 scenarios
│   ├── test_bridge.py            # Kernel behaviour through the C ABI (incl. differential testing)
│   └── test_simulation.py        # Scenario, helper and CLI tests
└── .github/workflows/ci.yml      # fmt, clippy, docs, tests, Cortex-M build, simulation on 3 OSes
```

The Python harness drives the **compiled Rust kernel** through the C ABI. Nothing security-relevant is
re-implemented in Python. Python only plays the legitimate host, the attacker and the test oracle.
At load time the bridge checks the ABI version and verifies that its table of verdict codes matches the
kernel's, so the two languages cannot drift apart silently.

### 3.2 Processing pipeline

```text
             68-byte packet from the radio link
                            │
   ┌────────────────────────▼─────────────────────────┐
   │ 1. Framing     length == 68, version, opcode     │──► 101/102/103
   ├──────────────────────────────────────────────────┤
   │ 2. Session     authenticated session active?     │──► 201
   │ 3. MAC         BLAKE3-keyed tag, constant time   │──► 204
   ├──────────────────────────────────────────────────┤
   │ 4. Freshness   counter > last accepted (commit)  │──► 301
   ├──────────────────────────────────────────────────┤
   │ 5. Physics     electrode lookup (firmware table) │──► 401
   │                absolute envelope + train length  │──► 402
   │                biphasic (no zero-charge phase)   │──► 404
   │                pulse fits in period              │──► 403
   │                charge balance  |Qc−Qa| ≤ tol     │──► 405
   │                Shannon         D·Q ≤ 10^k        │──► 406
   │                density         D ≤ D_max         │──► 407
   └────────────────────────┬─────────────────────────┘
                            │ ValidatedPulse
                            ▼
             StimulationGate::deliver()     (any rejection ⇒ force_open_circuit())
```

The counter is committed as soon as an authentic packet passes the freshness check, **before** the
physics check. An authentic but unsafe command therefore cannot be retried: the second attempt is a
replay.

## 4. Cryptographic protocol

### 4.1 Session establishment (ML-KEM-768 + PSK)

```text
 Implant (bnf-core Firewall)                          Host (bnf-core HostSession)
 ───────────────────────────                          ───────────────────────────
 (dk, ek) ← ML-KEM-768.KeyGen(TRNG)
                         ──── ek (1184 B) ───►
                                                      (ct, ss) ← ML-KEM-768.Encaps(ek)
                                                      keys ← KDF(PSK, ss, transcript)
                         ◄─── ct (1088 B) ‖ confirm (32 B) ───
 ss ← ML-KEM-768.Decaps(dk, ct)
 keys ← KDF(PSK, ss, transcript)
 verify confirm (constant time)   ⇒ session active, counter := 0
```

**Why a PSK on top of ML-KEM?** ML-KEM is a key-encapsulation mechanism. It gives confidentiality of the
shared secret, but **it does not authenticate the peer**: anyone in radio range could run the handshake
with the implant. BNF mixes a 32-byte provisioning pre-shared key (installed out of band, at
implantation) into the KDF, and the host must prove it derived the same keys with a confirmation tag.
A rogue host fails at the handshake (`HANDSHAKE_FAILED`, code 203), not later.

| Property | Mechanism |
|---|---|
| Post-quantum key establishment | ML-KEM-768 (FIPS 203, NIST security category 3) |
| Host authentication | PSK mixed into the KDF + key-confirmation tag |
| Forward secrecy | Ephemeral ML-KEM key pair per session, generated from the TRNG |
| Cross-session replay immunity | Fresh session key ⇒ old packets fail MAC verification |
| No downgrade of an active session | `begin_handshake` never tears down the active session; only a *completed*, confirmed handshake replaces it |
| One attempt per key pair | The pending decapsulation key is consumed on the first completion attempt |
| No counter reuse | The host refuses to sign once counter 2⁶⁴ − 1 is used (`COUNTER_EXHAUSTED`, 302) |

### 4.2 Key schedule

```text
transcript = BLAKE3-derive_key("…handshake transcript", BLAKE3(ek) ‖ ct)
master     = BLAKE3-derive_key("…session secret",       PSK ‖ ss ‖ transcript)
k_cmd      = BLAKE3-derive_key("…command MAC key",      master)
k_confirm  = BLAKE3-derive_key("…host key confirmation", master)
confirm    = BLAKE3-keyed(k_confirm, transcript)
```

### 4.3 Command authentication and replay protection

Every command carries a 32-byte `BLAKE3-keyed(k_cmd, body)` tag. BLAKE3 keyed mode is a PRF/MAC with a
256-bit key. For a 36-byte body it costs a single compression-function call, which is why it was
chosen over HMAC-SHA256. HMAC needs four SHA-256 compressions for the same message, or two if the
key pads are precomputed. Tags are compared in constant time.

Replay protection is a **strictly monotonic 64-bit counter** per session. Gaps are allowed, because a
lost packet must not stall the motor loop. Equal or lower counters are rejected. The TRNG does not
provide replay protection by itself. Its role is to make every session key fresh and unpredictable, so
a packet recorded in one session is worthless in every other session.

### 4.4 Wire format (68 bytes, little-endian)

| Offset | Size | Field | Unit |
|---:|---:|---|---|
| 0 | 1 | `version` = `0x01` | |
| 1 | 1 | `opcode` = `0x10` (STIMULATE) | |
| 2 | 2 | `electrode_id` | |
| 4 | 8 | `counter` | strictly monotonic |
| 12 | 4 | `cathodic_current` | µA |
| 16 | 4 | `cathodic_width` | µs |
| 20 | 4 | `interphase_gap` | µs |
| 24 | 4 | `anodic_current` | µA |
| 28 | 4 | `anodic_width` | µs |
| 32 | 2 | `pulse_rate` | Hz |
| 34 | 2 | `pulse_count` | |
| 36 | 32 | `tag` = BLAKE3-keyed(k_cmd, bytes 0..36) | |

Commands are authenticated, not encrypted. See [limitations](#11-threat-model-and-limitations).

## 5. Physical safety limiter (Shannon criterion)

### 5.1 Equations

For each phase of a biphasic pulse:

```text
Q = I · t                              charge per phase
D = Q / A                              charge density per phase (A = geometric area)
log10(D) = k − log10(Q)                Shannon (1992) boundary  ⇔  D · Q = 10^k
```

A pulse is **rejected** if any of the following is true for its larger-charge phase:

```text
log10(D) + log10(Q) > k        with k = 1.75 by default   (Shannon criterion)
D > D_max                      with D_max = 30 µC/cm²      (platinum reversible-injection limit)
```

It is also rejected if it is not charge-balanced and biphasic:

```text
Q_cathodic = 0  or  Q_anodic = 0                            (monophasic / DC  → 404)
|Q_cathodic − Q_anodic| / max(Q_cathodic, Q_anodic) > 1 %   (imbalance        → 405)
```

### 5.2 Units: where the trap is

The command carries **µA** and **µs**. Their product is **not** in µC:

```text
1 µA × 1 µs = 10⁻⁶ A × 10⁻⁶ s = 10⁻¹² C = 1 pC = 10⁻⁶ µC
```

Treating `I[µA] × t[µs]` as µC overstates the charge by a factor of 10⁶. The kernel therefore works in
explicit integer units:

| Quantity | Internal unit | Conversion |
|---|---|---|
| Charge `Q` | pC | `Q[pC] = I[µA] × t[µs]` |
| Area `A` | µm² | `1 cm² = 10⁸ µm²` |
| Density `D` | nC/cm² | `D[nC/cm²] = Q[pC] × 10⁵ / A[µm²]` |
| Shannon product | µC²/cm² | `D·Q = Q[pC]² × 10⁻⁴ / A[µm²]` |

### 5.3 Integer-exact decision

`10^k` is pre-computed as `floor(10^k × 10⁵)`. Rounding down makes the check marginally stricter, never
looser. The tests verify each preset against a floating-point reference. The Shannon decision
`Q² × 10⁻⁴ / A > 10^k` is evaluated without division:

```text
Q[pC]² × 10  >  floor(10^k × 10⁵) × A[µm²]        (u128, checked; overflow ⇒ reject)
Q[pC]  × 10⁵ >  D_max[nC/cm²]     × A[µm²]        (u128; both sides provably fit)
```

Presets: `ShannonK::K_1_50` (31.62…), `K_1_75` (56.23…, default), `K_1_85` (70.79…, the upper edge of
Shannon's damage boundary). No other value of `k` can be constructed.

### 5.4 Worked examples (Pt ECoG contact, A = 0.04 cm² = 4 000 000 µm²)

| Case | I | t | Q (µC) | D (µC/cm²) | D·Q | k | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| Nominal (sim start) | 2.0 mA | 200 µs | 0.400 | 10.0 | 4.00 | 0.602 | accepted |
| Nominal (sim peak) | 2.5 mA | 200 µs | 0.500 | 12.5 | 6.25 | 0.796 | accepted |
| Density boundary | 2.4 mA | 500 µs | 1.200 | 30.0 | 36.00 | 1.556 | accepted (exactly at limit) |
| Attack 3b | 2.6 mA | 500 µs | 1.300 | 32.5 | 42.25 | 1.626 | **407** density |
| Attack 3a ("lethal") | 10 mA | 1000 µs | 10.000 | 250.0 | 2500 | 3.398 | **406** Shannon |

### 5.5 Which limit binds first?

At the crossover, both limits are simultaneously active, so `D = D_max` and `D·Q = 10^k`. With
`Q = D_max·A`, this gives:

```text
A* = 10^k / D_max² = 56.234 / 30² = 0.0625 cm²  (6.25 mm²)
```

- **A < A\*** (most cortical electrodes): the density cap rejects first.
- **A > A\*** (large DBS/spinal contacts): the Shannon criterion rejects first.

Both regimes are covered by unit tests.

### 5.6 Choosing limits for your electrode

`SafetyLimits::PLATINUM_MACRO_DEFAULT` is calibrated for **platinum macro-electrodes** (ECoG/DBS class).
Do **not** use it unchanged for intracortical micro-electrodes:

- The Shannon criterion was fitted to macro-electrode data (McCreery et al., 1990). Its validity for
  micro-electrodes is not established (Cogan et al., 2016).
- 30 µC/cm² is a platinum reversible charge-injection figure. Activated/sputtered iridium oxide and
  other coatings support different limits. The limit must come from **your** electrode's measured
  charge-injection capacity.
- Example: a 2 000 µm² micro-electrode with a typical microstimulation pulse of 60 µA × 200 µs
  (Q = 12 nC) has D = 600 µC/cm². The default profile rejects it.

All limits are fields of `SafetyLimits`. `SafetyLimits::validate` (called by `Firewall::new`) refuses
zero maxima and charge-balance tolerances looser than 10 %.

### 5.7 Absolute envelope (defaults)

| Parameter | Default limit |
|---|---|
| Current per phase | ≤ 10 000 µA |
| Phase width | ≤ 1 000 µs |
| Interphase gap | ≤ 200 µs |
| Pulse rate | 1 … 300 Hz |
| Pulses per command | 1 … 1 000 |
| Train duration `⌈count × 10⁶ / rate⌉` | ≤ 1 s |
| Timing | `t_cathodic + t_gap + t_anodic < 1 / rate` |

Without the train-duration limit, a single signed command of 1 000 pulses at 1 Hz would keep
stimulating for almost 17 minutes (simulation attack 3d).

## 6. Latency budget and measurements

**Requirement:** a full cryptographic + physical check in **< 1 ms**, so that the end-to-end motor loop
stays below 50 ms at a 100 Hz command rate (10 ms period).

Measured with `python simulation/run_simulation.py --commands 2000 --recovery 500 --fuzz 20000` (release
build, Intel Core i5-14400F, Windows 11; `std::time::Instant`, ≈ 100 ns resolution on Windows):

| Operation | p50 | p99 | max |
|---|---:|---:|---:|
| `Firewall::process`, accepted command (2 500 samples) | 0.2 µs | 0.7 µs | 1.1 µs |
| `Firewall::process`, rejected attack packet | 0.2 µs | 0.5 µs | 0.5 µs |
| Same, measured from Python incl. ctypes | 3.8 µs | 12.1 µs | 178 µs |
| Handshake: ML-KEM-768 keygen (implant) | ≈ 104 µs | | |
| Handshake: decaps + KDF + confirmation (implant) | ≈ 116 µs | | |

Notes:

- Over all 22 500+ packets of that run (including the fuzzing burst), the single worst kernel sample was
  156 µs. That outlier is the desktop OS pre-empting the thread inside the timed region, not kernel
  work. It is still within the budget, and the run reports `OVERALL: PASS`.
- The millisecond-scale spikes in the Python column come from the interpreter and the OS scheduler.
  This is why the kernel is designed to run bare-metal on the implant MCU.
- The handshake runs once per session and is **off the hot path**.
- **None of these numbers has been measured on a microcontroller yet.** On a Cortex-M target, measure
  `Firewall::process` with the DWT cycle counter (`DWT->CYCCNT`) and keep the 1 ms budget as a
  hardware-in-the-loop CI gate.
- Static RAM: `Firewall<_, 8>` is 3 648 bytes and `Firewall<_, 64>` is 4 992 bytes, mostly the pending
  ML-KEM decapsulation key during a handshake. `HostSession` is 72 bytes. The ML-KEM stack peak has not
  been profiled yet; measure it on target.

## 7. Installation and usage

### 7.1 Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Rust (rustup) | 1.87 or newer (edition 2024) | kernel, C ABI |
| Python | 3.10 or newer | simulation (standard library only, no `pip install` needed) |
| `thumbv7em-none-eabihf` target | optional | `no_std` cross-build check |
| `pyflakes` | optional | Python lint used in CI |

### 7.2 Build and test the kernel

```bash
git clone https://github.com/7r123A/bio-neural-firewall.git
cd bio-neural-firewall

cargo test --workspace                                   # unit, property, integration, C ABI and doc tests
cargo clippy --workspace --all-targets -- -D warnings    # clippy::pedantic is enabled workspace-wide
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

# Prove the kernel is no_std / no_alloc by building it for a Cortex-M4F:
rustup target add thumbv7em-none-eabihf
cargo build -p bnf-core --release --target thumbv7em-none-eabihf
```

### 7.3 Run the attack simulation

```bash
cargo build --release -p bnf-ffi             # produces target/release/{bnf_ffi.dll | libbnf_ffi.so | libbnf_ffi.dylib}
python simulation/run_simulation.py          # exit code 0 = every expectation met
python -m unittest discover -s simulation -v # Python test suite
```

| Option | Default | Meaning |
|---|---|---|
| `--commands N` | 200 | nominal commands before the attacks (≥ 8) |
| `--recovery N` | 50 | nominal commands after the attacks (≥ 1) |
| `--rows N` | 5 | nominal rows to print |
| `--fuzz N` | 2000 | random packets in the fuzzing burst |
| `--seed N` | 2026 | seed of the fuzzing burst (reproducible) |
| `--lib PATH` | `target/release/…` | shared library to load (or set `BNF_FFI_LIB`) |

Exit codes: `0` all expectations met, `1` an expectation failed, `2` usage or library error.

### 7.4 What the simulation does

| Phase | Actor | Expected kernel verdict |
|---|---|---|
| Handshake | legitimate host | session active |
| Nominal stream | host, 100 Hz decoder output, 1.5–2.5 mA × 200 µs | all `ACCEPTED` |
| **1a** forged command, random tag, correct next counter | radio attacker | `AUTHENTICATION_FAILED` (204) |
| **1b** authentic packet, amplitude rewritten in flight | radio attacker | `AUTHENTICATION_FAILED` (204) |
| **1c** full ML-KEM handshake with a guessed PSK (MITM) | radio attacker | `HANDSHAKE_FAILED` (203), original session intact |
| **2a** byte-exact replay of an old captured packet | radio attacker | `REPLAY_DETECTED` (301) |
| **2b** replay of the most recently accepted packet | radio attacker | `REPLAY_DETECTED` (301) |
| **3a** validly signed 10 mA × 1 ms (10 µC/phase) | compromised host | `SHANNON_LIMIT_EXCEEDED` (406) |
| **3b** validly signed 1.3 µC/phase (32.5 µC/cm²) | compromised host | `CHARGE_DENSITY_EXCEEDED` (407) |
| **3c** validly signed monophasic DC pulse | compromised host | `MONOPHASIC_PULSE` (404) |
| **3d** validly signed 1 000 pulses at 1 Hz (≈ 17 min) | compromised host | `ENVELOPE_EXCEEDED` (402) |
| **4** fuzzing burst of random / malformed packets | radio attacker | every packet rejected |
| Recovery stream | host | all `ACCEPTED`; session still healthy |

For every attack, the harness checks that the delivered-command counter of the simulated output stage
did **not** change. At the end it cross-checks the kernel's own counters: the accepted, per-layer
rejected, handshake and open-circuit counts must equal exactly what the harness sent.

Abbreviated output:

```text
ATTACK 3 - SIGNED BUT PHYSICALLY UNSAFE COMMANDS (compromised host / software bug)
  [BLOCKED] 3a lethal charge: Shannon criterion
            payload  : validly signed 10.0 mA x 1000 us = 10 uC/phase on a 0.04 cm2 contact
            expected : SHANNON_LIMIT_EXCEEDED (406)
            kernel   : SHANNON_LIMIT_EXCEEDED (406) - Shannon limit exceeded: Q = 10.000000 uC/phase,
                       A = 0.04000000 cm^2, D*Q = 2500.000000 uC^2/cm^2 > 10^k = 56.234130
            physics  : Q = 10.000 uC/phase, D = 250.00 uC/cm2, k = 3.398 (limits: k <= 1.75, D <= 30 uC/cm2)
            output   : delivered 200 -> 200 (unchanged, stage held open-circuit)
...
  legitimate commands accepted : 250/250
  attack scenarios blocked     : 10/10
  commands reaching tissue     : 250 (expected 250)
  kernel rejections by layer   : framing 1001, authentication 1001, replay 2, safety 4
  handshakes                   : 1 completed, 1 rejected
  open-circuit enforcements    : 2009 (1 at power-up + 2008 rejections)
  kernel accounting consistent : yes
  latency within budget        : yes

  OVERALL: PASS
```

## 8. Testing strategy

| Suite | Location | Tests | What it covers |
|---|---|---:|---|
| Kernel unit tests | `crates/bnf-core/src/*.rs` | 54 | every module, every rejection variant and message, exact boundaries, overflow |
| Kernel property tests | `proptest!` blocks in the modules above (part of the 54) | 7 properties; the 4 limiter properties run 4 000 cases each | integer limiter vs float reference, soundness of every accepted pulse, wire round-trip, replay model, totality (no panics) |
| Integration tests | `crates/bnf-core/tests/pipeline.rs` | 20 | handshake failures, rekeying, session teardown, every bit flip, every safety code end-to-end, statistics; 3 properties × 512 cases (random bytes, random mutations, limiter equivalence) |
| Doc test | `crates/bnf-core/src/lib.rs` | 1 | the README-level usage example compiles and runs |
| C ABI tests | `crates/bnf-ffi/src/lib.rs` | 9 | every exported function, null/size misuse, UTF-8-safe message truncation |
| Python kernel tests | `simulation/test_bridge.py` | 35 | behaviour through the ABI, code-table parity with Rust, **differential testing of 5 000 random pulses against an exact 50-digit decimal model** |
| Python scenario tests | `simulation/test_simulation.py` | 20 | full scenario, per-attack codes, kernel accounting, helpers, CLI exit codes |

Extra stress run used before each release:

```bash
PROPTEST_CASES=50000 cargo test -p bnf-core --lib -- prop_
python simulation/run_simulation.py --commands 2000 --recovery 500 --fuzz 20000
```

## 9. Integrating the kernel on a microcontroller

```rust
#![no_std]
use bnf_core::{
    ElectrodeSpec, ElectrodeTable, Firewall, HardwareTrng, SafetyLimits, StimulationGate, ValidatedPulse,
};

/// Board-support implementation of the output stage.
struct FrontEnd { /* GPIO for the analog switch, DAC/current-source handle, … */ }

impl StimulationGate for FrontEnd {
    fn deliver(&mut self, pulse: &ValidatedPulse) {
        // Program the current source from pulse.command(), then close the output switch
        // for the duration of the train. Only reachable with a fully validated pulse.
    }
    fn force_open_circuit(&mut self) {
        // De-assert the switch enable line and zero the DAC. Must not fail.
    }
}

fn firmware_main(psk: [u8; 32], front_end: FrontEnd) -> ! {
    let electrodes = ElectrodeTable::<8>::try_new(&[
        ElectrodeSpec { id: 1, geometric_area_um2: 4_000_000 }, // 0.04 cm² Pt contact
        ElectrodeSpec { id: 2, geometric_area_um2: 4_000_000 },
    ])
    .unwrap_or_else(|_| halt_safe());

    let mut trng = HardwareTrng::new(|| read_trng_word()); // health-tested TRNG word
    let mut fw = Firewall::new(psk, SafetyLimits::PLATINUM_MACRO_DEFAULT, electrodes, front_end)
        .unwrap_or_else(|_| halt_safe()); // gate is already open-circuit here

    let ek = fw.begin_handshake(&mut trng);
    radio_send(&ek);
    let (ct, confirm) = radio_receive_handshake();
    if fw.complete_handshake(&ct, &confirm).is_err() { halt_safe(); }

    loop {
        let packet = radio_receive_packet();
        match fw.process(&packet) {
            Ok(accepted) => log_accept(accepted.counter),
            Err(rejection) => log_reject(rejection.code()), // gate already forced open-circuit
        }
    }
}
```

Integration checklist:

- Place the `Firewall` in a `static` (via `static_cell` or similar) rather than on the stack.
- `HardwareTrng` must wrap a TRNG whose continuous health tests (NIST SP 800-90B or the vendor's
  equivalent) are enabled. On a health-test failure, latch open-circuit and reset; never return
  low-entropy words.
- The PSK belongs in a secure element or in read-protected flash/OTP, never in the firmware image.
- After a reboot, the session is gone. The host must run a new handshake, and the counter restarts
  under a new key.
- Run the hot path from a priority level that the radio stack cannot pre-empt indefinitely.

### Defense in depth

The firmware limiter is **one** layer. A real device must also include an **independent analog
safeguard** that firmware cannot override: series DC-blocking capacitors, a hardware current limit, a
charge-per-phase comparator or timer that opens the switch, and a watchdog that defaults the output to
open-circuit.

## 10. Rejection codes

Names are stable and identical in Rust (`Rejection::name`, `REJECTION_CODES`), the C ABI
(`bnf_rejection_name`) and Python (`bnf_bridge.Code`).

| Code | Name | Layer | Meaning |
|---:|---|---|---|
| 0 | `ACCEPTED` | | delivered to the output stage |
| 101 | `MALFORMED_PACKET` | framing | length ≠ 68 |
| 102 | `UNSUPPORTED_VERSION` | framing | version byte ≠ 0x01 |
| 103 | `UNKNOWN_OPCODE` | framing | opcode ≠ 0x10 |
| 201 | `NO_ACTIVE_SESSION` | authentication | no completed handshake |
| 202 | `HANDSHAKE_NOT_STARTED` | authentication | completion without a pending key pair |
| 203 | `HANDSHAKE_FAILED` | authentication | bad ciphertext, wrong PSK or tampered transcript |
| 204 | `AUTHENTICATION_FAILED` | authentication | MAC does not verify |
| 301 | `REPLAY_DETECTED` | freshness | counter ≤ last accepted counter |
| 302 | `COUNTER_EXHAUSTED` | freshness | host-side: counter 2⁶⁴ − 1 already used; re-handshake |
| 401 | `UNKNOWN_ELECTRODE` | safety | electrode id not provisioned |
| 402 | `ENVELOPE_EXCEEDED` | safety | a raw parameter or the train duration is outside the envelope |
| 403 | `PULSE_TIMING_INVALID` | safety | the pulse does not fit in one period |
| 404 | `MONOPHASIC_PULSE` | safety | one phase carries zero charge |
| 405 | `CHARGE_IMBALANCE` | safety | cathodic/anodic mismatch above tolerance |
| 406 | `SHANNON_LIMIT_EXCEEDED` | safety | `log10(D) + log10(Q) > k` |
| 407 | `CHARGE_DENSITY_EXCEEDED` | safety | `D > D_max` |

With the default limits, code 403 cannot occur: at the maximum rate of 300 Hz the period is 3 333 µs,
and the longest allowed pulse is 1 000 + 200 + 1 000 = 2 200 µs. It becomes reachable when a profile
allows faster rates, and it is covered by unit tests for that case.

## 11. Threat model and limitations

**In scope**

- An attacker who can read, inject, modify, drop, reorder and replay packets on the wireless link.
- An attacker who runs their own handshake with the implant (without the PSK).
- A legitimate, authenticated host that sends physically unsafe commands because of a bug or a
  compromise.
- Future quantum adversaries recording handshakes today ("harvest now, decrypt later") for the key
  exchange.

**Out of scope / known limitations**

- **Jamming and denial of service.** The kernel fails safe (no stimulation), but it cannot keep the
  link up. Repeated `begin_handshake` calls can keep replacing the *pending* key pair, but never the
  active session.
- **Compromise of the PSK** or of the implant firmware itself.
- **Physical side channels** (power and EM analysis) on the MCU. The code uses constant-time tag
  comparison, but `ml-kem` and `blake3` have not been evaluated for side-channel resistance on any
  specific microcontroller.
- **Confidentiality.** Commands are authenticated, not encrypted. An eavesdropper can read stimulation
  parameters. Add an AEAD layer under the same session keys if this matters for your study.
- **Cumulative dose across commands.** Each command's train is bounded (≤ 1 s by default), but long-term
  charge budgets across many commands (per electrode, per time window) are a planned extension.
- **Neural recording uplink.** Only the stimulation (write) path is protected.
- **Not audited, not certified.** See the warning at the top.

## 12. References

1. R. V. Shannon, "A model of safe levels for electrical stimulation," *IEEE Trans. Biomed. Eng.*,
   39(4):424–426, 1992.
2. D. B. McCreery, W. F. Agnew, T. G. H. Yuen, L. Bullara, "Charge density and charge per phase as
   cofactors in neural injury induced by electrical stimulation," *IEEE Trans. Biomed. Eng.*,
   37(10):996–1001, 1990.
3. D. R. Merrill, M. Bikson, J. G. R. Jefferys, "Electrical stimulation of excitable tissue: design of
   efficacious and safe protocols," *J. Neurosci. Methods*, 141(2):171–198, 2005.
4. S. F. Cogan, K. A. Ludwig, C. G. Welle, P. Takmakov, "Tissue damage thresholds during therapeutic
   electrical stimulation," *J. Neural Eng.*, 13(2):021001, 2016.
5. NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, 2024.
6. J. O'Connor, J.-P. Aumasson, S. Neves, Z. Wilcox-O'Hearn, *BLAKE3: one function, fast everywhere*,
   2020.
7. NIST SP 800-90B, *Recommendation for the Entropy Sources Used for Random Bit Generation*, 2018.

## 13. Contributing and license

Contributions are welcome, especially:

- cycle-accurate measurements on real Cortex-M / RISC-V targets,
- electrode-material limit profiles backed by published data,
- cumulative charge-budget tracking across commands,
- an AEAD confidentiality layer,
- formal verification of the limiter arithmetic (e.g. with Kani).

Before opening a pull request, run everything CI runs:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo test --workspace
cargo build -p bnf-core --release --target thumbv7em-none-eabihf
cargo build --release -p bnf-ffi
python -m pyflakes simulation
python simulation/run_simulation.py
python -m unittest discover -s simulation -v
```

Licensed under the [MIT License](LICENSE).
