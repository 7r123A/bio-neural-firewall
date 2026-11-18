# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-11-19

### Added
- **Train-duration limit** (`SafetyLimits::max_train_duration_us`, default 1 s). Previously a single
  signed command of 1 000 pulses at 1 Hz (about 17 minutes of stimulation) was accepted.
- `SafetyLimits::validate`; `Firewall::new` now returns `Result` and refuses inconsistent limits
  (after forcing the gate open-circuit).
- `ConfigError::EmptyElectrodeTable` and `ConfigError::InvalidLimit`.
- `Rejection::CounterExhausted` (302): `HostSession::sign` now returns `Result` and never wraps or
  reuses a counter.
- Stable rejection names: `Rejection::name`, `REJECTION_CODES`, `rejection_name`; `core::error::Error`
  implementations for `Rejection` and `ConfigError`.
- `FirewallStats::handshakes_completed`, `handshakes_failed` and `rejected()`;
  `Firewall::has_pending_handshake` and `Firewall::electrodes`.
- C ABI v2: `bnf_default_limits`, `bnf_rejection_name`, `bnf_implant_stats`, `bnf_implant_end_session`,
  `bnf_max_electrodes`.
- Simulation: rogue-handshake (MITM) attack, endless-train attack, reproducible fuzzing burst,
  kernel-counter cross-check, `--fuzz` and `--seed` options.
- Property-based tests (proptest), differential testing against an exact decimal model, a runnable
  doc example, and CI jobs for `cargo doc` and `pyflakes`.

### Changed
- `ReplayGuard::check` + `commit` merged into a single `accept`, so a check cannot be committed by
  mistake.
- Workspace-wide strict lints (`clippy::pedantic`, `unsafe_op_in_unsafe_fn`, `missing_docs`,
  `unreachable_pub`).
- Python verdict names now come from a `Code` enum that is verified against the Rust kernel at load
  time, so the two tables cannot drift apart.
- Dependencies are optimised in debug/test builds, which makes the test suite run several times faster.

### Fixed
- The ML-KEM shared secret and the PSK copies made by the C ABI are now wiped after use.
- The C ABI message buffer no longer splits a UTF-8 character when truncating.
- The simulation took the 30 µC/cm² limit from a hard-coded string. It now reads every limit from
  the kernel.

### Removed
- Unreachable error branches in `packet::split_frame`, an unused simulation helper, and the
  duplicated rejection-name table in Python.

## [0.1.0] - 2026-11-18

- Initial release: `no_std` kernel (ML-KEM-768 + PSK handshake, BLAKE3 MAC, monotonic counter,
  Shannon/density/balance limiter), C ABI, Python attack simulation and README.
