# BKE .NET Security & Licensing Libraries

Reusable .NET 10 licensing verification, activation-mode policy, challenge proof-of-possession, and platform-protected secure storage primitives for BKE Windows and macOS applications.

## Architectural Boundary

- **This repository owns**: strict wire-contract deserialization, Ed25519 signature verification (`BouncyCastle.Cryptography`), trusted keyring selection, scope/time/revocation enforcement, activation-mode policy (`ACCOUNT`, `LICENSE_KEY`, `EITHER`), proof-of-possession challenge verification, and OS-specific secret protection abstractions (`BKE.Licensing.Platform`: Windows DPAPI and macOS Keychain sealed storage).
- **Trusted host / authority owns**: production signing keys, customer authorization decisions, commercial entitlement state, and elevated Windows Licensing Agent lifecycle operations.
- **Wire parity**: Binary and JSON wire contracts match `@bke/licensing` in [`jan2xo/bke-libraries-typescript`](https://github.com/jan2xo/bke-libraries-typescript).

## Layout

- `src/BKE.Licensing/` — Portable .NET 10 security contracts, strict JSON parser, verifiers, and policies.
- `src/BKE.Licensing.Platform/` — Windows DPAPI and macOS Keychain secret storage adapters.
- `tests/BKE.Licensing.Tests/` — Unit, adversarial, and platform secret storage tests.
- `tests/BKE.Licensing.Interop.Tests/` — Cross-language TypeScript -> .NET verification tests.
- `test-apps/BKE.Licensing.TestApp/` — Isolated CLI verification harness (executable without Digital Solutions).
