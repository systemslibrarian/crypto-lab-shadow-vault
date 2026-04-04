# Improvements

This document lists the highest-value changes that would make Shadow Vault more secure without changing its core premise: it remains a browser-based application with no backend.

Every item here is something that can be implemented directly in this repository.

## Priority Order

1. Stronger automated testing
2. Reduce JavaScript exposure at the UI boundary
3. Harden build and dependency integrity
4. Make failure behavior more uniform
5. Tighten browser deployment hardening
6. Formalize format compatibility and migration rules
7. Clarify the threat model in the app and docs

## 1. Stronger Automated Testing

The next major improvement is broader test coverage, especially around invariants and edge cases.

Recommended additions:

- Property tests for create/open round-trips across random messages, passphrases, and container sizes
- Regression tests for collision resolution across many generated passphrase pairs
- Negative tests for malformed containers, truncated ciphertext, corrupted tags, and oversized inputs
- Compatibility tests that lock down current format behavior so future changes do not silently break decryption
- Cross-check tests between Rust unit tests and browser integration tests

For a security tool, test depth is part of the security model.

This is the highest-value improvement that can be done entirely in-repo.

Concrete additions:

- Rust unit tests for key derivation, collision resolution, container creation, and container opening
- Property tests that generate random messages and passphrases and verify round-trip correctness
- Deterministic regression vectors for fixed passphrase and container combinations
- Browser integration tests that verify the worker, WASM loader, and UI flows behave correctly
- Corruption tests that flip random bytes in the container and confirm decryption fails cleanly
- Tests that assert real and decoy passphrases never produce overlapping written slots

The goal is to turn security assumptions into enforced invariants.

## 2. Reduce JavaScript Exposure At The UI Boundary

Rust/WASM now holds keys, nonces, salts, offsets, and plaintext slots, which is a real improvement. The main remaining weak point is that passphrases and message text still enter through DOM controls as JavaScript strings.

Within the browser constraint, the goal should be to reduce how long sensitive values live in JS and how many copies are created.

Good next steps:

- Minimize string copies before handing values to the worker
- Clear UI fields immediately after transfer to the worker when practical
- Avoid storing decrypted plaintext longer than necessary in DOM state
- Review every structured clone and buffer copy between main thread and worker
- Keep container bytes transferable where possible instead of copied

This does not eliminate browser limitations, but it narrows the exposed surface.

Concrete improvements that can be implemented:

- Move sensitive operations out of the main thread as early as possible
- Clear input fields immediately after values are transferred to the worker
- Avoid rendering decrypted plaintext until the user explicitly requests it
- Add a dedicated "clear decrypted message" action and auto-clear timer
- Review worker messages so large buffers are transferred instead of cloned when possible
- Minimize temporary JS variables that hold passphrases, message text, or container bytes

This does not remove browser limitations, but it reduces exposure measurably.

## 3. Harden Build And Dependency Integrity

For a browser security tool, supply-chain integrity matters almost as much as code correctness.

Recommended work:

- Pin Rust and npm dependencies tightly
- Review all transitive dependencies and remove any that are not essential
- Make the WASM build reproducible in CI
- Verify that the built WASM artifact is the one actually shipped
- Consider checksum verification for published artifacts
- Keep the deployment pipeline minimal and auditable

The less trust required in the toolchain, the better.

Concrete improvements that can be implemented:

- Pin Rust dependencies more tightly and review feature flags for anything unnecessary
- Commit to one supported Rust toolchain version in CI
- Add a CI step that rebuilds the WASM artifact and verifies the checked-in output matches
- Add dependency review for both npm and Cargo changes
- Remove any unused browser APIs and dead assets as the codebase evolves
- Keep the public output limited to only the files required at runtime

This reduces the chance of shipping something other than what the source implies.

## 4. Make Failure Behavior More Uniform

Observable differences between error cases can become side channels.

Areas to tighten:

- Wrong passphrase vs malformed container responses
- Timing differences across success and failure paths
- Distinct UI wording for cryptographic vs parsing failures
- Slot search behavior that leaks more than necessary

The practical goal is not perfect constant-time behavior across the browser stack, which is unrealistic. The goal is to avoid obvious behavioral distinctions that make probing easier.

Concrete improvements that can be implemented:

- Normalize visible error messages so malformed containers and wrong passphrases are harder to distinguish
- Review timing differences between successful and failed open attempts
- Ensure decryption walks the same search pattern regardless of where success occurs
- Keep progress reporting generic so it does not leak more than necessary

Perfect constant-time behavior is not realistic in the browser, but obvious behavioral leaks can still be reduced.

## 5. Tighten Browser Deployment Hardening

The app should keep a conservative browser security posture.

Useful improvements:

- Re-review the CSP now that the crypto path is Rust/WASM based
- Keep worker execution limited to same-origin assets only
- Remove any unused static assets or legacy compatibility paths
- Keep the app fully static with no analytics, no third-party scripts, and no remote runtime dependencies
- Review headers and hosting behavior for caching and integrity assumptions

Because the tool is browser-based, deployment hygiene is part of the security boundary.

Concrete improvements that can be implemented:

- Re-check the CSP now that the app uses module workers and WASM only
- Add Subresource Integrity only if any third-party assets are ever reintroduced
- Keep the app completely static and same-origin only
- Review caching behavior for the worker and WASM files so stale assets do not break compatibility
- Make sure no debug logging or diagnostic hooks are left in production paths

This is operational hardening, but it directly affects real security in a browser-delivered tool.

## 6. Formalize Format Compatibility And Migration Rules

The container format should be treated as a stable contract.

Even if the format remains headerless, the project needs explicit rules for:

- What is considered version-sensitive behavior
- Which derivation and layout rules are locked
- How future changes would preserve old container readability
- How intentional breaking changes would be communicated

This is less about convenience and more about preventing subtle data-loss or decryption regressions.

Concrete improvements that can be implemented:

- Add explicit versioned test vectors for the current container behavior
- Treat changes to key derivation, offset derivation, and slot layout as compatibility-sensitive
- Add tests that old containers still decrypt after internal refactors
- Decide in advance how a future format revision would be introduced without silent breakage

That discipline prevents security fixes from accidentally becoming data-loss bugs.

## 7. Clarify The Threat Model In The App And Docs

The app will be safer if its guarantees are stated narrowly and precisely.

The documentation should be explicit about what it does defend against and what it does not.

It does help against:

- Casual inspection of the container contents
- Straightforward detection of a second message from container structure alone
- Cheap brute-force attempts when strong passphrases and recommended Argon2id parameters are used

It does not fully protect against:

- Compromised browsers or malicious extensions
- Keyloggers or device-level malware
- JS string retention in browser memory
- OS-level or hardware-level compromise
- Coercion that goes beyond technical deniability

Clear threat-model boundaries reduce dangerous misuse.

Concrete improvements that can be implemented:

- Tighten README language so users do not mistake deniability for protection against device compromise
- Add short in-app warnings about browser memory and compromised-device limits
- State clearly that strong passphrases are required for both real and decoy messages
- Explain that this is still weaker than a native tool under serious threat models

## Best Single Next Move

If only one thing is done next, it should be this:

Build a serious automated test suite around the Rust/WASM core and the browser worker boundary.

That gives the best security return that can be implemented directly in this codebase.