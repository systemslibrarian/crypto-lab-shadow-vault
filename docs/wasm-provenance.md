# Current-source WASM reproduction

`npm run wasm` now calls `python3 scripts/reproduce-wasm.py` before the existing
copy helper. Python 3.12+, the repository-selected Rust 1.87.0 toolchain and its
wasm32 target are required. The gate supports macOS arm64 and Linux x86_64;
other hosts fail explicitly.

The gate copies immutable Git blobs at the actual HEAD into scratch, refuses
uncommitted Rust inputs, hashes every captured crate file and the toolchain
file, and records the actual rustc commit and executable hash. It downloads
wasm-pack 0.15.0 and wasm-bindgen 0.2.117 from official releases and checks
their pinned archive digests before executing them. It uses an isolated
Cargo home, fetches the locked public dependencies, and runs two offline,
locked release builds in distinct empty target directories. `--mode no-install`
prevents wasm-pack from substituting a cached or unlocked tool installation.

Both generated JavaScript and WASM must be present, nonempty and byte-identical
between builds. A malformed WASM header, command failure, missing artifact,
unsupported compiler or changed repository SHA fails the gate. Only a passing
pair is copied into `pkg/`; the existing copy helper then supplies `public/`.
`pkg/wasm-provenance.json` records commands, times, statuses, input identities,
actual tool hashes, flags and artifact hashes. CI retains that report as an
artifact. Its success state is `reproduced-current-source`, not a claim that an
older checked-in or published binary was reproduced.

The report separately compares checked-in binaries and preserves mismatches.
Cross-host and cross-capture byte equality are separate measurements. A live
deployment is verified only by comparing the actual deployed files with the
source-bound CI artifact and its reproduction report. Application/browser tests
remain separate gates; matching bytes does not establish constant-time behavior,
production suitability or the identity of the original historical compiler.
`originalCompiler` remains null until authentic historical evidence establishes it.
The catalog scanner's raw unread-WASM distinction remains intact.

Historical diagnosis retained: prior Mac builds used a cargo-installed
wasm-bindgen 0.2.117 whose output recorded Walrus 0.26.4; the deployed artifact
recorded Walrus 0.26.1 and wasm-bindgen's release Git commit. The old wasm-pack
fallback installed without `--locked`. The CI installer also left an existing
wasm-pack 0.13.1 in place despite reporting that a newer version was available.
Version strings and a `sha256sum` alone did not establish reproducibility.
These are tooling/environment distinctions, not evidence of a cryptographic defect.

Offline positive and negative controls:

```sh
python3 -B -m unittest discover -s tests -p 'test_wasm_provenance.py' -v
```

A real reproduction requires `npm run wasm`; the fixture controls alone do not
stand in for that command, CI execution or live-file verification.
