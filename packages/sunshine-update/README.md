# sunshine-update

This package owns `/usr/bin/sunshine-update` and installs the Evolution Engine
under `/usr/lib/sunshine/evolution-engine`:

- `src/` — Python Core (`src/engine.py`) and its declarative target/components;
- `bootstrap-rust/` — the std-only Stage A trust root, built from the vendored
  source with `cargo build --release --locked --offline` during `makepkg`;
- `docs/`, `fixtures/`, `tests/` — engine documentation, offline fixtures and
  the regression suite.

`scripts/stage-src.sh` builds `sunshine-update-src.tar.zst` from the files in
this directory; `scripts/build-repo.sh` discovers the PKGBUILD automatically and
installs `rust` in the builder container when `cargo` is missing.

## Manual release steps (not automated in this repo)

The Stage A trust material is deliberately **not** committed here:

- `/etc/sunshine/trust/trust-policy.json` (pins the first root and the receipt
  signing key),
- `/var/lib/sunshine/trust/index.json` (signed index with artifact digests),
- `/usr/share/sunshine/trust/repository-root.gpg` (dedicated keyring),
- the 2026-11-20 OLD → NEW rotation record and the root-only receipt signing
  key.

Generate and sign these with the procedures in
`bootstrap-rust/README.md` and `bootstrap-rust/ROTATION.md` of the engine, then
publish the signed artifacts through the normal release pipeline. The repo
signing key and the GitHub Release upload stay manual
(`scripts/build-repo.sh` → `scripts/sign-repo.sh` → `scripts/publish.sh`, with
the key in `~/sunshineos-build/signing`).

Until that material is provisioned, `/usr/bin/sunshine-update` runs Python Core
directly (`python3 .../src/engine.py --apply`) and reports the result. When all
three Stage A files exist, the same command uses the Rust bootstrap's verified
`handoff` automatically. Partial trust material is a hard failure: the wrapper
refuses to transform the machine rather than silently skipping verification.
