# Contributing

## License

A contribution is licensed under [Apache-2.0](LICENSE), as §5 of that license provides. There is no CLA.

## Sign your commits

Every commit must carry a `Signed-off-by` trailer, which certifies the [Developer Certificate of Origin 1.1](https://developercertificate.org/). The trailer's email must be the commit author's. Add it with:

```bash
git commit -s
```

To fix commits you have already made, run `git rebase --signoff origin/main` and force-push your branch.

## Before you open a PR

```bash
cargo test --all-features
```

CI ([`ci.yml`](.github/workflows/ci.yml)) also runs these, so run them locally too:

- `cargo fmt --check`
- `cargo clippy --all-features --all-targets` with warnings denied
- `RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps`
- `cargo deny check`
- `cargo check --lib --all-features` on Rust 1.84, the minimum supported version
- the release-mode alloc and property tests, reproducible vectors, and the WebAssembly harness, as listed in [`TESTING.md`](TESTING.md)
- Miri over the unit tests

After merge, `main` and the nightly run also run Miri over all vectors and fuzzing.

The [`dco.yml`](.github/workflows/dco.yml) workflow runs on every PR, Markdown-only ones included, and fails if any non-merge commit lacks its author's sign-off.
