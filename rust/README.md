# REA Rust core

This workspace is the first Rust boundary for REA. `rea-core` is a pure domain
crate that forbids `unsafe`; its base features use borrowed inputs without
heap allocation and compile with `--no-default-features` as a `no_std` library.
The default `auditable` feature intentionally enables bounded allocation for
normalized dependency metadata.

The core contains provider identity validation, deterministic selection, and
ELF header, program-header, section-header, architecture, Rust compiler-path,
and dependency-cycle parsing. With the default `auditable` feature it also
locates ELF `.dep-v0` sections and inflates and normalizes their bounded
cargo-auditable JSON. The parsers
accept caller-owned inputs, validate table bounds, and return scalar facts or
borrowed names and hashes without retaining or copying the input. The cycle
helper is behind the optional `alloc` feature because it returns an owned
sorted index list. It intentionally does not own processes, files, network
transports, or Evidence persistence. Those effectful concerns
must be introduced at explicit adapter boundaries with caller-owned buffers and
bounded lifetimes.

```sh
cargo test --manifest-path rust/Cargo.toml
cargo test --manifest-path rust/Cargo.toml --no-default-features
```

The `Auto` policy preserves candidate order. Sorting, caching, and diagnostic
formatting belong to the owner that has the relevant contract and storage;
this crate returns only typed, borrowed facts.

