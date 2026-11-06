# REA Rust core

This workspace is the first Rust boundary for REA. `rea-core` is a pure domain
crate that forbids `unsafe`; its base features use borrowed inputs without
heap allocation and compile with `--no-default-features` as a `no_std` library.
The default `auditable` feature intentionally enables bounded allocation for
normalized dependency metadata.

The core contains provider identity validation, deterministic selection, and
ELF header, program-header, section-header, architecture, Rust compiler-path,
and dependency-cycle parsing. With the default `auditable` feature it also
normalizes ELF, PE32/PE32+, thin Mach-O, and explicitly selected universal
Mach-O containers; locates format-specific `.dep-v0` sections; and inflates
and normalizes their bounded cargo-auditable JSON. The composed
`read_rust_binary_image` workflow also returns distinct read-only
`/rustc/<40-hex>/` observations with a fixed cap. The parsers
accept caller-owned inputs, validate table bounds, and return scalar facts or
borrowed names and hashes without retaining or copying the input. The cycle
helper is behind the optional `alloc` feature because it returns an owned
sorted index list. It intentionally does not own processes, files, network
transports, or Evidence persistence. Those effectful concerns
must be introduced at explicit adapter boundaries with caller-owned buffers,
bounded lifetimes, and the existing REA Evidence/session contracts.

`read_selected_rust_binary_image` additionally preserves the selected FAT
slice offset, byte length, raw CPU type/subtype, alignment exponent, and
SHA-256 of the FAT header/table. Dependency edges use named
`from_index`/`to_index` fields rather than positional tuples so an adapter can
project them directly into the Rust Evidence schema. Missing or unavailable
ELF section names remain an explicit partial fact; they never become a false
claim that `.dep-v0` is absent.

Call `RustBinaryImage::evidence_projection` when an effectful adapter needs
the report-level shape. It serializes only analysis facts; artifact path,
SHA-256, Evidence IDs, paging, transport limits, cancellation, and cleanup
remain owned by the application workflow.

## Standalone CLI

The workspace also builds a Node-independent `rea` executable:

```sh
cargo build --release --manifest-path rust/Cargo.toml --bin rea
./rust/target/release/rea inspect-rust-binary /absolute/path/to/application --json
```

Or install it into Cargo's binary directory:

```sh
cargo install --path rust/rea-cli --locked
rea inspect-rust-binary /absolute/path/to/application --json
```

Universal Mach-O inputs require an explicit slice architecture:

```sh
rea inspect-rust-binary /absolute/path/to/application \
  --architecture arm64 --json
```

The executable owns only local file reading and terminal/JSON delivery. It
does not execute the target, access the network, use Node or npm, or persist
Evidence sessions.

```sh
cargo test --manifest-path rust/Cargo.toml
cargo test --manifest-path rust/Cargo.toml --no-default-features
```

The `Auto` policy preserves candidate order. Sorting, caching, and diagnostic
formatting belong to the owner that has the relevant contract and storage;
this crate returns only typed, borrowed facts.

