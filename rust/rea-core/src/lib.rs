// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Symphony

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(clippy::all, missing_docs)]

//! Pure, allocation-free domain primitives for REA.
//!
//! The crate deliberately owns no process, filesystem, network, or transport
//! resources. Callers own storage and effects; these functions only validate,
//! select, and return borrowed facts.

#[cfg(feature = "alloc")]
extern crate alloc;

mod architecture;
#[cfg(feature = "auditable")]
mod auditable;
mod binary;
#[cfg(feature = "alloc")]
mod dependency_graph;
mod provider;
mod rust_metadata;

pub use architecture::{architecture_for_elf_machine, ElfArchitecture};
#[cfg(feature = "auditable")]
pub use auditable::{
    read_auditable_section, read_elf_auditable_section, AuditableError, AuditableMetadata,
    AuditablePackage, ElfAuditableError, PackageKind,
};
pub use binary::{parse_elf_header, ByteOrder, ElfClass, ElfError, ElfHeader};
pub use binary::{parse_elf_program_headers, ElfProgramHeader, ElfProgramHeaders};
pub use binary::{parse_elf_section_headers, section_name, ElfSectionHeader, ElfSectionHeaders};
#[cfg(feature = "alloc")]
pub use dependency_graph::{cyclic_dependency_indices, DependencyGraphError};
pub use provider::{
    select_provider, Provider, ProviderId, ProviderReadiness, ProviderSelection,
    ProviderSelectionError, ProviderSelector, RejectionCode,
};
pub use rust_metadata::{
    scan_rustc_hashes, scan_rustc_hashes_in_region, RustcHashMatch, RustcHashMatches,
    RustcRegionError,
};
