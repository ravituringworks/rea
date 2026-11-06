// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Symphony

//! Pure composition of native-container and Rust dependency observations.

use alloc::{string::String, vec::Vec};
use core::fmt::Write as _;
use serde::Serialize;

use crate::{
    parse_elf_header, read_auditable_section, read_auditable_section_with_alignment,
    read_elf_auditable_section, read_elf_container, read_macho_container, read_pe_container,
    read_universal_macho_slice, AuditableError, AuditableMetadata, BinaryArchitecture,
    BinaryContainer, ContainerError, ElfAuditableError, RustcHashCollectionError, RustcHashMatch,
    UniversalMachoError,
};

/// A bounded Rust-image observation before artifact identity is attached.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustBinaryImage<'a> {
    /// Native-container facts.
    pub container: BinaryContainer<'a>,
    /// Parsed cargo-auditable metadata, or `None` when absence is established.
    pub auditable_metadata: Option<AuditableMetadata>,
    /// Distinct inferred compiler paths in read-only file ranges.
    pub rustc_hashes: Vec<RustcHashMatch<'a>>,
    /// Whether section-name lookup was complete enough to establish absence.
    pub section_names_available: bool,
    /// Selected universal-slice identity, or `None` for a non-universal image.
    pub selected_slice: Option<MachoSelection>,
}

/// Provider-neutral identity of one selected universal Mach-O slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MachoSelection {
    /// File offset of the selected slice.
    pub offset: u64,
    /// Declared slice byte length.
    pub byte_length: u64,
    /// Raw FAT CPU type.
    pub cpu_type: u32,
    /// Raw FAT CPU subtype.
    pub cpu_subtype: u32,
    /// FAT alignment exponent.
    pub alignment_exponent: u32,
    /// SHA-256 of the FAT header/table bytes.
    pub container_table_sha256: [u8; 32],
}

/// Serializable report facts an application adapter can attach to Evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RustBinaryProjection<'a> {
    /// Native container spelling used by the public Rust report.
    pub format: &'static str,
    /// Stable architecture spelling, with unknown raw identity preserved separately.
    pub architecture: String,
    /// Original machine value when the architecture is unknown.
    pub architecture_raw: Option<u32>,
    /// Address width in bits.
    pub bits: u8,
    /// Byte-order spelling.
    pub byte_order: &'static str,
    /// Parsed dependency metadata, or null when absence is established.
    pub auditable_metadata: Option<&'a AuditableMetadata>,
    /// Inferred compiler-path observations, or null when none were found.
    pub rustc_commit: Option<RustcCommitProjection>,
    /// Whether section-name lookup was complete.
    pub section_names_available: bool,
    /// Universal Mach-O identity, when a slice was selected.
    pub selected_slice: Option<MachoSelectionProjection>,
}

/// Serializable inferred compiler-path evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RustcCommitProjection {
    /// Evidence classification.
    pub evidence_kind: &'static str,
    /// Distinct compiler hashes in retained file order.
    pub hashes: Vec<RustcHashProjection>,
}

/// One serialized lower-case compiler hash and its source offset.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RustcHashProjection {
    /// Lower-case hexadecimal hash.
    pub hash: String,
    /// File offset of the `/rustc/` prefix.
    pub file_offset: usize,
}

/// Serializable universal-slice identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MachoSelectionProjection {
    /// File offset of the selected slice.
    pub offset: u64,
    /// Selected slice byte length.
    pub byte_length: u64,
    /// Raw FAT CPU type.
    pub cpu_type: u32,
    /// Raw FAT CPU subtype.
    pub cpu_subtype: u32,
    /// FAT alignment exponent.
    pub alignment_exponent: u32,
    /// SHA-256 of the FAT header/table as lower-case hexadecimal.
    pub container_table_sha256: String,
}

impl<'a> RustBinaryImage<'a> {
    /// Projects core facts into the stable report shape without adding artifact identity.
    pub fn evidence_projection(&'a self) -> RustBinaryProjection<'a> {
        let architecture = self.container.architecture;
        let rustc_commit = if self.rustc_hashes.is_empty() {
            None
        } else {
            Some(RustcCommitProjection {
                evidence_kind: "inferred",
                hashes: self
                    .rustc_hashes
                    .iter()
                    .map(|entry| RustcHashProjection {
                        hash: String::from_utf8_lossy(entry.hash).into_owned(),
                        file_offset: entry.file_offset,
                    })
                    .collect(),
            })
        };
        RustBinaryProjection {
            format: match self.container.format {
                crate::BinaryFormat::Elf => "elf",
                crate::BinaryFormat::Pe => "pe",
                crate::BinaryFormat::MachO => "macho",
            },
            architecture: architecture_string(architecture),
            architecture_raw: architecture.raw(),
            bits: match self.container.class {
                crate::ElfClass::Elf32 => 32,
                crate::ElfClass::Elf64 => 64,
            },
            byte_order: match self.container.byte_order {
                crate::ByteOrder::Little => "little",
                crate::ByteOrder::Big => "big",
            },
            auditable_metadata: self.auditable_metadata.as_ref(),
            rustc_commit,
            section_names_available: self.section_names_available,
            selected_slice: self.selected_slice.map(selection_projection),
        }
    }
}

fn architecture_string(architecture: BinaryArchitecture) -> String {
    if let Some(raw) = architecture.raw() {
        let mut value = String::from("unknown-");
        let _ = write!(value, "{raw}");
        value
    } else {
        String::from(architecture.name())
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        value.push(HEX[usize::from(byte >> 4)] as char);
        value.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    value
}

fn selection_projection(selection: MachoSelection) -> MachoSelectionProjection {
    MachoSelectionProjection {
        offset: selection.offset,
        byte_length: selection.byte_length,
        cpu_type: selection.cpu_type,
        cpu_subtype: selection.cpu_subtype,
        alignment_exponent: selection.alignment_exponent,
        container_table_sha256: lower_hex(&selection.container_table_sha256),
    }
}

/// Failures from the composed Rust-image workflow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RustBinaryError {
    /// A native container was malformed, unsupported, or not recognized.
    Container(ContainerError),
    /// ELF section-name or dependency-section admission failed.
    ElfAuditable(ElfAuditableError),
    /// A non-ELF dependency section was malformed or resource-limited.
    Auditable(AuditableError),
    /// More than one dependency section matched the format-specific name.
    DuplicateDependencySections,
    /// The dependency section uses a native compression flag unsupported by this reader.
    CompressedDependencySection,
    /// The dependency section's declared bytes are not file-backed.
    DependencySectionOutOfBounds,
    /// Universal Mach-O selection or slice validation failed.
    Universal(UniversalMachoError),
    /// The bounded compiler-path inventory exceeded its distinct-hash limit.
    RustcHashes(RustcHashCollectionError),
}

/// Reads one explicit ELF, PE, or thin Mach-O Rust image without executing it.
pub fn read_rust_binary_image<'a>(bytes: &'a [u8]) -> Result<RustBinaryImage<'a>, RustBinaryError> {
    let container = read_container(bytes)?;
    compose_rust_binary_image(bytes, container, None)
}

/// Reads a Rust image, selecting one universal Mach-O slice when requested.
pub fn read_selected_rust_binary_image<'a>(
    bytes: &'a [u8],
    requested: Option<BinaryArchitecture>,
) -> Result<RustBinaryImage<'a>, RustBinaryError> {
    let magic = bytes
        .get(..4)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_be_bytes);
    let (container, selected_slice) = match magic {
        Some(0xcafe_babe | 0xbeba_feca | 0xcafe_babf | 0xbfba_feca) => {
            let slice =
                read_universal_macho_slice(bytes, requested).map_err(RustBinaryError::Universal)?;
            let identity = MachoSelection {
                offset: slice.offset,
                byte_length: slice.size,
                cpu_type: slice.cpu_type,
                cpu_subtype: slice.cpu_subtype,
                alignment_exponent: slice.alignment_exponent,
                container_table_sha256: slice.table_sha256,
            };
            (slice.container, Some(identity))
        }
        _ if requested.is_some() => {
            return Err(RustBinaryError::Universal(
                UniversalMachoError::ArchitectureNotApplicable,
            ));
        }
        _ => (read_container(bytes)?, None),
    };
    compose_rust_binary_image(bytes, container, selected_slice)
}

fn compose_rust_binary_image<'a>(
    bytes: &'a [u8],
    container: BinaryContainer<'a>,
    selected_slice: Option<MachoSelection>,
) -> Result<RustBinaryImage<'a>, RustBinaryError> {
    let (auditable_metadata, section_names_available) =
        read_dependency_metadata(bytes, &container)?;
    let rustc_hashes = collect_read_only_hashes(bytes, &container)?;
    Ok(RustBinaryImage {
        section_names_available,
        container,
        auditable_metadata,
        rustc_hashes,
        selected_slice,
    })
}

fn read_container<'a>(bytes: &'a [u8]) -> Result<BinaryContainer<'a>, RustBinaryError> {
    if bytes.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return read_elf_container(bytes).map_err(RustBinaryError::Container);
    }
    if bytes.starts_with(b"MZ") {
        return read_pe_container(bytes).map_err(RustBinaryError::Container);
    }
    read_macho_container(bytes).map_err(RustBinaryError::Container)
}

fn read_dependency_metadata<'a>(
    bytes: &'a [u8],
    container: &BinaryContainer<'a>,
) -> Result<(Option<AuditableMetadata>, bool), RustBinaryError> {
    match container.format {
        crate::BinaryFormat::Elf => {
            let header = parse_elf_header(bytes)
                .map_err(ContainerError::Elf)
                .map_err(RustBinaryError::Container)?;
            match read_elf_auditable_section(bytes, header) {
                Ok(metadata) => Ok((metadata, container.section_names_available)),
                Err(ElfAuditableError::SectionNamesUnavailable) => Ok((None, false)),
                Err(error) => Err(RustBinaryError::ElfAuditable(error)),
            }
        }
        crate::BinaryFormat::Pe | crate::BinaryFormat::MachO => {
            let section = dependency_section(container)?;
            let Some(section) = section else {
                return Ok((None, container.section_names_available));
            };
            if section.compressed {
                return Err(RustBinaryError::CompressedDependencySection);
            }
            if !section.file_backed {
                return Err(RustBinaryError::DependencySectionOutOfBounds);
            }
            let start = usize::try_from(section.offset)
                .map_err(|_| RustBinaryError::DependencySectionOutOfBounds)?;
            let end = usize::try_from(
                section
                    .offset
                    .checked_add(section.size)
                    .ok_or(RustBinaryError::DependencySectionOutOfBounds)?,
            )
            .map_err(|_| RustBinaryError::DependencySectionOutOfBounds)?;
            let data = bytes
                .get(start..end)
                .ok_or(RustBinaryError::DependencySectionOutOfBounds)?;
            let alignment = if container.format == crate::BinaryFormat::Pe
                && section.virtual_size == Some(0)
                && section.file_alignment.unwrap_or(0) > 0
                && section.raw_size.unwrap_or(0) % section.file_alignment.unwrap_or(1) == 0
            {
                section.file_alignment.map(|value| value as usize)
            } else {
                None
            };
            let metadata = if let Some(alignment) = alignment {
                read_auditable_section_with_alignment(
                    if container.format == crate::BinaryFormat::MachO {
                        "__DATA,.dep-v0"
                    } else {
                        ".dep-v0"
                    },
                    start,
                    data,
                    Some(alignment),
                )
            } else {
                read_auditable_section(
                    if container.format == crate::BinaryFormat::MachO {
                        "__DATA,.dep-v0"
                    } else {
                        ".dep-v0"
                    },
                    start,
                    data,
                )
            }
            .map_err(RustBinaryError::Auditable)?;
            Ok((Some(metadata), container.section_names_available))
        }
    }
}

fn dependency_section<'a>(
    container: &'a BinaryContainer<'a>,
) -> Result<Option<&'a crate::ImageSection<'a>>, RustBinaryError> {
    let mut found = None;
    for section in &container.sections {
        let matches = match container.format {
            crate::BinaryFormat::MachO => {
                section.segment_name == Some(b"__DATA") && section.name == Some(b".dep-v0")
            }
            crate::BinaryFormat::Elf | crate::BinaryFormat::Pe => section.name == Some(b".dep-v0"),
        };
        if matches {
            if found.is_some() {
                return Err(RustBinaryError::DuplicateDependencySections);
            }
            found = Some(section);
        }
    }
    Ok(found)
}

fn collect_read_only_hashes<'a>(
    bytes: &'a [u8],
    container: &BinaryContainer<'a>,
) -> Result<Vec<RustcHashMatch<'a>>, RustBinaryError> {
    let mut all = Vec::new();
    for section in &container.sections {
        if !section.read_only || !section.file_backed || section.size == 0 {
            continue;
        }
        let offset = usize::try_from(section.offset)
            .map_err(|_| RustBinaryError::Container(ContainerError::Malformed))?;
        let size = usize::try_from(section.size)
            .map_err(|_| RustBinaryError::Container(ContainerError::Malformed))?;
        let matches = crate::scan_rustc_hashes_in_region(bytes, offset, size)
            .map_err(|_| RustBinaryError::Container(ContainerError::Malformed))?;
        for candidate in matches {
            if all
                .iter()
                .any(|existing: &RustcHashMatch<'a>| existing.hash == candidate.hash)
            {
                continue;
            }
            if all.len() >= 64 {
                return Err(RustBinaryError::RustcHashes(
                    RustcHashCollectionError::TooManyDistinctHashes,
                ));
            }
            all.push(candidate);
        }
    }
    if container.format == crate::BinaryFormat::Elf {
        for region in &container.load_regions {
            if !region.read || region.write || region.execute || region.mapping.size == 0 {
                continue;
            }
            let offset = usize::try_from(region.mapping.offset)
                .map_err(|_| RustBinaryError::Container(ContainerError::Malformed))?;
            let size = usize::try_from(region.mapping.size)
                .map_err(|_| RustBinaryError::Container(ContainerError::Malformed))?;
            let matches = crate::scan_rustc_hashes_in_region(bytes, offset, size)
                .map_err(|_| RustBinaryError::Container(ContainerError::Malformed))?;
            for candidate in matches {
                if all
                    .iter()
                    .any(|existing: &RustcHashMatch<'a>| existing.hash == candidate.hash)
                {
                    continue;
                }
                if all.len() >= 64 {
                    return Err(RustBinaryError::RustcHashes(
                        RustcHashCollectionError::TooManyDistinctHashes,
                    ));
                }
                all.push(candidate);
            }
        }
    }
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composes_an_elf_identity_without_claiming_missing_sections() {
        let mut bytes = [0u8; 64];
        bytes[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4..16].copy_from_slice(&[2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
        let image = read_rust_binary_image(&bytes).unwrap();
        assert_eq!(image.container.format, crate::BinaryFormat::Elf);
        assert!(image.auditable_metadata.is_none());
        assert!(!image.section_names_available);
        assert!(image.rustc_hashes.is_empty());
        assert_eq!(
            read_selected_rust_binary_image(&bytes, Some(BinaryArchitecture::X86_64)),
            Err(RustBinaryError::Universal(
                UniversalMachoError::ArchitectureNotApplicable
            ))
        );
        let projection = image.evidence_projection();
        let json = serde_json::to_value(projection).unwrap();
        assert_eq!(json["format"], "elf");
        assert_eq!(json["architecture"], "amd64");
        assert_eq!(json["bits"], 64);
        assert_eq!(json["auditable_metadata"], serde_json::Value::Null);
        assert_eq!(json["rustc_commit"], serde_json::Value::Null);
    }

    #[test]
    fn preserves_universal_slice_selection_as_a_typed_failure() {
        let mut bytes = vec![0u8; 48];
        bytes[..4].copy_from_slice(&0xcafe_babeu32.to_be_bytes());
        bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
        bytes[8..12].copy_from_slice(&0x0100_0007u32.to_be_bytes());
        bytes[16..20].copy_from_slice(&48u32.to_be_bytes());
        assert_eq!(
            read_selected_rust_binary_image(&bytes, None),
            Err(RustBinaryError::Universal(
                UniversalMachoError::SelectionRequired
            ))
        );
    }
}
