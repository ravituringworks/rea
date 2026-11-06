// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Symphony

//! Bounded `.dep-v0` cargo-auditable section parsing.

use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryFrom;
use flate2::read::ZlibDecoder;
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read};

use crate::binary::{
    parse_elf_section_headers, section_name, ElfError, ElfHeader, ElfSectionHeader,
};

const MAX_COMPRESSED_BYTES: usize = 1024 * 1024;
const MAX_UNCOMPRESSED_BYTES: usize = 8 * 1024 * 1024;
const MAX_INFLATE_RATIO: usize = 64;
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 32;

/// Normalized package entry from an auditable dependency document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditablePackage {
    /// Crate name.
    pub name: String,
    /// Crate version.
    pub version: String,
    /// Source identifier.
    pub source: String,
    /// Build or runtime dependency kind.
    pub kind: Option<PackageKind>,
    /// Package indices referenced by this package.
    pub dependencies: Vec<usize>,
    /// Enabled package features, when declared.
    pub features: Option<Vec<String>>,
    /// Whether this package is marked as the root.
    pub root: bool,
}

/// Supported cargo-auditable package kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageKind {
    /// A runtime dependency.
    Runtime,
    /// A build dependency.
    Build,
}

/// Normalized `.dep-v0` metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditableMetadata {
    /// Section spelling used by the containing format.
    pub section_name: &'static str,
    /// File offset of the section bytes.
    pub file_offset: usize,
    /// Stored section size.
    pub section_bytes: usize,
    /// Bytes consumed by the zlib stream.
    pub compressed_bytes: usize,
    /// Inflated JSON size.
    pub uncompressed_bytes: usize,
    /// Optional embedded format revision.
    pub format_version: Option<u32>,
    /// Packages in source order.
    pub packages: Vec<AuditablePackage>,
    /// The sole root package, if one is marked.
    pub root_package_index: Option<usize>,
    /// Dependency edges in package order.
    pub dependency_edges: Vec<AuditableDependencyEdge>,
    /// Package indices participating in cycles.
    pub cyclic_dependency_indices: Vec<usize>,
}

/// One dependency edge in the Evidence-compatible named representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct AuditableDependencyEdge {
    /// Source package index.
    pub from_index: usize,
    /// Target package index.
    pub to_index: usize,
}

/// Malformed, unsupported, or resource-limited auditable metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditableError {
    /// The section is empty.
    EmptySection,
    /// The compressed section exceeds the bounded input limit.
    CompressedTooLarge,
    /// The inflated JSON exceeds the bounded output limit.
    UncompressedTooLarge,
    /// The zlib stream is invalid or has trailing bytes.
    InvalidCompression,
    /// The JSON document does not match the supported schema.
    InvalidDocument,
    /// A required package string was empty.
    EmptyPackageField,
    /// A package kind was not supported.
    InvalidPackageKind,
    /// A dependency index points outside the package list.
    DependencyOutOfBounds {
        /// Package containing the invalid edge.
        from: usize,
        /// Invalid target package index.
        to: usize,
    },
    /// More than one package was marked as root.
    MultipleRoots,
    /// The normalized package and edge report exceeds its output budget.
    OutputTooLarge,
    /// JSON nesting exceeds the bounded parser depth.
    JsonTooDeep,
}

/// ELF-specific failures while locating an auditable section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ElfAuditableError {
    /// The ELF section table was malformed or out of bounds.
    Elf(ElfError),
    /// Section names were unavailable or the name table index was invalid.
    SectionNamesUnavailable,
    /// More than one `.dep-v0` section was present.
    DuplicateDependencySections,
    /// The dependency section has the ELF compressed-section flag.
    CompressedDependencySection,
    /// The dependency section is not fully file-backed.
    DependencySectionOutOfBounds,
    /// The section bytes were not valid auditable metadata.
    Metadata(AuditableError),
}

/// Locates and reads one ELF `.dep-v0` section.
///
/// A missing section returns `Ok(None)`. Section-name absence is kept distinct
/// from a confirmed missing section because an ELF without a usable string
/// table cannot establish absence.
pub fn read_elf_auditable_section(
    bytes: &[u8],
    header: ElfHeader,
) -> Result<Option<AuditableMetadata>, ElfAuditableError> {
    let sections = parse_elf_section_headers(bytes, header).map_err(ElfAuditableError::Elf)?;
    let name_index = usize::from(header.section_name_index);
    if name_index >= usize::from(header.section_header_count) {
        return Err(ElfAuditableError::SectionNamesUnavailable);
    }
    let string_table = sections
        .clone()
        .nth(name_index)
        .ok_or(ElfAuditableError::SectionNamesUnavailable)?
        .map_err(ElfAuditableError::Elf)?;
    if string_table.flags & 0x800 != 0 {
        return Err(ElfAuditableError::SectionNamesUnavailable);
    }

    let mut found: Option<ElfSectionHeader> = None;
    for section in sections {
        let section = section.map_err(ElfAuditableError::Elf)?;
        let name = section_name(bytes, section, string_table).map_err(ElfAuditableError::Elf)?;
        if name != b".dep-v0" {
            continue;
        }
        if found.replace(section).is_some() {
            return Err(ElfAuditableError::DuplicateDependencySections);
        }
    }
    let Some(section) = found else {
        return Ok(None);
    };
    if section.flags & 0x800 != 0 {
        return Err(ElfAuditableError::CompressedDependencySection);
    }
    let offset = usize::try_from(section.offset)
        .map_err(|_| ElfAuditableError::DependencySectionOutOfBounds)?;
    let size = usize::try_from(section.size)
        .map_err(|_| ElfAuditableError::DependencySectionOutOfBounds)?;
    let end = offset
        .checked_add(size)
        .ok_or(ElfAuditableError::DependencySectionOutOfBounds)?;
    if end > bytes.len() {
        return Err(ElfAuditableError::DependencySectionOutOfBounds);
    }
    read_auditable_section(".dep-v0", offset, &bytes[offset..end])
        .map(Some)
        .map_err(ElfAuditableError::Metadata)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    format: Option<u32>,
    packages: Vec<RawPackage>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPackage {
    name: String,
    version: String,
    source: String,
    kind: Option<String>,
    #[serde(default)]
    dependencies: Vec<usize>,
    features: Option<Vec<String>>,
    #[serde(default)]
    root: bool,
}

/// Inflates and normalizes one zlib-compressed `.dep-v0` section.
pub fn read_auditable_section(
    section_name: &'static str,
    file_offset: usize,
    bytes: &[u8],
) -> Result<AuditableMetadata, AuditableError> {
    read_auditable_section_with_alignment(section_name, file_offset, bytes, None)
}

/// Inflates and normalizes a section that may contain zero PE alignment bytes
/// after the zlib stream.
pub fn read_auditable_section_with_alignment(
    section_name: &'static str,
    file_offset: usize,
    bytes: &[u8],
    pe_file_alignment: Option<usize>,
) -> Result<AuditableMetadata, AuditableError> {
    if bytes.is_empty() {
        return Err(AuditableError::EmptySection);
    }
    if bytes.len() > MAX_COMPRESSED_BYTES && pe_file_alignment.is_none() {
        return Err(AuditableError::CompressedTooLarge);
    }

    let mut decoder = ZlibDecoder::new(Cursor::new(bytes));
    let maximum = MAX_UNCOMPRESSED_BYTES.min(bytes.len() * MAX_INFLATE_RATIO);
    let mut inflated = Vec::with_capacity(maximum.min(8192));
    let mut buffer = [0u8; 8192];
    loop {
        let count = decoder
            .read(&mut buffer)
            .map_err(|_| AuditableError::InvalidCompression)?;
        if count == 0 {
            break;
        }
        if inflated.len() > maximum.saturating_sub(count) {
            return Err(AuditableError::UncompressedTooLarge);
        }
        inflated.extend_from_slice(&buffer[..count]);
    }
    let consumed =
        usize::try_from(decoder.total_in()).map_err(|_| AuditableError::InvalidCompression)?;
    if consumed > MAX_COMPRESSED_BYTES {
        return Err(AuditableError::CompressedTooLarge);
    }
    let consumed_maximum = MAX_UNCOMPRESSED_BYTES.min(
        consumed
            .checked_mul(MAX_INFLATE_RATIO)
            .ok_or(AuditableError::UncompressedTooLarge)?,
    );
    if inflated.len() > consumed_maximum {
        return Err(AuditableError::UncompressedTooLarge);
    }
    let accepted_length = if let Some(alignment) = pe_file_alignment.filter(|&value| value > 0) {
        if consumed > bytes.len() {
            return Err(AuditableError::InvalidCompression);
        }
        let aligned = consumed
            .checked_add(alignment - 1)
            .ok_or(AuditableError::InvalidCompression)?
            / alignment
            * alignment;
        if bytes.len() != aligned || bytes[consumed..].iter().any(|&byte| byte != 0) {
            return Err(AuditableError::InvalidCompression);
        }
        aligned
    } else {
        consumed
    };
    if accepted_length != bytes.len() {
        return Err(AuditableError::InvalidCompression);
    }

    if !json_depth_within_limit(&inflated, MAX_JSON_DEPTH) {
        return Err(AuditableError::JsonTooDeep);
    }
    if json_has_duplicate_object_key(&inflated) {
        return Err(AuditableError::InvalidDocument);
    }
    let document: Document =
        serde_json::from_slice(&inflated).map_err(|_| AuditableError::InvalidDocument)?;
    let mut packages = Vec::with_capacity(document.packages.len());
    let mut roots = Vec::new();
    for (index, raw) in document.packages.into_iter().enumerate() {
        if raw.name.is_empty() || raw.version.is_empty() || raw.source.is_empty() {
            return Err(AuditableError::EmptyPackageField);
        }
        let kind = match raw.kind.as_deref() {
            None => None,
            Some("runtime") => Some(PackageKind::Runtime),
            Some("build") => Some(PackageKind::Build),
            Some(_) => return Err(AuditableError::InvalidPackageKind),
        };
        if raw.root {
            roots.push(index);
        }
        packages.push(AuditablePackage {
            name: raw.name,
            version: raw.version,
            source: raw.source,
            kind,
            dependencies: raw.dependencies,
            features: raw.features,
            root: raw.root,
        });
    }
    if roots.len() > 1 {
        return Err(AuditableError::MultipleRoots);
    }
    if !admit_output_budget(&packages) {
        return Err(AuditableError::OutputTooLarge);
    }
    for (from, package) in packages.iter().enumerate() {
        for &to in &package.dependencies {
            if to >= packages.len() {
                return Err(AuditableError::DependencyOutOfBounds { from, to });
            }
        }
    }
    let edges: Vec<AuditableDependencyEdge> = packages
        .iter()
        .enumerate()
        .flat_map(|(from_index, package)| {
            package
                .dependencies
                .iter()
                .copied()
                .map(move |to_index| AuditableDependencyEdge {
                    from_index,
                    to_index,
                })
        })
        .collect();
    for edge in &edges {
        if edge.to_index >= packages.len() {
            return Err(AuditableError::DependencyOutOfBounds {
                from: edge.from_index,
                to: edge.to_index,
            });
        }
    }
    let edge_refs: Vec<&[usize]> = packages
        .iter()
        .map(|package| package.dependencies.as_slice())
        .collect();
    let cyclic_dependency_indices =
        crate::cyclic_dependency_indices(&edge_refs).map_err(|error| match error {
            crate::DependencyGraphError::TargetOutOfBounds { from, to } => {
                AuditableError::DependencyOutOfBounds { from, to }
            }
        })?;

    Ok(AuditableMetadata {
        section_name,
        file_offset,
        section_bytes: bytes.len(),
        compressed_bytes: consumed,
        uncompressed_bytes: inflated.len(),
        format_version: document.format,
        packages,
        root_package_index: roots.into_iter().next(),
        dependency_edges: edges,
        cyclic_dependency_indices,
    })
}

fn admit_output_budget(packages: &[AuditablePackage]) -> bool {
    let mut total = 2usize;
    for package in packages {
        let package_bytes = 128usize
            .saturating_add(package.name.len())
            .saturating_add(package.version.len())
            .saturating_add(package.source.len())
            .saturating_add(
                package
                    .features
                    .as_ref()
                    .map(|features| {
                        features.iter().fold(2usize, |count, feature| {
                            count.saturating_add(feature.len() + 6)
                        })
                    })
                    .unwrap_or(4),
            )
            .saturating_add(package.dependencies.len().saturating_mul(12));
        total = total.saturating_add(package_bytes);
        total = total.saturating_add(package.dependencies.len().saturating_mul(32));
        if total > MAX_OUTPUT_BYTES {
            return false;
        }
    }
    true
}

fn json_depth_within_limit(bytes: &[u8], maximum: usize) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > maximum {
                    return false;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    true
}

fn json_has_duplicate_object_key(bytes: &[u8]) -> bool {
    enum Frame<'a> {
        Object {
            keys: Vec<&'a [u8]>,
            expect_key: bool,
        },
        Array,
    }

    let mut frames = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        match bytes[cursor] {
            byte if byte.is_ascii_whitespace() => cursor += 1,
            b'{' => {
                frames.push(Frame::Object {
                    keys: Vec::new(),
                    expect_key: true,
                });
                cursor += 1;
            }
            b'[' => {
                frames.push(Frame::Array);
                cursor += 1;
            }
            b'}' | b']' => {
                frames.pop();
                cursor += 1;
            }
            b',' => {
                if let Some(Frame::Object { expect_key, .. }) = frames.last_mut() {
                    *expect_key = true;
                }
                cursor += 1;
            }
            b':' => {
                if let Some(Frame::Object { expect_key, .. }) = frames.last_mut() {
                    *expect_key = false;
                }
                cursor += 1;
            }
            b'"' => {
                let start = cursor + 1;
                cursor += 1;
                let mut escaped = false;
                while cursor < bytes.len() {
                    let byte = bytes[cursor];
                    cursor += 1;
                    if escaped {
                        escaped = false;
                    } else if byte == b'\\' {
                        escaped = true;
                    } else if byte == b'"' {
                        break;
                    }
                }
                if let Some(Frame::Object { keys, expect_key }) = frames.last_mut() {
                    if *expect_key {
                        let end = cursor.saturating_sub(1);
                        let key = bytes.get(start..end).unwrap_or_default();
                        if keys.contains(&key) {
                            return true;
                        }
                        keys.push(key);
                        *expect_key = false;
                    }
                }
            }
            _ => cursor += 1,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;

    fn compressed(document: &str) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(document.as_bytes()).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn normalizes_packages_edges_and_cycles() {
        let bytes = compressed(
            r#"{"format":1,"packages":[{"name":"root","version":"1","source":"local","dependencies":[1],"root":true},{"name":"cycle","version":"1","source":"local","dependencies":[2]},{"name":"cycle2","version":"1","source":"local","dependencies":[1]}]}"#,
        );
        let metadata = read_auditable_section(".dep-v0", 128, &bytes).unwrap();
        assert_eq!(metadata.root_package_index, Some(0));
        assert_eq!(
            metadata.dependency_edges,
            vec![
                AuditableDependencyEdge {
                    from_index: 0,
                    to_index: 1
                },
                AuditableDependencyEdge {
                    from_index: 1,
                    to_index: 2
                },
                AuditableDependencyEdge {
                    from_index: 2,
                    to_index: 1
                }
            ]
        );
        assert_eq!(metadata.cyclic_dependency_indices, vec![1, 2]);
        assert_eq!(metadata.file_offset, 128);
    }

    #[test]
    fn rejects_unknown_fields_invalid_kinds_and_bad_indices() {
        let unknown = compressed(r#"{"packages":[],"extra":true}"#);
        assert_eq!(
            read_auditable_section(".dep-v0", 0, &unknown),
            Err(AuditableError::InvalidDocument)
        );
        let kind =
            compressed(r#"{"packages":[{"name":"a","version":"1","source":"x","kind":"dev"}]}"#);
        assert_eq!(
            read_auditable_section(".dep-v0", 0, &kind),
            Err(AuditableError::InvalidPackageKind)
        );
        let index = compressed(
            r#"{"packages":[{"name":"a","version":"1","source":"x","dependencies":[1]}]}"#,
        );
        assert_eq!(
            read_auditable_section(".dep-v0", 0, &index),
            Err(AuditableError::DependencyOutOfBounds { from: 0, to: 1 })
        );
        let duplicate = compressed(r#"{"packages":[],"packages":[]}"#);
        assert_eq!(
            read_auditable_section(".dep-v0", 0, &duplicate),
            Err(AuditableError::InvalidDocument)
        );
    }

    #[test]
    fn rejects_trailing_compressed_bytes() {
        let mut bytes = compressed(r#"{"packages":[]}"#);
        bytes.push(0);
        assert_eq!(
            read_auditable_section(".dep-v0", 0, &bytes),
            Err(AuditableError::InvalidCompression)
        );
    }

    #[test]
    fn accepts_zero_pe_alignment_padding_only_when_requested() {
        let compressed = compressed(r#"{"packages":[]}"#);
        let mut padded = compressed.clone();
        let aligned = padded.len().div_ceil(16) * 16;
        padded.resize(aligned, 0);
        assert_eq!(
            read_auditable_section_with_alignment(".dep-v0", 0, &padded, Some(16))
                .unwrap()
                .compressed_bytes,
            compressed.len()
        );
        assert_eq!(
            read_auditable_section(".dep-v0", 0, &padded),
            Err(AuditableError::InvalidCompression)
        );
    }

    #[test]
    fn rejects_excessive_json_nesting() {
        let document = format!(
            r#"{{"packages":[],"nested":{}}}"#,
            "[".repeat(MAX_JSON_DEPTH + 1)
        );
        let bytes = compressed(&document);
        assert_eq!(
            read_auditable_section(".dep-v0", 0, &bytes),
            Err(AuditableError::JsonTooDeep)
        );
    }

    #[test]
    fn locates_the_named_elf_section() {
        let payload = compressed(r#"{"packages":[]}"#);
        let mut bytes = vec![0u8; 512 + payload.len()];
        bytes[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4..16].copy_from_slice(&[2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[40..48].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&3u16.to_le_bytes());
        bytes[62..64].copy_from_slice(&1u16.to_le_bytes());

        // Null section, .shstrtab at 128, and .dep-v0 at 192.
        let names = b"\0.shstrtab\0.dep-v0\0";
        bytes[128 + 24..128 + 32].copy_from_slice(&400u64.to_le_bytes());
        bytes[128 + 32..128 + 40].copy_from_slice(&(names.len() as u64).to_le_bytes());
        bytes[192..196].copy_from_slice(&11u32.to_le_bytes());
        bytes[192 + 4..192 + 8].copy_from_slice(&1u32.to_le_bytes());
        bytes[192 + 24..192 + 32].copy_from_slice(&512u64.to_le_bytes());
        bytes[192 + 32..192 + 40].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes[400..400 + names.len()].copy_from_slice(names);
        bytes[512..].copy_from_slice(&payload);

        let header = crate::binary::parse_elf_header(&bytes).unwrap();
        let metadata = read_elf_auditable_section(&bytes, header).unwrap().unwrap();
        assert_eq!(metadata.section_name, ".dep-v0");
        assert_eq!(metadata.file_offset, 512);
    }
}
