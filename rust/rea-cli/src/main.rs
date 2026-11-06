// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Symphony

//! Standalone command-line adapter for the pure REA Rust core.

use std::env;
use std::fs;
use std::path::Path;
use std::process;

use rea_core::{
    read_selected_rust_binary_image, AuditableMetadata, BinaryArchitecture, MachoSelection,
    RustBinaryError, RustBinaryImage, RustcCommitProjection,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_INPUT_BYTES: u64 = 256 * 1024 * 1024;

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("rea: {error}");
        process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print_help();
        return Ok(());
    }
    if args[0] == "--version" || args[0] == "-V" {
        println!("rea 0.1.0");
        return Ok(());
    }
    if args[0] != "inspect-rust-binary" && args[0] != "inspect-rust" {
        return Err(format!(
            "unknown command {:?}; use `rea inspect-rust-binary PATH --json`",
            args[0]
        ));
    }
    let (path, architecture, json) = parse_inspect_args(&args[1..])?;
    let path = if path.is_absolute() {
        path
    } else {
        env::current_dir()
            .map_err(|error| format!("cannot determine current directory: {error}"))?
            .join(path)
    };
    let metadata =
        fs::metadata(&path).map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "selected file is {} bytes; the maximum is {} bytes",
            metadata.len(),
            MAX_INPUT_BYTES
        ));
    }
    let bytes =
        fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let digest = hex(&Sha256::digest(&bytes));
    let image = read_selected_rust_binary_image(&bytes, architecture)
        .map_err(|error| format_core_error(&error))?;
    let report = report(&path, bytes.len(), digest, &image);
    if json {
        let encoded = serde_json::to_string_pretty(&report)
            .map_err(|error| format!("cannot encode report: {error}"))?;
        println!("{encoded}");
    } else {
        print_human(&report);
    }
    Ok(())
}

fn parse_inspect_args(
    args: &[String],
) -> Result<(std::path::PathBuf, Option<BinaryArchitecture>, bool), String> {
    let mut path = None;
    let mut architecture = None;
    let mut json = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--json" => json = true,
            "--architecture" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--architecture requires a value".to_string())?;
                architecture = Some(parse_architecture(value)?);
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown option {value:?}"));
            }
            value if path.is_none() => path = Some(std::path::PathBuf::from(value)),
            value => return Err(format!("unexpected argument {value:?}")),
        }
        index += 1;
    }
    Ok((
        path.ok_or_else(|| "inspect-rust-binary requires a file path".to_string())?,
        architecture,
        json,
    ))
}

fn parse_architecture(value: &str) -> Result<BinaryArchitecture, String> {
    match value {
        "x86" | "386" => Ok(BinaryArchitecture::X86),
        "x86_64" | "amd64" => Ok(BinaryArchitecture::X86_64),
        "arm" => Ok(BinaryArchitecture::Arm),
        "arm64" => Ok(BinaryArchitecture::Arm64),
        "arm64_32" => Ok(BinaryArchitecture::Arm64_32),
        _ => Err(format!(
            "unsupported architecture {value:?}; use x86, x86_64, arm, arm64, or arm64_32"
        )),
    }
}

#[derive(Serialize)]
struct Artifact {
    path: String,
    sha256: String,
    bytes: usize,
}

#[derive(Serialize)]
struct Report<'a> {
    artifact: Artifact,
    format: &'static str,
    architecture: String,
    bits: u8,
    byte_order: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_slice: Option<SelectedSlice>,
    auditable_metadata: Option<&'a AuditableMetadata>,
    rustc_commit: Option<RustcCommitProjection>,
    limitations: Vec<String>,
}

#[derive(Serialize)]
struct SelectedSlice {
    kind: &'static str,
    container: &'static str,
    offset: u64,
    byte_length: u64,
    cpu_type: u32,
    cpu_subtype: u32,
    container_table_sha256: String,
}

fn report<'a>(
    path: &Path,
    bytes: usize,
    sha256: String,
    image: &'a RustBinaryImage<'a>,
) -> Report<'a> {
    let projection = image.evidence_projection();
    let selected_slice = image.selected_slice.map(selected_slice);
    let mut limitations = vec![
        "Embedded dependency metadata and compiler paths are observed file content; they do not authenticate packages or prove compiler provenance.".to_string(),
        "Only static container metadata, the cargo-auditable dependency section, and read-only compiler paths are inspected; target execution is not performed.".to_string(),
    ];
    if image.auditable_metadata.is_none() {
        limitations.push(if image.section_names_available {
            "No .dep-v0 section was found; absence does not prove that the binary has no dependencies.".to_string()
        } else {
            "ELF section names were unavailable, so .dep-v0 presence remains unknown.".to_string()
        });
    }
    if image.rustc_hashes.is_empty() {
        limitations.push(
            "No /rustc/<40-hex>/ path was found in admitted read-only data; the compiler hash is unknown."
                .to_string(),
        );
    }
    if image
        .auditable_metadata
        .as_ref()
        .is_some_and(|metadata| !metadata.cyclic_dependency_indices.is_empty())
    {
        limitations.push(
            "Dependency indices contain a cycle; the cycle is reported and not traversed."
                .to_string(),
        );
    }
    Report {
        artifact: Artifact {
            path: path.display().to_string(),
            sha256,
            bytes,
        },
        format: projection.format,
        architecture: projection.architecture,
        bits: projection.bits,
        byte_order: projection.byte_order,
        selected_slice,
        auditable_metadata: projection.auditable_metadata,
        rustc_commit: projection.rustc_commit,
        limitations,
    }
}

fn selected_slice(selection: MachoSelection) -> SelectedSlice {
    SelectedSlice {
        kind: "macho-selected-image-v1",
        container: "fat",
        offset: selection.offset,
        byte_length: selection.byte_length,
        cpu_type: selection.cpu_type,
        cpu_subtype: selection.cpu_subtype,
        container_table_sha256: hex(&selection.container_table_sha256),
    }
}

fn print_human(report: &Report<'_>) {
    println!(
        "{} {} ({}-bit, {})",
        report.format, report.architecture, report.bits, report.byte_order
    );
    println!(
        "artifact: {} ({} bytes, sha256 {})",
        report.artifact.path, report.artifact.bytes, report.artifact.sha256
    );
    match &report.auditable_metadata {
        Some(metadata) => println!(
            "cargo-auditable: {} packages, {} edges, section offset {}",
            metadata.packages.len(),
            metadata.dependency_edges.len(),
            metadata.file_offset
        ),
        None => println!("cargo-auditable: no confirmed .dep-v0 metadata"),
    }
    println!(
        "rustc paths: {} distinct hash(es)",
        report
            .rustc_commit
            .as_ref()
            .map_or(0, |commit| commit.hashes.len())
    );
    if let Some(slice) = &report.selected_slice {
        println!(
            "selected slice: offset {}, {} bytes, cpu type 0x{:x}, subtype 0x{:x}",
            slice.offset, slice.byte_length, slice.cpu_type, slice.cpu_subtype
        );
    }
}

fn format_core_error(error: &RustBinaryError) -> String {
    format!("Rust binary inspection failed: {error:?}")
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(DIGITS[usize::from(byte >> 4)] as char);
        result.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    result
}

fn print_help() {
    println!(
        "REA standalone CLI\n\nUsage:\n  rea inspect-rust-binary PATH [--json] [--architecture ARCH]\n  rea --version\n\nArchitectures: x86, x86_64, arm, arm64, arm64_32\nUniversal Mach-O files require --architecture."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_architectures() {
        assert_eq!(parse_architecture("amd64"), Ok(BinaryArchitecture::X86_64));
        assert_eq!(parse_architecture("arm64"), Ok(BinaryArchitecture::Arm64));
        assert!(parse_architecture("mips").is_err());
    }

    #[test]
    fn parses_json_and_path_options_without_node() {
        let parsed = parse_inspect_args(&[
            "--json".to_string(),
            "--architecture".to_string(),
            "arm64".to_string(),
            "/tmp/example".to_string(),
        ])
        .unwrap();
        assert_eq!(parsed.0, Path::new("/tmp/example"));
        assert_eq!(parsed.1, Some(BinaryArchitecture::Arm64));
        assert!(parsed.2);
    }
}
