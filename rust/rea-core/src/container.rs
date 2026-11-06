// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Symphony

//! Borrowed, format-neutral native-container facts.

use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use sha2::{Digest, Sha256};

use crate::architecture::{architecture_for_elf_machine, ElfArchitecture};
use crate::binary::{
    parse_elf_header, parse_elf_program_headers, parse_elf_section_headers, section_name,
    ByteOrder, ElfClass, ElfError,
};

/// Native binary format represented by the shared container boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinaryFormat {
    /// ELF executable or shared object.
    Elf,
    /// Portable Executable image.
    Pe,
    /// Thin Mach-O image.
    MachO,
}

/// Format-neutral architecture identity with the original machine value kept
/// for unknown targets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinaryArchitecture {
    /// 32-bit x86.
    X86,
    /// 64-bit x86.
    X86_64,
    /// 32-bit ARM.
    Arm,
    /// 64-bit ARM.
    Arm64,
    /// 32-bit pointer ABI using the ARM64 instruction set.
    Arm64_32,
    /// 32-bit PowerPC.
    PowerPc,
    /// 64-bit PowerPC.
    PowerPc64,
    /// MIPS.
    Mips,
    /// RISC-V.
    Riscv,
    /// Hexagon.
    Hexagon,
    /// IBM S/390.
    S390,
    /// LoongArch.
    LoongArch,
    /// Unknown format-specific machine value.
    Unknown(u32),
}

impl BinaryArchitecture {
    /// Stable REA display spelling.
    pub const fn name(self) -> &'static str {
        match self {
            Self::X86 => "386",
            Self::X86_64 => "amd64",
            Self::Arm => "arm",
            Self::Arm64 => "arm64",
            Self::Arm64_32 => "arm64_32",
            Self::PowerPc => "ppc",
            Self::PowerPc64 => "ppc64",
            Self::Mips => "mips",
            Self::Riscv => "riscv",
            Self::Hexagon => "hexagon",
            Self::S390 => "s390",
            Self::LoongArch => "loongarch",
            Self::Unknown(_) => "unknown",
        }
    }

    /// Preserves an original machine value when this architecture is unknown.
    pub const fn raw(self) -> Option<u32> {
        match self {
            Self::Unknown(value) => Some(value),
            _ => None,
        }
    }
}

const fn from_elf_architecture(architecture: ElfArchitecture) -> BinaryArchitecture {
    match architecture {
        ElfArchitecture::X86 => BinaryArchitecture::X86,
        ElfArchitecture::X86_64 => BinaryArchitecture::X86_64,
        ElfArchitecture::Mips => BinaryArchitecture::Mips,
        ElfArchitecture::PowerPc => BinaryArchitecture::PowerPc,
        ElfArchitecture::Arm => BinaryArchitecture::Arm,
        ElfArchitecture::Arm64 => BinaryArchitecture::Arm64,
        ElfArchitecture::Hexagon => BinaryArchitecture::Hexagon,
        ElfArchitecture::S390 => BinaryArchitecture::S390,
        ElfArchitecture::LoongArch => BinaryArchitecture::LoongArch,
        ElfArchitecture::Riscv => BinaryArchitecture::Riscv,
        ElfArchitecture::Ppc64 => BinaryArchitecture::PowerPc64,
        ElfArchitecture::Unknown(value) => BinaryArchitecture::Unknown(value as u32),
    }
}

/// A file-backed virtual mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileMapping {
    /// Virtual address represented by the first file byte.
    pub address: u64,
    /// File offset of the first mapped byte.
    pub offset: u64,
    /// Number of file-backed bytes.
    pub size: u64,
}

/// Loader permissions associated with a mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadRegion {
    /// File-backed portion of the load region.
    pub mapping: FileMapping,
    /// Declared bytes in memory, including zero-fill.
    pub memory_size: u64,
    /// Whether the region is readable.
    pub read: bool,
    /// Whether the region is writable.
    pub write: bool,
    /// Whether the region is executable.
    pub execute: bool,
    /// Raw format-specific current protection mask, when available.
    pub current_protection: Option<u32>,
    /// Raw format-specific maximum protection mask, when available.
    pub maximum_protection: Option<u32>,
}

/// Declared virtual memory with no file-backed bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZeroFillMapping {
    /// Virtual address of the zero-filled range.
    pub address: u64,
    /// Number of zero-initialized bytes.
    pub size: u64,
}

/// One normalized section with a borrowed optional name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageSection<'a> {
    /// Section name bytes, or `None` when names were unavailable/malformed.
    pub name: Option<&'a [u8]>,
    /// Mach-O segment name when the section has one.
    pub segment_name: Option<&'a [u8]>,
    /// File offset declared by the section.
    pub offset: u64,
    /// File size declared by the section.
    pub size: u64,
    /// Whether the declared bytes fit in the input.
    pub file_backed: bool,
    /// Whether the section is not writable.
    pub read_only: bool,
    /// Whether ELF marks the section as compressed.
    pub compressed: bool,
    /// ELF virtual address.
    pub address: u64,
    /// Format-specific section type, when the format defines one.
    pub section_type: u32,
    /// Declared file offset before admission as file-backed.
    pub declared_offset: u64,
    /// Declared file size before admission as file-backed.
    pub declared_size: u64,
    /// PE virtual address relative to the image base.
    pub virtual_address: Option<u32>,
    /// PE declared virtual size.
    pub virtual_size: Option<u32>,
    /// PE declared raw size.
    pub raw_size: Option<u32>,
    /// PE file alignment.
    pub file_alignment: Option<u32>,
    /// PE section characteristics.
    pub characteristics: Option<u32>,
    /// Mach-O segment mapping owning the section, when mapped.
    pub segment_mapping: Option<FileMapping>,
    /// Whether the Mach-O segment containing the section was unmapped.
    pub segment_unmapped: bool,
}

/// Declared ELF PT_DYNAMIC file extent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfDynamicSegment {
    /// File offset of the dynamic segment.
    pub offset: u64,
    /// Declared file size of the dynamic segment.
    pub size: u64,
}

/// One PE optional-header data directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeDataDirectory {
    /// RVA declared by the directory.
    pub virtual_address: u32,
    /// Byte size declared by the directory.
    pub size: u32,
}

/// Format-neutral native container facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryContainer<'a> {
    /// Format identity.
    pub format: BinaryFormat,
    /// Normalized architecture.
    pub architecture: BinaryArchitecture,
    /// Address width.
    pub class: ElfClass,
    /// Declared byte order.
    pub byte_order: ByteOrder,
    /// File-backed load mappings.
    pub mappings: Vec<FileMapping>,
    /// Loader regions and permissions.
    pub load_regions: Vec<LoadRegion>,
    /// File-backed ranges marked executable by the image format.
    pub executable_mappings: Vec<FileMapping>,
    /// Declared zero-fill ranges.
    pub zero_fills: Vec<ZeroFillMapping>,
    /// Parsed sections.
    pub sections: Vec<ImageSection<'a>>,
    /// Whether section names could be established completely.
    pub section_names_available: bool,
    /// Original ELF machine value.
    pub elf_machine: Option<u16>,
    /// Original ELF object type.
    pub elf_type: Option<u16>,
    /// Preferred image base for PE images.
    pub image_base: Option<u64>,
    /// File-backed PE headers mapped at the image base.
    pub header_mapping: Option<FileMapping>,
    /// Whether Mach-O chained fixups were declared.
    pub macho_chained_fixups: bool,
    /// ELF PT_DYNAMIC declarations.
    pub elf_dynamic_segments: Vec<ElfDynamicSegment>,
    /// PE machine value.
    pub pe_machine: Option<u16>,
    /// PE section alignment.
    pub pe_section_alignment: Option<u32>,
    /// PE file alignment.
    pub pe_file_alignment: Option<u32>,
    /// PE optional-header data directories.
    pub pe_data_directories: Vec<PeDataDirectory>,
    /// PE DLL characteristics and their optional-header file offset.
    pub dll_characteristics: Option<u16>,
    /// File offset of PE DLL characteristics.
    pub dll_characteristics_offset: Option<u64>,
}

/// Stable failures at the shared native-container boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainerError {
    /// The input was not an ELF image for this adapter.
    NotElf,
    /// The input was not a PE image for this adapter.
    NotPe,
    /// The input was not a thin Mach-O image for this adapter.
    NotMachO,
    /// ELF structure parsing failed.
    Elf(ElfError),
    /// A recognized container was structurally malformed.
    Malformed,
    /// A recognized container uses an unsupported variant.
    Unsupported,
}

/// A selected slice of a universal Mach-O file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachoSlice<'a> {
    /// Original file offset of the selected slice.
    pub offset: u64,
    /// Declared size of the selected slice.
    pub size: u64,
    /// Raw FAT CPU type.
    pub cpu_type: u32,
    /// Raw FAT CPU subtype, including capability bits.
    pub cpu_subtype: u32,
    /// FAT alignment exponent.
    pub alignment_exponent: u32,
    /// SHA-256 of the complete FAT header/table bytes.
    pub table_sha256: [u8; 32],
    /// Normalized facts parsed from the selected thin image.
    pub container: BinaryContainer<'a>,
}

/// Failures while identifying and selecting a universal Mach-O slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UniversalMachoError {
    /// The input is not a universal Mach-O file.
    NotUniversal,
    /// The FAT table is malformed or outside the file.
    Malformed,
    /// Universal files require an explicit architecture selection.
    SelectionRequired,
    /// No slice matches the requested architecture.
    ArchitectureNotFound,
    /// More than one slice matches the requested architecture.
    DuplicateArchitecture,
    /// A slice architecture was supplied for an image without a FAT container.
    ArchitectureNotApplicable,
    /// The selected thin image is malformed or unsupported.
    Thin(ContainerError),
}

fn macho_architecture(cpu: u32) -> BinaryArchitecture {
    match cpu {
        7 => BinaryArchitecture::X86,
        0x0100_0007 => BinaryArchitecture::X86_64,
        12 => BinaryArchitecture::Arm,
        0x0100_000c => BinaryArchitecture::Arm64,
        0x0200_000c => BinaryArchitecture::Arm64_32,
        18 => BinaryArchitecture::PowerPc,
        0x0100_0012 => BinaryArchitecture::PowerPc64,
        value => BinaryArchitecture::Unknown(value),
    }
}

fn macho_name(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    &bytes[..end]
}

fn macho_u32(bytes: &[u8], offset: usize, little: bool) -> Result<u32, ContainerError> {
    let end = offset.checked_add(4).ok_or(ContainerError::Malformed)?;
    let value = bytes.get(offset..end).ok_or(ContainerError::Malformed)?;
    let value: [u8; 4] = value.try_into().map_err(|_| ContainerError::Malformed)?;
    Ok(if little {
        u32::from_le_bytes(value)
    } else {
        u32::from_be_bytes(value)
    })
}

fn macho_u64(bytes: &[u8], offset: usize, little: bool) -> Result<u64, ContainerError> {
    let end = offset.checked_add(8).ok_or(ContainerError::Malformed)?;
    let value = bytes.get(offset..end).ok_or(ContainerError::Malformed)?;
    let value: [u8; 8] = value.try_into().map_err(|_| ContainerError::Malformed)?;
    Ok(if little {
        u64::from_le_bytes(value)
    } else {
        u64::from_be_bytes(value)
    })
}

/// Reads a thin 32-bit or 64-bit Mach-O image into the shared model.
pub fn read_macho_container<'a>(bytes: &'a [u8]) -> Result<BinaryContainer<'a>, ContainerError> {
    if bytes.len() < 4 {
        return Err(ContainerError::NotMachO);
    }
    let magic = u32::from_be_bytes(
        bytes[..4]
            .try_into()
            .map_err(|_| ContainerError::NotMachO)?,
    );
    let (class, little) = match magic {
        0xfeedface => (ElfClass::Elf32, false),
        0xcefaedfe => (ElfClass::Elf32, true),
        0xfeedfacf => (ElfClass::Elf64, false),
        0xcffaedfe => (ElfClass::Elf64, true),
        _ => return Err(ContainerError::NotMachO),
    };
    let header_size: usize = if class == ElfClass::Elf64 { 32 } else { 28 };
    let cpu = macho_u32(bytes, 4, little)?;
    let command_count =
        usize::try_from(macho_u32(bytes, 16, little)?).map_err(|_| ContainerError::Malformed)?;
    let command_bytes =
        usize::try_from(macho_u32(bytes, 20, little)?).map_err(|_| ContainerError::Malformed)?;
    let command_end = header_size
        .checked_add(command_bytes)
        .ok_or(ContainerError::Malformed)?;
    if command_end > bytes.len() {
        return Err(ContainerError::Malformed);
    }

    let mut mappings = Vec::new();
    let mut load_regions = Vec::new();
    let mut executable_mappings = Vec::new();
    let mut zero_fills = Vec::new();
    let mut sections = Vec::new();
    let mut chained_fixups = false;
    let mut cursor = header_size;
    for _ in 0..command_count {
        let command = macho_u32(bytes, cursor, little)?;
        let size = usize::try_from(macho_u32(bytes, cursor + 4, little)?)
            .map_err(|_| ContainerError::Malformed)?;
        if size < 8 || cursor.checked_add(size).ok_or(ContainerError::Malformed)? > command_end {
            return Err(ContainerError::Malformed);
        }
        if command == 0x8000_0034 {
            chained_fixups = true;
        }
        let segment_command = if class == ElfClass::Elf64 { 0x19 } else { 1 };
        if command == segment_command {
            let wide = class == ElfClass::Elf64;
            let segment_header = if wide { 72 } else { 56 };
            let section_width = if wide { 80 } else { 68 };
            if size < segment_header {
                return Err(ContainerError::Malformed);
            }
            let segment_name = macho_name(&bytes[cursor + 8..cursor + 24]);
            let (address, memory_size, file_offset, file_size, max_protection, protection, count) =
                if wide {
                    (
                        macho_u64(bytes, cursor + 24, little)?,
                        macho_u64(bytes, cursor + 32, little)?,
                        macho_u64(bytes, cursor + 40, little)?,
                        macho_u64(bytes, cursor + 48, little)?,
                        macho_u32(bytes, cursor + 56, little)?,
                        macho_u32(bytes, cursor + 60, little)?,
                        usize::try_from(macho_u32(bytes, cursor + 64, little)?)
                            .map_err(|_| ContainerError::Malformed)?,
                    )
                } else {
                    (
                        u64::from(macho_u32(bytes, cursor + 24, little)?),
                        u64::from(macho_u32(bytes, cursor + 28, little)?),
                        u64::from(macho_u32(bytes, cursor + 32, little)?),
                        u64::from(macho_u32(bytes, cursor + 36, little)?),
                        macho_u32(bytes, cursor + 40, little)?,
                        macho_u32(bytes, cursor + 44, little)?,
                        usize::try_from(macho_u32(bytes, cursor + 48, little)?)
                            .map_err(|_| ContainerError::Malformed)?,
                    )
                };
            let section_bytes = count
                .checked_mul(section_width)
                .ok_or(ContainerError::Malformed)?;
            if segment_header
                .checked_add(section_bytes)
                .ok_or(ContainerError::Malformed)?
                > size
            {
                return Err(ContainerError::Malformed);
            }
            let is_pagezero = segment_name == b"__PAGEZERO";
            let file_end = file_offset
                .checked_add(file_size)
                .ok_or(ContainerError::Malformed)?;
            if file_end > bytes.len() as u64 && file_size != 0 {
                return Err(ContainerError::Malformed);
            }
            let mapping = FileMapping {
                address,
                offset: file_offset,
                size: file_size,
            };
            if !is_pagezero && file_size != 0 {
                mappings.push(mapping);
                let load = LoadRegion {
                    mapping,
                    memory_size,
                    read: protection & 1 != 0,
                    write: protection & 2 != 0,
                    execute: protection & 4 != 0,
                    current_protection: Some(protection),
                    maximum_protection: Some(max_protection),
                };
                load_regions.push(load);
                if protection & 4 != 0 {
                    executable_mappings.push(mapping);
                }
            }
            if !is_pagezero && memory_size > file_size {
                zero_fills.push(ZeroFillMapping {
                    address: address
                        .checked_add(file_size)
                        .ok_or(ContainerError::Malformed)?,
                    size: memory_size - file_size,
                });
            }
            for section_index in 0..count {
                let section = cursor + segment_header + section_index * section_width;
                let section_name_offset = section;
                let (section_address, section_size, section_offset, flags) = if wide {
                    (
                        macho_u64(bytes, section + 32, little)?,
                        macho_u64(bytes, section + 40, little)?,
                        u64::from(macho_u32(bytes, section + 48, little)?),
                        macho_u32(bytes, section + 64, little)?,
                    )
                } else {
                    (
                        u64::from(macho_u32(bytes, section + 32, little)?),
                        u64::from(macho_u32(bytes, section + 36, little)?),
                        u64::from(macho_u32(bytes, section + 40, little)?),
                        macho_u32(bytes, section + 56, little)?,
                    )
                };
                let section_name =
                    macho_name(&bytes[section_name_offset..section_name_offset + 16]);
                let zero_fill = flags & 0xff == 1;
                let file_backed = !zero_fill
                    && section_offset
                        .checked_add(section_size)
                        .map(|end| end <= bytes.len() as u64)
                        .unwrap_or(false);
                let address_delta = section_address.checked_sub(address);
                let file_delta = section_offset.checked_sub(file_offset);
                let in_memory = address_delta
                    .map(|delta| delta <= memory_size && section_size <= memory_size - delta)
                    .unwrap_or(false);
                let in_file = file_delta
                    .map(|delta| delta <= file_size && section_size <= file_size - delta)
                    .unwrap_or(false);
                let file_backed = file_backed && !is_pagezero && in_memory && in_file;
                sections.push(ImageSection {
                    name: Some(section_name),
                    segment_name: Some(segment_name),
                    offset: section_offset,
                    size: section_size,
                    file_backed,
                    read_only: file_backed
                        && protection & 1 != 0
                        && protection & 2 == 0
                        && flags & 0x8000_0400 == 0,
                    compressed: false,
                    section_type: flags & 0xff,
                    address: section_address,
                    declared_offset: section_offset,
                    declared_size: section_size,
                    virtual_address: None,
                    virtual_size: None,
                    raw_size: None,
                    file_alignment: None,
                    characteristics: None,
                    segment_mapping: if is_pagezero { None } else { Some(mapping) },
                    segment_unmapped: is_pagezero,
                });
            }
            let _ = max_protection;
        }
        cursor += size;
    }
    Ok(BinaryContainer {
        format: BinaryFormat::MachO,
        architecture: macho_architecture(cpu),
        class,
        byte_order: if little {
            ByteOrder::Little
        } else {
            ByteOrder::Big
        },
        mappings,
        load_regions,
        executable_mappings,
        zero_fills,
        sections,
        section_names_available: true,
        elf_machine: None,
        elf_type: None,
        image_base: None,
        header_mapping: None,
        macho_chained_fixups: chained_fixups,
        elf_dynamic_segments: Vec::new(),
        pe_machine: None,
        pe_section_alignment: None,
        pe_file_alignment: None,
        pe_data_directories: Vec::new(),
        dll_characteristics: None,
        dll_characteristics_offset: None,
    })
}

fn universal_u32(bytes: &[u8], offset: usize, little: bool) -> Result<u32, UniversalMachoError> {
    let end = offset
        .checked_add(4)
        .ok_or(UniversalMachoError::Malformed)?;
    let value = bytes
        .get(offset..end)
        .ok_or(UniversalMachoError::Malformed)?;
    let value: [u8; 4] = value
        .try_into()
        .map_err(|_| UniversalMachoError::Malformed)?;
    Ok(if little {
        u32::from_le_bytes(value)
    } else {
        u32::from_be_bytes(value)
    })
}

fn universal_u64(bytes: &[u8], offset: usize, little: bool) -> Result<u64, UniversalMachoError> {
    let end = offset
        .checked_add(8)
        .ok_or(UniversalMachoError::Malformed)?;
    let value = bytes
        .get(offset..end)
        .ok_or(UniversalMachoError::Malformed)?;
    let value: [u8; 8] = value
        .try_into()
        .map_err(|_| UniversalMachoError::Malformed)?;
    Ok(if little {
        u64::from_le_bytes(value)
    } else {
        u64::from_be_bytes(value)
    })
}

fn add_slice_offset(
    container: &mut BinaryContainer<'_>,
    offset: u64,
) -> Result<(), UniversalMachoError> {
    for mapping in &mut container.mappings {
        mapping.offset = mapping
            .offset
            .checked_add(offset)
            .ok_or(UniversalMachoError::Malformed)?;
    }
    for mapping in &mut container.executable_mappings {
        mapping.offset = mapping
            .offset
            .checked_add(offset)
            .ok_or(UniversalMachoError::Malformed)?;
    }
    for section in &mut container.sections {
        section.offset = section
            .offset
            .checked_add(offset)
            .ok_or(UniversalMachoError::Malformed)?;
    }
    Ok(())
}

/// Selects and parses one thin slice from a universal Mach-O file.
pub fn read_universal_macho_slice<'a>(
    bytes: &'a [u8],
    requested: Option<BinaryArchitecture>,
) -> Result<MachoSlice<'a>, UniversalMachoError> {
    if bytes.len() < 8 {
        return Err(UniversalMachoError::NotUniversal);
    }
    let magic = u32::from_be_bytes(
        bytes[..4]
            .try_into()
            .map_err(|_| UniversalMachoError::NotUniversal)?,
    );
    let (wide, little) = match magic {
        0xcafe_babe => (false, false),
        0xbeba_feca => (false, true),
        0xcafe_babf => (true, false),
        0xbfba_feca => (true, true),
        _ => return Err(UniversalMachoError::NotUniversal),
    };
    let count = usize::try_from(universal_u32(bytes, 4, little)?)
        .map_err(|_| UniversalMachoError::Malformed)?;
    let entry_size = if wide { 32 } else { 20 };
    let table_size = count
        .checked_mul(entry_size)
        .ok_or(UniversalMachoError::Malformed)?;
    let table_end = 8usize
        .checked_add(table_size)
        .ok_or(UniversalMachoError::Malformed)?;
    if table_end > bytes.len() {
        return Err(UniversalMachoError::Malformed);
    }
    let requested = requested.ok_or(UniversalMachoError::SelectionRequired)?;
    let mut selected: Option<(u64, u64, u32, u32, u32)> = None;
    for index in 0..count {
        let entry = 8 + index * entry_size;
        let cpu = universal_u32(bytes, entry, little)?;
        let cpu_subtype = universal_u32(bytes, entry + 4, little)?;
        let architecture = macho_architecture(cpu);
        if architecture != requested {
            continue;
        }
        let offset = if wide {
            universal_u64(bytes, entry + 8, little)?
        } else {
            u64::from(universal_u32(bytes, entry + 8, little)?)
        };
        let size = if wide {
            universal_u64(bytes, entry + 16, little)?
        } else {
            u64::from(universal_u32(bytes, entry + 12, little)?)
        };
        let alignment_exponent = universal_u32(bytes, entry + if wide { 24 } else { 16 }, little)?;
        if selected
            .replace((offset, size, cpu, cpu_subtype, alignment_exponent))
            .is_some()
        {
            return Err(UniversalMachoError::DuplicateArchitecture);
        }
    }
    let (offset, size, cpu_type, cpu_subtype, alignment_exponent) =
        selected.ok_or(UniversalMachoError::ArchitectureNotFound)?;
    if alignment_exponent > 52 {
        return Err(UniversalMachoError::Malformed);
    }
    let alignment = 1u64
        .checked_shl(alignment_exponent)
        .ok_or(UniversalMachoError::Malformed)?;
    if offset < table_end as u64 || offset % alignment != 0 || size == 0 {
        return Err(UniversalMachoError::Malformed);
    }
    let end = offset
        .checked_add(size)
        .ok_or(UniversalMachoError::Malformed)?;
    if end > bytes.len() as u64 {
        return Err(UniversalMachoError::Malformed);
    }
    let start = usize::try_from(offset).map_err(|_| UniversalMachoError::Malformed)?;
    let end = usize::try_from(end).map_err(|_| UniversalMachoError::Malformed)?;
    let mut container =
        read_macho_container(&bytes[start..end]).map_err(UniversalMachoError::Thin)?;
    let embedded_cpu = match container.architecture {
        BinaryArchitecture::X86 => 7,
        BinaryArchitecture::X86_64 => 0x0100_0007,
        BinaryArchitecture::Arm => 12,
        BinaryArchitecture::Arm64 => 0x0100_000c,
        BinaryArchitecture::Arm64_32 => 0x0200_000c,
        BinaryArchitecture::PowerPc => 18,
        BinaryArchitecture::PowerPc64 => 0x0100_0012,
        BinaryArchitecture::Mips => 8,
        BinaryArchitecture::Riscv => 0x00f3,
        BinaryArchitecture::Hexagon => 164,
        BinaryArchitecture::S390 => 22,
        BinaryArchitecture::LoongArch => 258,
        BinaryArchitecture::Unknown(value) => value,
    };
    if embedded_cpu != cpu_type {
        return Err(UniversalMachoError::Malformed);
    }
    add_slice_offset(&mut container, offset)?;
    let mut digest = Sha256::new();
    digest.update(&bytes[..table_end]);
    let table_sha256: [u8; 32] = digest.finalize().into();
    Ok(MachoSlice {
        offset,
        size,
        cpu_type,
        cpu_subtype,
        alignment_exponent,
        table_sha256,
        container,
    })
}

fn pe_u16(bytes: &[u8], offset: usize) -> Result<u16, ContainerError> {
    let end = offset.checked_add(2).ok_or(ContainerError::Malformed)?;
    bytes
        .get(offset..end)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(ContainerError::Malformed)
}

fn pe_u32(bytes: &[u8], offset: usize) -> Result<u32, ContainerError> {
    let end = offset.checked_add(4).ok_or(ContainerError::Malformed)?;
    bytes
        .get(offset..end)
        .and_then(|value| value.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(ContainerError::Malformed)
}

fn pe_u64(bytes: &[u8], offset: usize) -> Result<u64, ContainerError> {
    let end = offset.checked_add(8).ok_or(ContainerError::Malformed)?;
    bytes
        .get(offset..end)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or(ContainerError::Malformed)
}

fn pe_architecture(machine: u16) -> BinaryArchitecture {
    match machine {
        0x014c => BinaryArchitecture::X86,
        0x8664 => BinaryArchitecture::X86_64,
        0x01c0 | 0x01c4 => BinaryArchitecture::Arm,
        0xaa64 => BinaryArchitecture::Arm64,
        0x01f0 => BinaryArchitecture::PowerPc,
        value => BinaryArchitecture::Unknown(u32::from(value)),
    }
}

/// Reads a PE32 or PE32+ image into the shared borrowed container model.
pub fn read_pe_container<'a>(bytes: &'a [u8]) -> Result<BinaryContainer<'a>, ContainerError> {
    if bytes.len() < 2 || bytes[..2] != *b"MZ" {
        return Err(ContainerError::NotPe);
    }
    let pe_offset = usize::try_from(pe_u32(bytes, 0x3c)?).map_err(|_| ContainerError::Malformed)?;
    let signature_end = pe_offset.checked_add(4).ok_or(ContainerError::Malformed)?;
    if bytes.get(pe_offset..signature_end) != Some(b"PE\0\0") {
        return Err(ContainerError::Malformed);
    }
    let machine = pe_u16(bytes, pe_offset + 4)?;
    let section_count = usize::from(pe_u16(bytes, pe_offset + 6)?);
    let optional_size = usize::from(pe_u16(bytes, pe_offset + 20)?);
    let optional = pe_offset.checked_add(24).ok_or(ContainerError::Malformed)?;
    let optional_end = optional
        .checked_add(optional_size)
        .ok_or(ContainerError::Malformed)?;
    if optional_end > bytes.len() {
        return Err(ContainerError::Malformed);
    }
    let magic = pe_u16(bytes, optional)?;
    let (
        class,
        image_base,
        section_alignment,
        file_alignment,
        directory_count_offset,
        directory_offset,
    ) = match magic {
        0x10b => (
            ElfClass::Elf32,
            u64::from(pe_u32(bytes, optional + 28)?),
            pe_u32(bytes, optional + 32)?,
            pe_u32(bytes, optional + 36)?,
            optional + 92,
            optional + 96,
        ),
        0x20b => (
            ElfClass::Elf64,
            pe_u64(bytes, optional + 24)?,
            pe_u32(bytes, optional + 32)?,
            pe_u32(bytes, optional + 36)?,
            optional + 108,
            optional + 112,
        ),
        _ => return Err(ContainerError::Unsupported),
    };
    if section_alignment == 0 || file_alignment == 0 {
        return Err(ContainerError::Malformed);
    }
    let directory_count = usize::try_from(pe_u32(bytes, directory_count_offset)?)
        .map_err(|_| ContainerError::Malformed)?;
    let directory_bytes = directory_count
        .checked_mul(8)
        .ok_or(ContainerError::Malformed)?;
    if directory_offset
        .checked_add(directory_bytes)
        .ok_or(ContainerError::Malformed)?
        > optional_end
    {
        return Err(ContainerError::Malformed);
    }
    let mut pe_data_directories = Vec::with_capacity(directory_count);
    for index in 0..directory_count {
        let entry = directory_offset + index * 8;
        pe_data_directories.push(PeDataDirectory {
            virtual_address: pe_u32(bytes, entry)?,
            size: pe_u32(bytes, entry + 4)?,
        });
    }
    let dll_characteristics = pe_u16(bytes, optional + 70)?;
    let header_size =
        usize::try_from(pe_u32(bytes, optional + 60)?).map_err(|_| ContainerError::Malformed)?;
    let section_table_size = section_count
        .checked_mul(40)
        .ok_or(ContainerError::Malformed)?;
    let section_table = optional_end;
    let section_table_end = section_table
        .checked_add(section_table_size)
        .ok_or(ContainerError::Malformed)?;
    if section_table_end > bytes.len() {
        return Err(ContainerError::Malformed);
    }

    let header_mapping = FileMapping {
        address: image_base,
        offset: 0,
        size: header_size.min(bytes.len()) as u64,
    };
    let mut mappings = Vec::new();
    let mut executable_mappings = Vec::new();
    let mut zero_fills = Vec::new();
    let mut sections = Vec::new();
    for index in 0..section_count {
        let entry = section_table + index * 40;
        let name_bytes = bytes
            .get(entry..entry + 8)
            .ok_or(ContainerError::Malformed)?;
        let name_end = name_bytes.iter().position(|&byte| byte == 0).unwrap_or(8);
        let name =
            core::str::from_utf8(&name_bytes[..name_end]).map_err(|_| ContainerError::Malformed)?;
        let virtual_size = pe_u32(bytes, entry + 8)? as u64;
        let virtual_address = u64::from(pe_u32(bytes, entry + 12)?);
        let raw_size = u64::from(pe_u32(bytes, entry + 16)?);
        let raw_offset = u64::from(pe_u32(bytes, entry + 20)?);
        let characteristics = pe_u32(bytes, entry + 36)?;
        let address = image_base
            .checked_add(virtual_address)
            .ok_or(ContainerError::Malformed)?;
        let mapped_size = raw_size.max(virtual_size);
        if class == ElfClass::Elf32
            && address
                .checked_add(mapped_size)
                .map(|end| end > (1u64 << 32))
                .unwrap_or(true)
        {
            return Err(ContainerError::Malformed);
        }
        let raw_end = raw_offset
            .checked_add(raw_size)
            .ok_or(ContainerError::Malformed)?;
        if raw_end > bytes.len() as u64 {
            return Err(ContainerError::Malformed);
        }
        let file_backed = raw_size > 0;
        let mapping = FileMapping {
            address,
            offset: raw_offset,
            size: raw_size,
        };
        if file_backed {
            mappings.push(mapping);
            if characteristics & 0x2000_0000 != 0 {
                executable_mappings.push(mapping);
            }
        }
        if virtual_size > raw_size {
            zero_fills.push(ZeroFillMapping {
                address: address + raw_size,
                size: virtual_size - raw_size,
            });
        }
        let read_only = file_backed
            && characteristics & 0x4000_0000 != 0
            && characteristics & 0x8000_0000 == 0
            && characteristics & 0x2000_0000 == 0
            && characteristics & 0x40 != 0;
        sections.push(ImageSection {
            name: Some(name.as_bytes()),
            segment_name: None,
            offset: raw_offset,
            size: raw_size,
            file_backed,
            read_only,
            compressed: false,
            section_type: 0,
            address,
            declared_offset: raw_offset,
            declared_size: raw_size,
            virtual_address: Some(pe_u32(bytes, entry + 12)?),
            virtual_size: Some(u32::try_from(virtual_size).map_err(|_| ContainerError::Malformed)?),
            raw_size: Some(u32::try_from(raw_size).map_err(|_| ContainerError::Malformed)?),
            file_alignment: Some(file_alignment),
            characteristics: Some(characteristics),
            segment_mapping: None,
            segment_unmapped: false,
        });
    }
    Ok(BinaryContainer {
        format: BinaryFormat::Pe,
        architecture: pe_architecture(machine),
        class,
        byte_order: ByteOrder::Little,
        mappings,
        load_regions: Vec::new(),
        executable_mappings,
        zero_fills,
        sections,
        section_names_available: true,
        elf_machine: None,
        elf_type: None,
        image_base: Some(image_base),
        header_mapping: Some(header_mapping),
        macho_chained_fixups: false,
        elf_dynamic_segments: Vec::new(),
        pe_machine: Some(machine),
        pe_section_alignment: Some(section_alignment),
        pe_file_alignment: Some(file_alignment),
        pe_data_directories,
        dll_characteristics: Some(dll_characteristics),
        dll_characteristics_offset: Some((optional + 70) as u64),
    })
}

/// Reads ELF structure facts into the shared borrowed container model.
pub fn read_elf_container<'a>(bytes: &'a [u8]) -> Result<BinaryContainer<'a>, ContainerError> {
    if bytes.len() < 4 || bytes[..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(ContainerError::NotElf);
    }
    let header = parse_elf_header(bytes).map_err(ContainerError::Elf)?;
    let mut mappings = Vec::new();
    let mut load_regions = Vec::new();
    let mut executable_mappings = Vec::new();
    let mut zero_fills = Vec::new();
    let mut dynamic_segments = Vec::new();
    for entry in parse_elf_program_headers(bytes, header).map_err(ContainerError::Elf)? {
        let entry = entry.map_err(ContainerError::Elf)?;
        if entry.segment_type == 2 {
            dynamic_segments.push(ElfDynamicSegment {
                offset: entry.offset,
                size: entry.file_size,
            });
            continue;
        }
        if entry.segment_type != 1 {
            continue;
        }
        let mapping = FileMapping {
            address: entry.virtual_address,
            offset: entry.offset,
            size: entry.file_size,
        };
        mappings.push(mapping);
        load_regions.push(LoadRegion {
            mapping,
            memory_size: entry.memory_size,
            read: entry.flags & 4 != 0,
            write: entry.flags & 2 != 0,
            execute: entry.flags & 1 != 0,
            current_protection: None,
            maximum_protection: None,
        });
        if entry.flags & 1 != 0 {
            executable_mappings.push(mapping);
        }
        if entry.memory_size > entry.file_size {
            zero_fills.push(ZeroFillMapping {
                address: entry.virtual_address.saturating_add(entry.file_size),
                size: entry.memory_size - entry.file_size,
            });
        }
    }

    let mut sections = Vec::new();
    let mut section_names_available = true;
    if header.section_header_count > 0 {
        let headers = parse_elf_section_headers(bytes, header)
            .map_err(ContainerError::Elf)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(ContainerError::Elf)?;
        let string_table = headers.get(usize::from(header.section_name_index)).copied();
        if string_table.is_none() || string_table.is_some_and(|table| table.flags & 0x800 != 0) {
            section_names_available = false;
        }
        for section in headers {
            let name = string_table.and_then(|table| section_name(bytes, section, table).ok());
            if name.is_none() && section.name_offset != 0 {
                section_names_available = false;
            }
            let file_backed = section
                .offset
                .checked_add(section.size)
                .map(|end| end <= bytes.len() as u64)
                .unwrap_or(false);
            sections.push(ImageSection {
                name,
                segment_name: None,
                offset: section.offset,
                size: section.size,
                file_backed,
                read_only: section.section_type == 1
                    && file_backed
                    && section.flags & 0x800 == 0
                    && section.flags & 1 == 0
                    && section.flags & 4 == 0
                    && section.flags & 2 != 0,
                compressed: section.flags & 0x800 != 0,
                section_type: section.section_type,
                address: section.address,
                declared_offset: section.offset,
                declared_size: section.size,
                virtual_address: None,
                virtual_size: None,
                raw_size: None,
                file_alignment: None,
                characteristics: None,
                segment_mapping: None,
                segment_unmapped: false,
            });
        }
    }

    Ok(BinaryContainer {
        format: BinaryFormat::Elf,
        architecture: from_elf_architecture(architecture_for_elf_machine(header.machine)),
        class: header.class,
        byte_order: header.byte_order,
        mappings,
        load_regions,
        executable_mappings,
        zero_fills,
        sections,
        section_names_available,
        elf_machine: Some(header.machine),
        elf_type: Some(header.object_type),
        image_base: None,
        header_mapping: None,
        macho_chained_fixups: false,
        elf_dynamic_segments: dynamic_segments,
        pe_machine: None,
        pe_section_alignment: None,
        pe_file_alignment: None,
        pe_data_directories: Vec::new(),
        dll_characteristics: None,
        dll_characteristics_offset: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf_input_at_the_adapter_boundary() {
        assert_eq!(read_elf_container(b"MZ"), Err(ContainerError::NotElf));
    }

    #[test]
    fn preserves_elf_identity_and_empty_tables() {
        let mut bytes = [0u8; 64];
        bytes[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4..16].copy_from_slice(&[2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
        let container = read_elf_container(&bytes).unwrap();
        assert_eq!(container.format, BinaryFormat::Elf);
        assert_eq!(container.architecture, BinaryArchitecture::X86_64);
        assert!(container.mappings.is_empty());
        assert!(container.sections.is_empty());
    }

    #[test]
    fn reads_pe_section_mapping_and_architecture() {
        let mut bytes = vec![0u8; 768];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        let optional = 0x98;
        bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[optional + 24..optional + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x200u32.to_le_bytes());
        let section = optional + 0xf0;
        bytes[section..section + 6].copy_from_slice(b".rdata");
        bytes[section + 8..section + 12].copy_from_slice(&16u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&16u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0x40000040u32.to_le_bytes());
        let container = read_pe_container(&bytes).unwrap();
        assert_eq!(container.architecture, BinaryArchitecture::X86_64);
        assert_eq!(container.sections[0].name, Some(&b".rdata"[..]));
        assert!(container.sections[0].read_only);
    }

    #[test]
    fn reads_thin_little_endian_macho_identity() {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        bytes[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&2u32.to_le_bytes());
        let container = read_macho_container(&bytes).unwrap();
        assert_eq!(container.format, BinaryFormat::MachO);
        assert_eq!(container.architecture, BinaryArchitecture::X86_64);
        assert_eq!(container.byte_order, ByteOrder::Little);
        assert!(container.mappings.is_empty());
    }

    #[test]
    fn selects_and_rebases_a_universal_macho_slice() {
        let mut bytes = vec![0u8; 80];
        bytes[..4].copy_from_slice(&0xcafebabeu32.to_be_bytes());
        bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
        bytes[8..12].copy_from_slice(&0x0100_0007u32.to_be_bytes());
        bytes[16..20].copy_from_slice(&48u32.to_be_bytes());
        bytes[20..24].copy_from_slice(&32u32.to_be_bytes());
        bytes[48..52].copy_from_slice(&0xcffa_edfeu32.to_be_bytes());
        bytes[52..56].copy_from_slice(&0x0100_0007u32.to_le_bytes());
        let selected =
            read_universal_macho_slice(&bytes, Some(BinaryArchitecture::X86_64)).unwrap();
        assert_eq!(selected.offset, 48);
        assert_eq!(selected.container.architecture, BinaryArchitecture::X86_64);
        assert_eq!(
            read_universal_macho_slice(&bytes, None),
            Err(UniversalMachoError::SelectionRequired)
        );
    }
}
