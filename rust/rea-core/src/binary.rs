// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Symphony

//! Bounded, borrowed binary primitives and ELF fixed-header parsing.

/// Byte order declared by a binary image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ByteOrder {
    /// Least-significant byte first.
    Little,
    /// Most-significant byte first.
    Big,
}

/// ELF class declared by the image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfClass {
    /// 32-bit ELF fields.
    Elf32,
    /// 64-bit ELF fields.
    Elf64,
}

/// ELF fixed-header facts, all borrowed or scalar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfHeader {
    /// ELF class.
    pub class: ElfClass,
    /// ELF byte order.
    pub byte_order: ByteOrder,
    /// Object file type (`e_type`).
    pub object_type: u16,
    /// Target machine (`e_machine`).
    pub machine: u16,
    /// Entry point (`e_entry`), widened to `u64` for one representation.
    pub entry: u64,
    /// Program-header table file offset (`e_phoff`).
    pub program_header_offset: u64,
    /// Section-header table file offset (`e_shoff`).
    pub section_header_offset: u64,
    /// ELF header size (`e_ehsize`).
    pub header_size: u16,
    /// Program-header entry size (`e_phentsize`).
    pub program_header_entry_size: u16,
    /// Number of program-header entries (`e_phnum`).
    pub program_header_count: u16,
    /// Section-header entry size (`e_shentsize`).
    pub section_header_entry_size: u16,
    /// Number of section-header entries (`e_shnum`).
    pub section_header_count: u16,
    /// Section-name string-table index (`e_shstrndx`).
    pub section_name_index: u16,
}

/// One ELF program-header entry, widened to common scalar types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfProgramHeader {
    /// Segment type (`p_type`).
    pub segment_type: u32,
    /// Segment flags (`p_flags`).
    pub flags: u32,
    /// File offset of the segment.
    pub offset: u64,
    /// Virtual address of the segment.
    pub virtual_address: u64,
    /// Physical address of the segment.
    pub physical_address: u64,
    /// Number of file-backed bytes.
    pub file_size: u64,
    /// Number of memory bytes.
    pub memory_size: u64,
    /// Segment alignment.
    pub alignment: u64,
}

/// One ELF section-header entry, widened to common scalar types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfSectionHeader {
    /// String-table offset of the section name.
    pub name_offset: u32,
    /// Section type (`sh_type`).
    pub section_type: u32,
    /// Section flags (`sh_flags`).
    pub flags: u64,
    /// Virtual address of the section.
    pub address: u64,
    /// File offset of the section.
    pub offset: u64,
    /// Section size in bytes.
    pub size: u64,
    /// Related section index (`sh_link`).
    pub link: u32,
    /// Extra section information (`sh_info`).
    pub info: u32,
    /// Required alignment.
    pub alignment: u64,
    /// Entry size for table sections.
    pub entry_size: u64,
}

/// Stable failures from bounded ELF header parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfError {
    /// The input does not begin with the ELF magic bytes.
    InvalidMagic,
    /// The ELF class byte is not supported.
    InvalidClass(u8),
    /// The ELF data byte is not supported.
    InvalidByteOrder(u8),
    /// The ELF identification version is not one.
    InvalidIdentificationVersion(u8),
    /// The fixed header ended before the requested field.
    Truncated {
        /// Exclusive byte offset required by the attempted read.
        needed: usize,
        /// Number of bytes supplied by the caller.
        available: usize,
    },
    /// The `e_version` field is not one.
    InvalidHeaderVersion(u32),
    /// The program-header entry size does not match the ELF class.
    InvalidProgramHeaderEntrySize {
        /// Entry size required by the ELF class.
        expected: u16,
        /// Entry size declared by the input.
        actual: u16,
    },
    /// The program-header table does not fit in the supplied bytes.
    ProgramHeaderTableOutOfBounds,
    /// The section-header entry size does not match the ELF class.
    InvalidSectionHeaderEntrySize {
        /// Entry size required by the ELF class.
        expected: u16,
        /// Entry size declared by the input.
        actual: u16,
    },
    /// The section-header table does not fit in the supplied bytes.
    SectionHeaderTableOutOfBounds,
    /// A section-name string table does not fit in the supplied bytes.
    SectionNameTableOutOfBounds,
    /// A section name offset is outside its string table.
    SectionNameOffsetOutOfBounds,
    /// A section name has no terminating NUL byte.
    UnterminatedSectionName,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], ElfError> {
        let end = self.offset.saturating_add(N);
        if end > self.bytes.len() {
            return Err(ElfError::Truncated {
                needed: end,
                available: self.bytes.len(),
            });
        }
        let mut result = [0; N];
        result.copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
        Ok(result)
    }

    fn u8(&mut self) -> Result<u8, ElfError> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self, order: ByteOrder) -> Result<u16, ElfError> {
        let bytes = self.take::<2>()?;
        Ok(match order {
            ByteOrder::Little => u16::from_le_bytes(bytes),
            ByteOrder::Big => u16::from_be_bytes(bytes),
        })
    }

    fn u32(&mut self, order: ByteOrder) -> Result<u32, ElfError> {
        let bytes = self.take::<4>()?;
        Ok(match order {
            ByteOrder::Little => u32::from_le_bytes(bytes),
            ByteOrder::Big => u32::from_be_bytes(bytes),
        })
    }

    fn u64(&mut self, order: ByteOrder) -> Result<u64, ElfError> {
        let bytes = self.take::<8>()?;
        Ok(match order {
            ByteOrder::Little => u64::from_le_bytes(bytes),
            ByteOrder::Big => u64::from_be_bytes(bytes),
        })
    }
}

/// Parses only the fixed ELF header and never allocates or reads beyond it.
pub fn parse_elf_header(bytes: &[u8]) -> Result<ElfHeader, ElfError> {
    let mut cursor = Cursor::new(bytes);
    let magic = cursor.take::<4>()?;
    if magic != [0x7f, b'E', b'L', b'F'] {
        return Err(ElfError::InvalidMagic);
    }

    let class = match cursor.u8()? {
        1 => ElfClass::Elf32,
        value => {
            if value == 2 {
                ElfClass::Elf64
            } else {
                return Err(ElfError::InvalidClass(value));
            }
        }
    };
    let byte_order = match cursor.u8()? {
        1 => ByteOrder::Little,
        2 => ByteOrder::Big,
        value => return Err(ElfError::InvalidByteOrder(value)),
    };
    let identification_version = cursor.u8()?;
    if identification_version != 1 {
        return Err(ElfError::InvalidIdentificationVersion(
            identification_version,
        ));
    }
    let _os_abi = cursor.u8()?;
    let _abi_version = cursor.u8()?;
    let _padding = cursor.take::<7>()?;

    let object_type = cursor.u16(byte_order)?;
    let machine = cursor.u16(byte_order)?;
    let header_version = cursor.u32(byte_order)?;
    if header_version != 1 {
        return Err(ElfError::InvalidHeaderVersion(header_version));
    }

    let (entry, program_header_offset, section_header_offset) = match class {
        ElfClass::Elf32 => (
            cursor.u32(byte_order)? as u64,
            cursor.u32(byte_order)? as u64,
            cursor.u32(byte_order)? as u64,
        ),
        ElfClass::Elf64 => (
            cursor.u64(byte_order)?,
            cursor.u64(byte_order)?,
            cursor.u64(byte_order)?,
        ),
    };
    let _flags = cursor.u32(byte_order)?;
    let header_size = cursor.u16(byte_order)?;
    let program_header_entry_size = cursor.u16(byte_order)?;
    let program_header_count = cursor.u16(byte_order)?;
    let section_header_entry_size = cursor.u16(byte_order)?;
    let section_header_count = cursor.u16(byte_order)?;
    let section_name_index = cursor.u16(byte_order)?;

    Ok(ElfHeader {
        class,
        byte_order,
        object_type,
        machine,
        entry,
        program_header_offset,
        section_header_offset,
        header_size,
        program_header_entry_size,
        program_header_count,
        section_header_entry_size,
        section_header_count,
        section_name_index,
    })
}

/// A lazy, allocation-free view over validated ELF program headers.
#[derive(Clone, Copy, Debug)]
pub struct ElfProgramHeaders<'a> {
    bytes: &'a [u8],
    class: ElfClass,
    byte_order: ByteOrder,
    offset: usize,
    entry_size: usize,
    remaining: usize,
}

impl<'a> Iterator for ElfProgramHeaders<'a> {
    type Item = Result<ElfProgramHeader, ElfError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let end = self.offset + self.entry_size;
        let entry =
            parse_program_header(&self.bytes[self.offset..end], self.class, self.byte_order);
        self.offset = end;
        self.remaining -= 1;
        Some(entry)
    }
}

/// Validates and returns a lazy view of the complete program-header table.
pub fn parse_elf_program_headers<'a>(
    bytes: &'a [u8],
    header: ElfHeader,
) -> Result<ElfProgramHeaders<'a>, ElfError> {
    let expected = match header.class {
        ElfClass::Elf32 => 32,
        ElfClass::Elf64 => 56,
    };
    if header.program_header_entry_size != expected {
        return Err(ElfError::InvalidProgramHeaderEntrySize {
            expected,
            actual: header.program_header_entry_size,
        });
    }

    let offset = usize::try_from(header.program_header_offset)
        .map_err(|_| ElfError::ProgramHeaderTableOutOfBounds)?;
    let entry_size = usize::from(header.program_header_entry_size);
    let count = usize::from(header.program_header_count);
    let table_size = entry_size
        .checked_mul(count)
        .ok_or(ElfError::ProgramHeaderTableOutOfBounds)?;
    let end = offset
        .checked_add(table_size)
        .ok_or(ElfError::ProgramHeaderTableOutOfBounds)?;
    if end > bytes.len() {
        return Err(ElfError::ProgramHeaderTableOutOfBounds);
    }

    Ok(ElfProgramHeaders {
        bytes,
        class: header.class,
        byte_order: header.byte_order,
        offset,
        entry_size,
        remaining: count,
    })
}

fn parse_program_header(
    bytes: &[u8],
    class: ElfClass,
    byte_order: ByteOrder,
) -> Result<ElfProgramHeader, ElfError> {
    let mut cursor = Cursor::new(bytes);
    let (
        segment_type,
        flags,
        offset,
        virtual_address,
        physical_address,
        file_size,
        memory_size,
        alignment,
    ) = match class {
        ElfClass::Elf32 => {
            let segment_type = cursor.u32(byte_order)?;
            let offset = cursor.u32(byte_order)? as u64;
            let virtual_address = cursor.u32(byte_order)? as u64;
            let physical_address = cursor.u32(byte_order)? as u64;
            let file_size = cursor.u32(byte_order)? as u64;
            let memory_size = cursor.u32(byte_order)? as u64;
            let flags = cursor.u32(byte_order)?;
            let alignment = cursor.u32(byte_order)? as u64;
            (
                segment_type,
                flags,
                offset,
                virtual_address,
                physical_address,
                file_size,
                memory_size,
                alignment,
            )
        }
        ElfClass::Elf64 => {
            let segment_type = cursor.u32(byte_order)?;
            let flags = cursor.u32(byte_order)?;
            let offset = cursor.u64(byte_order)?;
            let virtual_address = cursor.u64(byte_order)?;
            let physical_address = cursor.u64(byte_order)?;
            let file_size = cursor.u64(byte_order)?;
            let memory_size = cursor.u64(byte_order)?;
            let alignment = cursor.u64(byte_order)?;
            (
                segment_type,
                flags,
                offset,
                virtual_address,
                physical_address,
                file_size,
                memory_size,
                alignment,
            )
        }
    };
    Ok(ElfProgramHeader {
        segment_type,
        flags,
        offset,
        virtual_address,
        physical_address,
        file_size,
        memory_size,
        alignment,
    })
}

/// A lazy, allocation-free view over validated ELF section headers.
#[derive(Clone, Copy, Debug)]
pub struct ElfSectionHeaders<'a> {
    bytes: &'a [u8],
    class: ElfClass,
    byte_order: ByteOrder,
    offset: usize,
    entry_size: usize,
    remaining: usize,
}

impl<'a> Iterator for ElfSectionHeaders<'a> {
    type Item = Result<ElfSectionHeader, ElfError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let end = self.offset + self.entry_size;
        let entry =
            parse_section_header(&self.bytes[self.offset..end], self.class, self.byte_order);
        self.offset = end;
        self.remaining -= 1;
        Some(entry)
    }
}

/// Validates and returns a lazy view of the complete section-header table.
pub fn parse_elf_section_headers<'a>(
    bytes: &'a [u8],
    header: ElfHeader,
) -> Result<ElfSectionHeaders<'a>, ElfError> {
    let expected = match header.class {
        ElfClass::Elf32 => 40,
        ElfClass::Elf64 => 64,
    };
    if header.section_header_entry_size != expected {
        return Err(ElfError::InvalidSectionHeaderEntrySize {
            expected,
            actual: header.section_header_entry_size,
        });
    }
    let offset = usize::try_from(header.section_header_offset)
        .map_err(|_| ElfError::SectionHeaderTableOutOfBounds)?;
    let entry_size = usize::from(header.section_header_entry_size);
    let count = usize::from(header.section_header_count);
    let table_size = entry_size
        .checked_mul(count)
        .ok_or(ElfError::SectionHeaderTableOutOfBounds)?;
    let end = offset
        .checked_add(table_size)
        .ok_or(ElfError::SectionHeaderTableOutOfBounds)?;
    if end > bytes.len() {
        return Err(ElfError::SectionHeaderTableOutOfBounds);
    }
    Ok(ElfSectionHeaders {
        bytes,
        class: header.class,
        byte_order: header.byte_order,
        offset,
        entry_size,
        remaining: count,
    })
}

fn parse_section_header(
    bytes: &[u8],
    class: ElfClass,
    byte_order: ByteOrder,
) -> Result<ElfSectionHeader, ElfError> {
    let mut cursor = Cursor::new(bytes);
    let name_offset = cursor.u32(byte_order)?;
    let section_type = cursor.u32(byte_order)?;
    let (flags, address, offset, size, link, info, alignment, entry_size) = match class {
        ElfClass::Elf32 => (
            cursor.u32(byte_order)? as u64,
            cursor.u32(byte_order)? as u64,
            cursor.u32(byte_order)? as u64,
            cursor.u32(byte_order)? as u64,
            cursor.u32(byte_order)?,
            cursor.u32(byte_order)?,
            cursor.u32(byte_order)? as u64,
            cursor.u32(byte_order)? as u64,
        ),
        ElfClass::Elf64 => (
            cursor.u64(byte_order)?,
            cursor.u64(byte_order)?,
            cursor.u64(byte_order)?,
            cursor.u64(byte_order)?,
            cursor.u32(byte_order)?,
            cursor.u32(byte_order)?,
            cursor.u64(byte_order)?,
            cursor.u64(byte_order)?,
        ),
    };
    Ok(ElfSectionHeader {
        name_offset,
        section_type,
        flags,
        address,
        offset,
        size,
        link,
        info,
        alignment,
        entry_size,
    })
}

/// Returns one NUL-terminated section name as a borrowed byte slice.
pub fn section_name(
    bytes: &[u8],
    section: ElfSectionHeader,
    string_table: ElfSectionHeader,
) -> Result<&[u8], ElfError> {
    let table_start =
        usize::try_from(string_table.offset).map_err(|_| ElfError::SectionNameTableOutOfBounds)?;
    let table_size =
        usize::try_from(string_table.size).map_err(|_| ElfError::SectionNameTableOutOfBounds)?;
    let table_end = table_start
        .checked_add(table_size)
        .ok_or(ElfError::SectionNameTableOutOfBounds)?;
    if table_end > bytes.len() {
        return Err(ElfError::SectionNameTableOutOfBounds);
    }
    let name_start = table_start
        .checked_add(
            usize::try_from(section.name_offset)
                .map_err(|_| ElfError::SectionNameOffsetOutOfBounds)?,
        )
        .ok_or(ElfError::SectionNameOffsetOutOfBounds)?;
    if name_start >= table_end {
        return Err(ElfError::SectionNameOffsetOutOfBounds);
    }
    let table = &bytes[name_start..table_end];
    let name_end = table
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(ElfError::UnterminatedSectionName)?;
    Ok(&table[..name_end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf64_little_header() -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4..16].copy_from_slice(&[2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x1234_5678u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&0x40u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&0x40u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&0x38u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        bytes
    }

    #[test]
    fn parses_elf64_little_endian_header_without_copying_input() {
        let bytes = elf64_little_header();
        let header = parse_elf_header(&bytes).unwrap();
        assert_eq!(header.class, ElfClass::Elf64);
        assert_eq!(header.byte_order, ByteOrder::Little);
        assert_eq!(header.machine, 0x3e);
        assert_eq!(header.entry, 0x1234_5678);
        assert_eq!(header.program_header_offset, 0x40);
        assert_eq!(header.header_size, 0x40);
    }

    #[test]
    fn rejects_invalid_and_truncated_inputs() {
        assert_eq!(parse_elf_header(&[0; 4]), Err(ElfError::InvalidMagic));
        assert_eq!(
            parse_elf_header(&[0x7f, b'E', b'L', b'F']),
            Err(ElfError::Truncated {
                needed: 5,
                available: 4
            })
        );
    }

    #[test]
    fn parses_big_endian_elf32_scalars() {
        let mut bytes = [0; 52];
        bytes[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4..16].copy_from_slice(&[1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        bytes[16..18].copy_from_slice(&2u16.to_be_bytes());
        bytes[18..20].copy_from_slice(&8u16.to_be_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_be_bytes());
        bytes[24..28].copy_from_slice(&0x10u32.to_be_bytes());
        bytes[28..32].copy_from_slice(&0x34u32.to_be_bytes());
        bytes[32..36].copy_from_slice(&0x44u32.to_be_bytes());
        bytes[40..42].copy_from_slice(&0x34u16.to_be_bytes());
        bytes[42..44].copy_from_slice(&0x20u16.to_be_bytes());
        bytes[44..46].copy_from_slice(&1u16.to_be_bytes());
        let header = parse_elf_header(&bytes).unwrap();
        assert_eq!(header.class, ElfClass::Elf32);
        assert_eq!(header.byte_order, ByteOrder::Big);
        assert_eq!(header.machine, 8);
        assert_eq!(header.entry, 0x10);
        assert_eq!(header.program_header_offset, 0x34);
    }

    #[test]
    fn lazily_parses_elf64_program_headers() {
        let mut bytes = elf64_little_header().to_vec();
        bytes.extend_from_slice(&[
            1, 0, 0, 0, 5, 0, 0, 0, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x40, 0, 0, 0, 0, 0, 0x40, 0,
            0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0,
        ]);
        bytes.extend_from_slice(&[0; 8]);
        let header = parse_elf_header(&bytes).unwrap();
        let mut headers = parse_elf_program_headers(&bytes, header).unwrap();
        assert_eq!(
            headers.next(),
            Some(Ok(ElfProgramHeader {
                segment_type: 1,
                flags: 5,
                offset: 0x40,
                virtual_address: 0x40_0000,
                physical_address: 0x40,
                file_size: 0x20,
                memory_size: 0x20,
                alignment: 0,
            }))
        );
        assert_eq!(headers.next(), None);
    }

    #[test]
    fn validates_program_header_table_before_returning_iterator() {
        let bytes = elf64_little_header();
        let header = parse_elf_header(&bytes).unwrap();
        assert!(matches!(
            parse_elf_program_headers(&bytes, header),
            Err(ElfError::ProgramHeaderTableOutOfBounds)
        ));
    }

    #[test]
    fn lazily_parses_sections_and_resolves_a_borrowed_name() {
        let mut bytes = elf64_little_header().to_vec();
        bytes[40..48].copy_from_slice(&0x40u64.to_le_bytes());
        bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&1u16.to_le_bytes());
        bytes[62..64].copy_from_slice(&0u16.to_le_bytes());

        let mut section = [0; 64];
        section[0..4].copy_from_slice(&1u32.to_le_bytes());
        section[4..8].copy_from_slice(&1u32.to_le_bytes());
        section[8..16].copy_from_slice(&6u64.to_le_bytes());
        section[16..24].copy_from_slice(&0x1000u64.to_le_bytes());
        section[24..32].copy_from_slice(&0x80u64.to_le_bytes());
        section[32..40].copy_from_slice(&7u64.to_le_bytes());
        bytes.extend_from_slice(&section);
        bytes.extend_from_slice(b"\0.text\0");

        let header = parse_elf_header(&bytes).unwrap();
        let section_header = parse_elf_section_headers(&bytes, header)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(section_header.name_offset, 1);
        assert_eq!(
            section_name(&bytes, section_header, section_header),
            Ok(b".text".as_slice())
        );
    }
}
