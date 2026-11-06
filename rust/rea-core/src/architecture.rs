// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Symphony

//! Stable architecture interpretation for ELF machine identifiers.

/// Architecture names exposed by REA's ELF normalization boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfArchitecture {
    /// 32-bit x86, normalized as `386`.
    X86,
    /// 64-bit x86, normalized as `amd64`.
    X86_64,
    /// MIPS.
    Mips,
    /// PowerPC, normalized as `ppc`.
    PowerPc,
    /// ARM.
    Arm,
    /// Qualcomm Hexagon.
    Hexagon,
    /// AArch64.
    Arm64,
    /// RISC-V.
    Riscv,
    /// 64-bit PowerPC.
    Ppc64,
    /// IBM S/390.
    S390,
    /// LoongArch.
    LoongArch,
    /// An unrecognized machine value retained as evidence.
    Unknown(u16),
}

impl ElfArchitecture {
    /// Returns the stable display name without allocating.
    pub const fn name(self) -> &'static str {
        match self {
            Self::X86 => "386",
            Self::X86_64 => "amd64",
            Self::Mips => "mips",
            Self::PowerPc => "ppc",
            Self::Arm => "arm",
            Self::Hexagon => "hexagon",
            Self::Arm64 => "arm64",
            Self::Riscv => "riscv",
            Self::Ppc64 => "ppc64",
            Self::S390 => "s390",
            Self::LoongArch => "loongarch",
            Self::Unknown(_) => "unknown",
        }
    }

    /// Returns the original ELF machine value for evidence and diagnostics.
    pub const fn machine(self) -> Option<u16> {
        match self {
            Self::Unknown(machine) => Some(machine),
            _ => None,
        }
    }
}

/// Maps an ELF `e_machine` value without discarding unknown values.
pub const fn architecture_for_elf_machine(machine: u16) -> ElfArchitecture {
    match machine {
        3 => ElfArchitecture::X86,
        62 => ElfArchitecture::X86_64,
        8 => ElfArchitecture::Mips,
        20 => ElfArchitecture::PowerPc,
        40 => ElfArchitecture::Arm,
        164 => ElfArchitecture::Hexagon,
        183 => ElfArchitecture::Arm64,
        243 => ElfArchitecture::Riscv,
        21 => ElfArchitecture::Ppc64,
        22 => ElfArchitecture::S390,
        258 => ElfArchitecture::LoongArch,
        other => ElfArchitecture::Unknown(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_known_normalization() {
        assert_eq!(architecture_for_elf_machine(3).name(), "386");
        assert_eq!(architecture_for_elf_machine(62).name(), "amd64");
        assert_eq!(architecture_for_elf_machine(21).name(), "ppc64");
    }

    #[test]
    fn preserves_unknown_machine_identity() {
        let architecture = architecture_for_elf_machine(0xffff);
        assert_eq!(architecture.name(), "unknown");
        assert_eq!(architecture.machine(), Some(0xffff));
    }
}
