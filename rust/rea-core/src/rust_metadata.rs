// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Symphony

//! Zero-copy Rust compiler metadata observations.

const RUSTC_PREFIX: &[u8] = b"/rustc/";
const HASH_BYTES: usize = 40;

/// One inferred Rust compiler commit path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RustcHashMatch<'a> {
    /// File offset of the `/rustc/` prefix.
    pub file_offset: usize,
    /// Borrowed hexadecimal commit bytes.
    pub hash: &'a [u8],
}

/// A lazy, allocation-free scan of caller-owned bytes for Rust compiler paths.
#[derive(Clone, Copy, Debug)]
pub struct RustcHashMatches<'a> {
    bytes: &'a [u8],
    cursor: usize,
    file_offset: usize,
}

/// Stable failures when a caller supplies a file-backed scan region.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RustcRegionError {
    /// The requested region does not fit in the supplied bytes.
    OutOfBounds,
    /// Adding the region offset would overflow the caller's address space.
    OffsetOverflow,
}

/// Scans bytes for `/rustc/<40 hexadecimal digits>/` observations.
pub const fn scan_rustc_hashes(bytes: &[u8]) -> RustcHashMatches<'_> {
    RustcHashMatches {
        bytes,
        cursor: 0,
        file_offset: 0,
    }
}

/// Scans one validated file-backed region and preserves its original offset.
///
/// The region is not copied and matches are not deduplicated. Callers that
/// merge overlapping read-only ranges or retain distinct hashes own those
/// policies at the format boundary.
pub fn scan_rustc_hashes_in_region<'a>(
    bytes: &'a [u8],
    file_offset: usize,
    size: usize,
) -> Result<RustcHashMatches<'a>, RustcRegionError> {
    let end = file_offset
        .checked_add(size)
        .ok_or(RustcRegionError::OffsetOverflow)?;
    if end > bytes.len() {
        return Err(RustcRegionError::OutOfBounds);
    }
    Ok(RustcHashMatches {
        bytes: &bytes[file_offset..end],
        cursor: 0,
        file_offset,
    })
}

impl<'a> Iterator for RustcHashMatches<'a> {
    type Item = RustcHashMatch<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.cursor < self.bytes.len() {
            let prefix_start = self.cursor;
            self.cursor += 1;
            if !self.bytes[prefix_start..].starts_with(RUSTC_PREFIX) {
                continue;
            }

            let hash_start = prefix_start + RUSTC_PREFIX.len();
            let hash_end = hash_start.checked_add(HASH_BYTES)?;
            let suffix = hash_end.checked_add(1)?;
            if suffix > self.bytes.len() || self.bytes[hash_end] != b'/' {
                continue;
            }
            let hash = &self.bytes[hash_start..hash_end];
            if hash.iter().all(|byte| byte.is_ascii_hexdigit()) {
                return Some(RustcHashMatch {
                    file_offset: self.file_offset + prefix_start,
                    hash,
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_borrowed_hashes_and_preserves_offsets() {
        let bytes = b"prefix /rustc/0123456789abcdef0123456789abcdef01234567/ suffix";
        let found = scan_rustc_hashes(bytes).next().unwrap();
        assert_eq!(found.file_offset, 7);
        assert_eq!(found.hash, b"0123456789abcdef0123456789abcdef01234567");
        assert_eq!(scan_rustc_hashes(bytes).nth(1), None);
    }

    #[test]
    fn rejects_wrong_length_non_hex_and_missing_suffix() {
        let bytes = b"/rustc/short/ /rustc/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz/ /rustc/0123456789abcdef0123456789abcdef01234567x";
        assert_eq!(scan_rustc_hashes(bytes).next(), None);
    }

    #[test]
    fn finds_multiple_matches_without_deduplicating_observations() {
        let bytes = b"/rustc/0123456789abcdef0123456789abcdef01234567/ /rustc/0123456789abcdef0123456789abcdef01234567/";
        let mut matches = scan_rustc_hashes(bytes);
        let first = matches.next().unwrap();
        let second = matches.next().unwrap();
        assert_eq!(first.hash, second.hash);
        assert_ne!(first.file_offset, second.file_offset);
    }

    #[test]
    fn scans_a_bounded_region_with_original_file_offsets() {
        let bytes = b"ignored /rustc/0123456789abcdef0123456789abcdef01234567/ tail";
        let found = scan_rustc_hashes_in_region(bytes, 8, bytes.len() - 8)
            .unwrap()
            .next()
            .unwrap();
        assert_eq!(found.file_offset, 8);
        assert_eq!(found.hash, b"0123456789abcdef0123456789abcdef01234567");
    }

    #[test]
    fn rejects_regions_that_do_not_fit() {
        let bytes = b"bytes";
        assert!(matches!(
            scan_rustc_hashes_in_region(bytes, 4, 2),
            Err(RustcRegionError::OutOfBounds)
        ));
        assert!(matches!(
            scan_rustc_hashes_in_region(bytes, usize::MAX, 1),
            Err(RustcRegionError::OffsetOverflow)
        ));
    }
}
