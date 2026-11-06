// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Symphony

//! Provider identity and deterministic selection.

/// A validated, borrowed provider identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderId<'a>(&'a str);

impl<'a> ProviderId<'a> {
    /// Validates the stable REA provider-id grammar without allocating.
    pub const fn parse(value: &'a str) -> Result<Self, ProviderSelectionError> {
        let bytes = value.as_bytes();
        if bytes.is_empty() || bytes[0] < b'a' || bytes[0] > b'z' {
            return Err(ProviderSelectionError::InvalidProviderId);
        }

        let mut index = 1;
        while index < bytes.len() {
            let byte = bytes[index];
            let valid =
                (byte >= b'a' && byte <= b'z') || (byte >= b'0' && byte <= b'9') || byte == b'-';
            if !valid {
                return Err(ProviderSelectionError::InvalidProviderId);
            }
            index += 1;
        }

        if bytes.len() == 4
            && bytes[0] == b'a'
            && bytes[1] == b'u'
            && bytes[2] == b't'
            && bytes[3] == b'o'
        {
            return Err(ProviderSelectionError::ReservedProviderId);
        }
        Ok(Self(value))
    }

    /// Returns the original caller-provided spelling.
    pub const fn as_str(self) -> &'a str {
        self.0
    }
}

/// A caller's provider choice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderSelector<'a> {
    /// Select the first ready provider in caller-provided order.
    Auto,
    /// Select exactly this provider.
    Explicit(ProviderId<'a>),
}

/// Provider readiness observed by the owning adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderReadiness {
    /// The provider can accept the target.
    Ready,
    /// The provider cannot participate for this stable reason.
    Rejected(RejectionCode),
}

/// Stable reasons a provider cannot participate in selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectionCode {
    /// The provider is not configured.
    NotConfigured,
    /// The provider executable or runtime is unavailable.
    Unavailable,
    /// The target is unsupported.
    TargetUnsupported,
}

/// A provider candidate. The slice containing candidates remains caller-owned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Provider<'a> {
    /// Stable provider identity.
    pub id: ProviderId<'a>,
    /// Adapter-owned readiness observation.
    pub readiness: ProviderReadiness,
}

/// The successful result of selection, borrowing the input candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderSelection<'a> {
    /// The selected provider.
    pub provider: &'a Provider<'a>,
}

/// Selection failures with no owned diagnostic strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderSelectionError {
    /// The requested provider identifier failed validation.
    InvalidProviderId,
    /// `auto` is reserved for [`ProviderSelector::Auto`].
    ReservedProviderId,
    /// The explicit provider was not present in the candidate slice.
    ProviderNotFound,
    /// The explicit provider was present but rejected.
    ProviderRejected(RejectionCode),
    /// Automatic selection found no ready candidate.
    NoReadyProvider,
}

/// Selects a provider deterministically without allocation or mutation.
pub fn select_provider<'a>(
    selector: ProviderSelector<'a>,
    candidates: &'a [Provider<'a>],
) -> Result<ProviderSelection<'a>, ProviderSelectionError> {
    match selector {
        ProviderSelector::Auto => candidates
            .iter()
            .find(|candidate| candidate.readiness == ProviderReadiness::Ready)
            .map(|provider| ProviderSelection { provider })
            .ok_or(ProviderSelectionError::NoReadyProvider),
        ProviderSelector::Explicit(requested) => candidates
            .iter()
            .find(|candidate| candidate.id == requested)
            .map_or(
                Err(ProviderSelectionError::ProviderNotFound),
                |provider| match provider.readiness {
                    ProviderReadiness::Ready => Ok(ProviderSelection { provider }),
                    ProviderReadiness::Rejected(reason) => {
                        Err(ProviderSelectionError::ProviderRejected(reason))
                    }
                },
            ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_preserves_borrowed_spelling() {
        let id = ProviderId::parse("ghidra-12").unwrap();
        assert_eq!(id.as_str(), "ghidra-12");
        assert_eq!(
            ProviderId::parse("Ghidra"),
            Err(ProviderSelectionError::InvalidProviderId)
        );
        assert_eq!(
            ProviderId::parse("auto"),
            Err(ProviderSelectionError::ReservedProviderId)
        );
    }

    #[test]
    fn auto_selects_first_ready_candidate_in_input_order() {
        let first = Provider {
            id: ProviderId::parse("ida").unwrap(),
            readiness: ProviderReadiness::Rejected(RejectionCode::Unavailable),
        };
        let second = Provider {
            id: ProviderId::parse("ghidra").unwrap(),
            readiness: ProviderReadiness::Ready,
        };
        let candidates = [first, second];
        let selected = select_provider(ProviderSelector::Auto, &candidates).unwrap();
        assert_eq!(selected.provider.id.as_str(), "ghidra");
    }

    #[test]
    fn explicit_selection_reports_provider_owned_rejection() {
        let provider = Provider {
            id: ProviderId::parse("ida").unwrap(),
            readiness: ProviderReadiness::Rejected(RejectionCode::TargetUnsupported),
        };
        let candidates = [provider];
        let result = select_provider(ProviderSelector::Explicit(provider.id), &candidates);
        assert_eq!(
            result,
            Err(ProviderSelectionError::ProviderRejected(
                RejectionCode::TargetUnsupported
            ))
        );
    }

    #[test]
    fn no_ready_candidate_is_not_reported_as_absence_of_candidates() {
        let provider = Provider {
            id: ProviderId::parse("ida").unwrap(),
            readiness: ProviderReadiness::Rejected(RejectionCode::NotConfigured),
        };
        assert_eq!(
            select_provider(ProviderSelector::Auto, &[provider]),
            Err(ProviderSelectionError::NoReadyProvider)
        );
    }
}
