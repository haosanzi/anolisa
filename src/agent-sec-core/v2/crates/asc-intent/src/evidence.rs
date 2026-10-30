//! Locate model-supplied quotes uniquely in the original UTF-8 task text and
//! compute byte ranges and SHA-256 digests. Matching ignores whitespace
//! differences, because models often garble spacing, while the recorded range
//! and digest stay the original bytes. It establishes textual presence, not the
//! correctness of an interpretation.

use std::ops::Range;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_SOURCE_ID_BYTES: usize = 256;

/// Untrusted source label and exact quote supplied for evidence validation.
///
/// Extra JSON fields are rejected, including caller-supplied positions or trust.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteReference {
    /// Source label that must match the text being validated.
    pub source_id: String,
    /// Nonempty quote; matching ignores whitespace differences and requires a
    /// unique location in the source.
    pub quote: String,
}

/// Program-computed location and digest of a uniquely matched source quote.
///
/// Constructed only by [`resolve_text_evidence`], not deserialized from model
/// output. The half-open byte range always follows UTF-8 character boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TextEvidence {
    source_id: String,
    start_byte: usize,
    end_byte: usize,
    quote_sha256: String,
}

impl TextEvidence {
    /// Attribution label of the source whose bytes were validated.
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    /// Half-open byte range in the unchanged source, not character indexes.
    pub fn byte_range(&self) -> Range<usize> {
        self.start_byte..self.end_byte
    }

    /// SHA-256 of the matched bytes, encoded as `sha256:` and lowercase hex.
    pub fn quote_sha256(&self) -> &str {
        &self.quote_sha256
    }
}

/// Evidence validation failures without source text, quotes or untrusted IDs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EvidenceError {
    /// The source label is empty, oversized or contains control characters.
    #[error("source ID must contain 1..256 bytes and no control characters")]
    InvalidSourceId,
    /// The reference names a different source from the supplied text.
    #[error("quote source does not match the supplied text source")]
    SourceMismatch,
    /// The source exceeds the bounded text size.
    #[error("text length {actual_bytes} bytes exceeds the {max_bytes}-byte limit")]
    TextTooLarge {
        /// Observed source length in bytes.
        actual_bytes: usize,
        /// Maximum accepted source length in bytes.
        max_bytes: usize,
    },
    /// No quote bytes were supplied.
    #[error("quote must not be empty")]
    EmptyQuote,
    /// The quote has no non-whitespace characters or does not occur in the source.
    #[error("quote not found in source text")]
    QuoteNotFound,
    /// More than one whitespace-insensitive match, including overlapping ones.
    #[error("quote occurs more than once in source text")]
    AmbiguousQuote,
}

/// Resolve a quote in unchanged source text and compute its evidence.
///
/// Source labels are limited to 256 bytes without control characters, and text
/// to 64 KiB. Matching compares non-whitespace characters only, so quotes that
/// differ from the source in spaces or line breaks still resolve; the returned
/// range and digest always cover the original matched bytes. Repeated matches
/// are rejected even when they overlap. Other normalization, such as Unicode
/// folding or punctuation conversion, is deliberately not applied.
///
/// # Errors
///
/// Returns [`EvidenceError`] for an invalid or mismatched source ID, oversized
/// text, an empty or unlocatable quote, or more than one match.
///
/// # Examples
///
/// ```
/// use asc_intent::{QuoteReference, resolve_text_evidence};
///
/// let reference = QuoteReference {
///     source_id: "task-1".into(),
///     quote: "notes.txt".into(),
/// };
/// let evidence = resolve_text_evidence("task-1", "Read notes.txt", &reference)?;
/// assert_eq!(evidence.byte_range(), 5..14);
/// # Ok::<(), asc_intent::EvidenceError>(())
/// ```
pub fn resolve_text_evidence(
    source_id: &str,
    text: &str,
    reference: &QuoteReference,
) -> Result<TextEvidence, EvidenceError> {
    if source_id.is_empty()
        || source_id.len() > MAX_SOURCE_ID_BYTES
        || source_id.chars().any(char::is_control)
    {
        return Err(EvidenceError::InvalidSourceId);
    }
    if reference.source_id != source_id {
        return Err(EvidenceError::SourceMismatch);
    }
    if text.len() > MAX_TEXT_BYTES {
        return Err(EvidenceError::TextTooLarge {
            actual_bytes: text.len(),
            max_bytes: MAX_TEXT_BYTES,
        });
    }
    reference
        .quote
        .chars()
        .next()
        .ok_or(EvidenceError::EmptyQuote)?;
    if reference.quote.chars().all(char::is_whitespace) {
        return Err(EvidenceError::QuoteNotFound);
    }
    // Models often garble spacing inside quotes, so compare non-whitespace
    // characters and map the match back to original byte offsets.
    let needle: Vec<char> = reference
        .quote
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let (haystack, offsets): (Vec<char>, Vec<(usize, usize)>) = text
        .char_indices()
        .filter(|(_, c)| !c.is_whitespace())
        .map(|(offset, c)| (c, (offset, c.len_utf8())))
        .unzip();
    if haystack.len() < needle.len() {
        return Err(EvidenceError::QuoteNotFound);
    }
    let mut first_match: Option<usize> = None;
    for start in 0..=(haystack.len() - needle.len()) {
        if haystack[start..start + needle.len()] == needle[..] {
            if first_match.is_some() {
                return Err(EvidenceError::AmbiguousQuote);
            }
            first_match = Some(start);
        }
    }
    let matched = first_match.ok_or(EvidenceError::QuoteNotFound)?;
    let start_byte = offsets[matched].0;
    let (last_offset, last_len) = offsets[matched + needle.len() - 1];
    let end_byte = last_offset + last_len;
    let quote = text
        .get(start_byte..end_byte)
        .ok_or(EvidenceError::QuoteNotFound)?;

    Ok(TextEvidence {
        source_id: source_id.to_owned(),
        start_byte,
        end_byte,
        quote_sha256: format!("sha256:{:x}", Sha256::digest(quote.as_bytes())),
    })
}
