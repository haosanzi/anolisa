//! Verify unique quote attribution, unchanged UTF-8 byte offsets and digests.
//! Reject fabricated sources and ambiguous matches without exposing input text.

use std::collections::BTreeSet;

use asc_intent::{EvidenceError, QuoteReference, TextEvidence, resolve_text_evidence};
use serde_json::json;

fn resolve(text: &str, quote: &str) -> Result<TextEvidence, EvidenceError> {
    resolve_text_evidence(
        "task-input-1",
        text,
        &QuoteReference {
            source_id: "task-input-1".into(),
            quote: quote.into(),
        },
    )
}

#[test]
fn locates_exact_utf8_bytes_ignoring_only_whitespace() {
    let text = "🙂\u{53ea}\u{5ba1}\u{67e5}\u{ff0c}\u{4e0d}\u{4fee}\u{590d}\r\n";
    let quote = "\u{4e0d}\u{4fee}\u{590d}";
    let evidence = resolve(text, quote).unwrap();
    assert_eq!(evidence.source_id(), "task-input-1");
    assert_eq!(evidence.byte_range(), 16..25);
    assert_eq!(text.get(evidence.byte_range()), Some(quote));
    assert!(text.is_char_boundary(evidence.byte_range().start));
    assert!(text.is_char_boundary(evidence.byte_range().end));
    assert_eq!(resolve(text, &format!("{quote}\n")), Ok(evidence));
    assert_eq!(
        resolve("café", "cafe\u{301}"),
        Err(EvidenceError::QuoteNotFound)
    );
}

#[test]
fn serializes_only_program_computed_evidence_with_known_digest() {
    let evidence = resolve("\u{524d}\u{8a00}abc\u{540e}\u{8bb0}", "abc").unwrap();
    let digest = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert_eq!(evidence.quote_sha256(), digest);
    assert_eq!(
        serde_json::to_value(&evidence).unwrap(),
        json!({
            "source_id": "task-input-1",
            "start_byte": 6,
            "end_byte": 9,
            "quote_sha256": digest,
        })
    );
    assert_eq!(
        evidence,
        resolve("\u{524d}\u{8a00}abc\u{540e}\u{8bb0}", "abc").unwrap()
    );
    assert_ne!(
        evidence,
        resolve("\u{524d}\u{8a00}xabc\u{540e}\u{8bb0}", "abc").unwrap()
    );
    assert_ne!(
        evidence.quote_sha256(),
        resolve("abd", "abd").unwrap().quote_sha256()
    );
}

#[test]
fn rejects_empty_missing_and_ambiguous_quotes() {
    for (text, quote, expected) in [
        ("", "", EvidenceError::EmptyQuote),
        ("Inspect only", "", EvidenceError::EmptyQuote),
        ("", "Inspect", EvidenceError::QuoteNotFound),
        ("Inspect only", "Run tests", EvidenceError::QuoteNotFound),
        (
            "inspect then inspect",
            "inspect",
            EvidenceError::AmbiguousQuote,
        ),
        ("aaaa", "aa", EvidenceError::AmbiguousQuote),
        ("aaa", "aa", EvidenceError::AmbiguousQuote),
        (
            "\u{54c8}\u{54c8}\u{54c8}",
            "\u{54c8}\u{54c8}",
            EvidenceError::AmbiguousQuote,
        ),
    ] {
        assert_eq!(resolve(text, quote), Err(expected));
    }
}

#[test]
fn accepts_whole_source_and_matches_at_either_edge() {
    for (text, quote, range) in [
        ("abc", "abc", 0..3),
        ("xabc", "abc", 1..4),
        ("abcx", "abc", 0..3),
    ] {
        assert_eq!(resolve(text, quote).unwrap().byte_range(), range);
    }
}

#[test]
fn tolerates_spacing_garbling_but_still_reports_original_bytes() {
    // Real qwen-plus output: an inserted space before the full stop.
    let text = "\u{5ba1}\u{67e5} repo-A \u{5f53}\u{524d}\u{53d8}\u{66f4}\u{ff0c}\u{68c0}\u{67e5}\u{6f5c}\u{5728} bug \u{548c}\u{5b89}\u{5168}\u{95ee}\u{9898}\u{ff0c}\u{76f4}\u{63a5}\u{8fd4}\u{56de}\u{5ba1}\u{67e5}\u{7ed3}\u{8bba}\u{3002}\u{4e0d}\u{8981}\u{6539}\u{6587}\u{4ef6}";
    let exact = "\u{5ba1}\u{67e5} repo-A \u{5f53}\u{524d}\u{53d8}\u{66f4}\u{ff0c}\u{68c0}\u{67e5}\u{6f5c}\u{5728} bug \u{548c}\u{5b89}\u{5168}\u{95ee}\u{9898}\u{ff0c}\u{76f4}\u{63a5}\u{8fd4}\u{56de}\u{5ba1}\u{67e5}\u{7ed3}\u{8bba}\u{3002}";
    let garbled = "\u{5ba1}\u{67e5} repo-A \u{5f53}\u{524d}\u{53d8}\u{66f4}\u{ff0c}\u{68c0}\u{67e5}\u{6f5c}\u{5728} bug \u{548c}\u{5b89}\u{5168}\u{95ee}\u{9898}\u{ff0c}\u{76f4}\u{63a5}\u{8fd4}\u{56de}\u{5ba1}\u{67e5}\u{7ed3}\u{8bba} \u{3002}";
    let expected = resolve(text, exact).unwrap();
    let evidence = resolve(text, garbled).unwrap();
    assert_eq!(evidence, expected);
    assert_eq!(text.get(evidence.byte_range()), Some(exact));

    // Line breaks and ideographic spaces inside the match are also tolerated.
    assert_eq!(
        resolve("line1\nline2", "line1 line2").unwrap().byte_range(),
        0..11
    );
    assert_eq!(resolve("a\u{3000}b", "ab").unwrap().byte_range(), 0..5);
    assert_eq!(resolve("   ", "   "), Err(EvidenceError::QuoteNotFound));
    assert_eq!(resolve("ab a b", "ab"), Err(EvidenceError::AmbiguousQuote));
}

#[test]
fn rejects_unknown_or_invalid_source_ids() {
    let reference = QuoteReference {
        source_id: "tool-result".into(),
        quote: "abc".into(),
    };
    assert_eq!(
        resolve_text_evidence("user-input", "abc", &reference),
        Err(EvidenceError::SourceMismatch)
    );
    for source_id in [
        String::new(),
        "x".repeat(257),
        "user\0input".into(),
        "user\ninput".into(),
    ] {
        let reference = QuoteReference {
            source_id: source_id.clone(),
            quote: "abc".into(),
        };
        assert_eq!(
            resolve_text_evidence(&source_id, "abc", &reference),
            Err(EvidenceError::InvalidSourceId)
        );
    }
    let source_id = "x".repeat(256);
    let reference = QuoteReference {
        source_id: source_id.clone(),
        quote: "abc".into(),
    };
    assert!(resolve_text_evidence(&source_id, "abc", &reference).is_ok());
}

#[test]
fn enforces_task_text_byte_limit() {
    let text = format!("{}abc", "x".repeat(64 * 1024 - 3));
    assert_eq!(resolve(&text, "abc").unwrap().byte_range(), 65_533..65_536);
    assert_eq!(
        resolve(&(text + "x"), "abc"),
        Err(EvidenceError::TextTooLarge {
            actual_bytes: 65_537,
            max_bytes: 65_536
        })
    );
    assert!(matches!(
        resolve(&"\u{4e2d}".repeat(22_000), "\u{4e2d}"),
        Err(EvidenceError::TextTooLarge { .. })
    ));
}

#[test]
fn strict_dto_accepts_only_source_id_and_quote() {
    let reference: QuoteReference =
        serde_json::from_value(json!({ "source_id": "task-input-1", "quote": "abc" })).unwrap();
    assert_eq!(
        resolve_text_evidence("task-input-1", "abc", &reference)
            .unwrap()
            .byte_range(),
        0..3
    );
    for field in [
        "trusted",
        "verified",
        "authority",
        "confirmed",
        "principal",
        "start_byte",
        "end_byte",
        "quote_sha256",
    ] {
        let mut value = json!({ "source_id": "task-input-1", "quote": "abc" });
        value[field] = json!(true);
        assert!(serde_json::from_value::<QuoteReference>(value).is_err());
    }
    for value in [
        json!({}),
        json!({ "source_id": "task-input-1" }),
        json!({ "source_id": 1, "quote": "abc" }),
        json!({ "source_id": "task-input-1", "quote": null }),
    ] {
        assert!(serde_json::from_value::<QuoteReference>(value).is_err());
    }
    assert!(
        serde_json::from_str::<QuoteReference>(
            r#"{"source_id":"a","source_id":"b","quote":"abc"}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<QuoteReference>(r#"{"source_id":"a","quote":"abc","quote":"abd"}"#)
            .is_err()
    );
}

#[test]
fn errors_do_not_include_source_text_quotes_or_untrusted_ids() {
    let secret = "SECRET_MARKER_456";
    let reference = QuoteReference {
        source_id: secret.into(),
        quote: secret.into(),
    };
    let error = resolve_text_evidence("task-input-1", secret, &reference).unwrap_err();
    assert!(!format!("{error}: {error:?}").contains(secret));
    let error = resolve(secret, "SECRET_QUOTE_789").unwrap_err();
    assert!(!format!("{error}: {error:?}").contains("SECRET_"));
}

#[test]
fn uniqueness_matches_all_character_boundaries_in_small_utf8_sources() {
    for length in 1..=5 {
        for mask in 0..(1 << length) {
            let text: String = (0..length)
                .map(|bit| {
                    if mask & (1 << bit) == 0 {
                        'a'
                    } else {
                        '\u{4e2d}'
                    }
                })
                .collect();
            let mut boundaries: Vec<_> = text.char_indices().map(|(offset, _)| offset).collect();
            boundaries.push(text.len());
            let mut quotes = BTreeSet::new();
            for (index, &start) in boundaries.iter().enumerate() {
                for &end in &boundaries[index + 1..] {
                    quotes.insert(&text[start..end]);
                }
            }
            for quote in quotes {
                let matches: Vec<_> = text
                    .char_indices()
                    .filter_map(|(offset, _)| text[offset..].starts_with(quote).then_some(offset))
                    .collect();
                if matches.len() == 1 {
                    assert_eq!(
                        resolve(&text, quote).unwrap().byte_range(),
                        matches[0]..matches[0] + quote.len()
                    );
                } else {
                    assert_eq!(resolve(&text, quote), Err(EvidenceError::AmbiguousQuote));
                }
            }
        }
    }
}
