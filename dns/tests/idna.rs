//! How domain names typed by the user are encoded into labels.
//!
//! These pin the behaviour of the IDNA library dog has always used, so that
//! replacing that library cannot quietly change which names dog accepts or
//! what it sends for them.

use dns::Labels;

fn encode(input: &str) -> Result<String, String> {
    Labels::encode(input).map(|labels| labels.to_string()).map_err(|e| e.to_string())
}

#[cfg(feature = "with_idna")]
fn idn_error(label: &str) -> Result<String, String> {
    Err(format!("its label {label:?} is not a valid internationalised name"))
}

fn length_error(label: &str) -> Result<String, String> {
    Err(format!("its label {label:?} is longer than 63 bytes"))
}

/// Empty labels used to be dropped, so `a..b` quietly became `a.b`; now
/// the name is refused, as dig refuses it.
#[cfg(feature = "with_idna")]
#[test]
fn idna_encoding() {
    let max_label = "a".repeat(63);
    let long_label = "a".repeat(64);

    let cases: Vec<(&str, Result<String, String>)> = vec![
        ("example.com", Ok("example.com.".into())),
        ("example.com.", Ok("example.com.".into())),
        ("a..b", Err("it has an empty label".into())),
        ("EXAMPLE.Com", Ok("example.com.".into())),
        ("_dmarc.example.com", Ok("_dmarc.example.com.".into())),
        ("_25._tcp.mail.example", Ok("_25._tcp.mail.example.".into())),
        ("bücher.example", Ok("xn--bcher-kva.example.".into())),
        ("BÜCHER.example", Ok("xn--bcher-kva.example.".into())),
        ("xn--bcher-kva.example", Ok("xn--bcher-kva.example.".into())),
        ("faß.example", Ok("xn--fa-hia.example.".into())),
        ("☕.example", Ok("xn--53h.example.".into())),
        ("ab--cd.example", Ok("ab--cd.example.".into())),
        ("-lead.example", idn_error("-lead")),
        ("trail-.example", idn_error("trail-")),
        ("xn--zz.example", idn_error("xn--zz")),
        (max_label.as_str(), Ok(format!("{max_label}."))),
        (long_label.as_str(), length_error(&long_label)),
    ];

    for (input, expected) in cases {
        assert_eq!(encode(input), expected, "{input:?}");
    }
}

/// Punycode makes a label longer, so the limit applies to the result: this
/// label is 62 bytes as typed, and 68 as `xn--` and its encoding.
#[cfg(feature = "with_idna")]
#[test]
fn the_length_limit_applies_after_encoding() {
    let label = format!("{}ü", "a".repeat(60));
    assert_eq!(label.len(), 62);
    assert_eq!(encode(&format!("{label}.example")), length_error(&label));
}

#[cfg(not(feature = "with_idna"))]
#[test]
fn without_idna_names_pass_through() {
    assert_eq!(encode("bücher.example"), Ok(r"b\195\188cher.example.".into()));
    assert_eq!(encode("EXAMPLE.com"), Ok("EXAMPLE.com.".into()));
    assert_eq!(encode(&"a".repeat(64)), length_error(&"a".repeat(64)));
    assert_eq!(encode("a..b"), Err("it has an empty label".into()));
}
