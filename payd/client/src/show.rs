//! What is shown on the terminal, and what is read of an exit's answer
//! before it is.
//!
//! An exit is somebody else's machine. Text of its making goes to this
//! terminal as words on one line and nothing else: no control character,
//! nothing hidden, not without end. And what it asks to be paid is looked
//! at here before it is shown as something to pay.

use fips_exit_proto::tidy;
use qrcode::{Color, EcLevel, QrCode};
use serde_json::Value;

/// Text of an exit's, for the terminal: one line, `limit` characters.
pub fn plain(text: &str, limit: usize) -> String {
    tidy(text, limit).chars().filter(|c| !c.is_control()).collect()
}

/// A field of an answer that is text, for the terminal.
pub fn text(of: &Value, field: &str, limit: usize) -> String {
    plain(of[field].as_str().unwrap_or_default(), limit)
}

/// An order's name as the service writes one: `o` and 16 small hex digits.
/// Anything else is not put into a path.
pub fn is_order_id(id: &str) -> bool {
    id.len() == 17 && id.starts_with('o') && id[1..].bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A package's key: 64 hex digits.
pub fn is_key(key: &str) -> bool {
    key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit())
}

/// How many sat a BOLT11 invoice asks for, read from its first part, which
/// says it in the clear. None for what is no invoice, names no amount, or
/// names one that is no whole number of sat.
pub fn invoice_sat(invoice: &str) -> Option<u64> {
    let invoice = invoice.to_ascii_lowercase();
    if !invoice.bytes().all(|b| b.is_ascii_alphanumeric()) || invoice.len() > 4096 {
        return None;
    }
    // Its first part ends at the last `1`: the rest has none.
    let (head, _) = invoice.rsplit_once('1')?;
    let rest = head.strip_prefix("ln")?;
    let amount = rest.trim_start_matches(|c: char| c.is_ascii_lowercase());
    if amount.len() == rest.len() || amount.is_empty() {
        return None;
    }
    let (digits, unit) = match amount.as_bytes()[amount.len() - 1] {
        b'0'..=b'9' => (amount, None),
        unit => (&amount[..amount.len() - 1], Some(unit)),
    };
    if digits.is_empty() || digits.len() > 18 || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let n: u128 = digits.parse().ok()?;
    // In millisatoshi: a bitcoin is 10^11 of them.
    let msat = match unit {
        None => n.checked_mul(100_000_000_000)?,
        Some(b'm') => n * 100_000_000,
        Some(b'u') => n * 100_000,
        Some(b'n') => n * 100,
        Some(b'p') if n.is_multiple_of(10) => n / 10,
        _ => return None,
    };
    msat.is_multiple_of(1000).then(|| u64::try_from(msat / 1000).ok()).flatten()
}

/// Is `address` written as a Bitcoin address is: letters and digits, not
/// too few and not too many? Whose it is, the mint alone knows.
pub fn is_address(address: &str) -> bool {
    (14..=90).contains(&address.len()) && address.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// An invoice as wallets read it from a code: in capitals, which a code
/// holds in less room.
pub fn invoice_link(invoice: &str) -> String {
    format!("LIGHTNING:{}", invoice.to_ascii_uppercase())
}

/// An address as a wallet opens it, with `sat` as the amount: in bitcoin,
/// to the satoshi.
pub fn address_link(address: &str, sat: u64) -> String {
    format!("bitcoin:{address}?amount={}.{:08}", sat / 100_000_000, sat % 100_000_000)
}

/// `text` as a QR code for a terminal: two rows of the code to a line,
/// black on white whatever the terminal's colours are. None for text that
/// does not fit in one.
pub fn code(text: &str) -> Option<String> {
    /// The empty margin around a code, in modules.
    const MARGIN: usize = 2;
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::L).ok()?;
    let (width, modules) = (code.width(), code.to_colors());
    let dark = |x: usize, y: usize| {
        let inside = |n: usize| (MARGIN..MARGIN + width).contains(&n);
        inside(x) && inside(y) && modules[(y - MARGIN) * width + (x - MARGIN)] == Color::Dark
    };
    let size = width + 2 * MARGIN;
    let mut out = String::new();
    for y in (0..size).step_by(2) {
        out.push_str("\x1b[30;107m");
        for x in 0..size {
            out.push(match (dark(x, y), dark(x, y + 1)) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push_str("\x1b[0m\n");
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_exits_text_is_one_line_of_words_on_the_terminal() {
        assert_eq!(plain("An exit\x1b[2J\r\nin  \tBern\u{202e}", 80), "An exit[2J in Bern");
        assert_eq!(plain(&"x".repeat(500), 40).len(), 40);
        assert_eq!(text(&serde_json::json!({ "name": 7 }), "name", 40), "");
        assert_eq!(text(&serde_json::json!({ "name": "a\u{7}b" }), "name", 40), "ab");
    }

    #[test]
    fn an_order_and_a_key_are_what_the_service_writes() {
        assert!(is_order_id("o0123456789abcdef"));
        for not in [
            "",
            "o0123456789abcde",
            "o0123456789ABCDEF",
            "p0123456789abcdef",
            "o0123456789abcdef/key",
            "o../../../terms",
        ] {
            assert!(!is_order_id(not), "{not}");
        }
        assert!(is_key(&"aB".repeat(32)) && !is_key(&"a".repeat(63)) && !is_key(&"g".repeat(64)));
    }

    #[test]
    fn an_invoice_says_what_it_asks_for() {
        // 2500 micro-bitcoin, 20 milli, 80 nano (8 sat), 10 pico-bitcoin short of a sat.
        assert_eq!(invoice_sat("lnbc2500u1pvjluezsp5zyg3zyg3zyg"), Some(250_000));
        assert_eq!(invoice_sat("LNBC20M1PVJLUEZ"), Some(2_000_000));
        assert_eq!(invoice_sat("lnbc80n1p5qqqqq"), Some(8));
        assert_eq!(invoice_sat("lnbcrt15u1p5qqqqq"), Some(1500));
        assert_eq!(invoice_sat("lntb1500n1p5qqqqq"), Some(150));
        assert_eq!(invoice_sat("lnbc10000p1p5qqqqq"), Some(1));
        assert_eq!(invoice_sat("lnbc11p5qqqqq"), Some(100_000_000), "a whole bitcoin");
        // No amount, a part of a sat, and what is no invoice.
        for not in
            ["lnbc1p5qqqqq", "lnbc10p1p5qqqqq", "lnbc15p1p5qqqqq", "lnbc0u1p5qq", "lnbc5x1p5qq", "lnbc", "", "bc1qabc"]
        {
            assert_eq!(invoice_sat(not), None, "{not}");
        }
        assert_eq!(invoice_sat("lnbc80n1p5qq\x1b[2J"), None);
        assert_eq!(invoice_sat(&format!("lnbc{}u1p5qq", "9".repeat(30))), None);
    }

    #[test]
    fn an_address_and_its_link() {
        assert!(is_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
        assert!(is_address("bcrt1qf97xyk99c7arrwwmfwdnf72p96rjk89nm9w7v5"));
        for not in [
            "",
            "bc1q",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=9",
            "bc1q w508d6qejxtdg4y5r3",
            &"a".repeat(91),
        ] {
            assert!(!is_address(not), "{not}");
        }
        assert_eq!(address_link("bc1qabc", 1500), "bitcoin:bc1qabc?amount=0.00001500");
        assert_eq!(address_link("bc1qabc", 250_000_000), "bitcoin:bc1qabc?amount=2.50000000");
        assert_eq!(invoice_link("lnbc80n1p5"), "LIGHTNING:LNBC80N1P5");
    }

    #[test]
    fn a_code_is_drawn_black_on_white_two_rows_to_a_line() {
        let drawn = code("LIGHTNING:LNBC80N1P5QQQQQ").unwrap();
        let lines: Vec<&str> = drawn.lines().collect();
        // The smallest code is 21 modules wide: with its margin, 25.
        assert_eq!(lines.len(), 13);
        for line in &lines {
            assert!(line.starts_with("\x1b[30;107m") && line.ends_with("\x1b[0m"), "{line:?}");
            assert_eq!(line.chars().filter(|c| matches!(c, '█' | '▀' | '▄' | ' ')).count(), 25, "{line:?}");
        }
        // The margin is empty, and the corner after it is a finder's.
        assert!(lines[0].contains(&" ".repeat(25)));
        assert!(lines[1].contains("  █▀▀▀▀▀█"), "{:?}", lines[1]);
        assert!(code(&"x".repeat(5000)).is_none());
    }
}
