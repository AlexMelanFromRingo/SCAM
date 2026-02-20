use qrcodegen::{QrCode, QrCodeEcc};
use thiserror::Error;

pub fn qr_for_payment_uri(
    address: &str,
    amount: Option<u64>,
    label: Option<&str>,
) -> Result<String, QrError> {
    let mut uri = format!("coin:{address}");
    let mut has_query = false;

    if let Some(value) = amount {
        uri.push(if has_query { '&' } else { '?' });
        has_query = true;
        uri.push_str(&format!("amount={value}"));
    }
    if let Some(lbl) = label {
        uri.push(if has_query { '&' } else { '?' });
        let escaped = lbl.replace(' ', "%20");
        uri.push_str(&format!("label={escaped}"));
    }

    qr_for_text(&uri)
}

pub fn qr_for_text(text: &str) -> Result<String, QrError> {
    if text.trim().is_empty() {
        return Err(QrError::EmptyData);
    }

    let qr = QrCode::encode_text(text, QrCodeEcc::Medium).map_err(QrError::DataTooLong)?;
    Ok(render_ascii_qr(&qr, 1))
}

fn render_ascii_qr(qr: &QrCode, border: i32) -> String {
    let size = qr.size();
    let mut out = String::new();

    for y in -border..(size + border) {
        for x in -border..(size + border) {
            if qr.get_module(x, y) {
                out.push_str("##");
            } else {
                out.push_str("  ");
            }
        }
        out.push('\n');
    }

    out
}

#[derive(Debug, Error)]
pub enum QrError {
    #[error("qr input data must not be empty")]
    EmptyData,
    #[error("qr input is too long")]
    DataTooLong(#[source] qrcodegen::DataTooLong),
}

#[cfg(test)]
mod tests {
    use qrcodegen::{QrCode, QrCodeEcc};

    use crate::qr::{qr_for_payment_uri, qr_for_text, render_ascii_qr};

    #[test]
    fn qr_generation_works() {
        let ascii = qr_for_text("scam").expect("must generate");
        assert!(!ascii.is_empty());
    }

    #[test]
    fn qr_for_text_matches_renderer_output() {
        let payload = "scam";
        let qr = QrCode::encode_text(payload, QrCodeEcc::Medium).expect("qr");
        let expected = render_ascii_qr(&qr, 1);
        let actual = qr_for_text(payload).expect("must generate");
        assert_eq!(actual, expected);
    }

    #[test]
    fn payment_uri_qr_generation_works() {
        let ascii =
            qr_for_payment_uri("sc1deadbeef", Some(100), Some("Alice")).expect("must generate");
        assert!(!ascii.is_empty());
    }

    #[test]
    fn payment_uri_qr_matches_direct_uri_rendering() {
        let direct = qr_for_text("coin:sc1deadbeef?amount=100&label=Alice%20Smith").expect("qr");
        let via_uri = qr_for_payment_uri("sc1deadbeef", Some(100), Some("Alice Smith"))
            .expect("payment uri qr");
        assert_eq!(via_uri, direct);
    }

    #[test]
    fn render_ascii_qr_has_consistent_row_width() {
        let qr = QrCode::encode_text("a", QrCodeEcc::Low).expect("qr");
        let rendered = render_ascii_qr(&qr, 1);
        let lines = rendered.lines().collect::<Vec<_>>();
        assert!(!lines.is_empty());
        let width = lines[0].len();
        assert!(width > 0);
        assert!(lines.iter().all(|line| line.len() == width));
    }

    #[test]
    fn render_ascii_qr_high_density_contains_dark_and_light_modules() {
        let payload =
            "coin:sd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpk5fg?amount=123456&label=HighDensityCase";
        let qr = QrCode::encode_text(payload, QrCodeEcc::High).expect("qr");
        let rendered = render_ascii_qr(&qr, 1);
        assert!(rendered.contains("##"));
        assert!(rendered.contains("  "));
    }

    #[test]
    fn render_ascii_qr_obeys_expected_dimensions_with_border() {
        let qr = QrCode::encode_text("dim-check", QrCodeEcc::Low).expect("qr");
        let border = 2;
        let rendered = render_ascii_qr(&qr, border);
        let lines = rendered.lines().collect::<Vec<_>>();
        let expected_modules = qr.size() + (2 * border);
        assert_eq!(lines.len() as i32, expected_modules);
        let expected_width = (expected_modules as usize) * 2;
        assert!(lines.iter().all(|line| line.len() == expected_width));
    }
}
