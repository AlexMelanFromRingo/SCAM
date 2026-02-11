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
    use crate::qr::{qr_for_payment_uri, qr_for_text};

    #[test]
    fn qr_generation_works() {
        let ascii = qr_for_text("scam").expect("must generate");
        assert!(!ascii.is_empty());
    }

    #[test]
    fn payment_uri_qr_generation_works() {
        let ascii =
            qr_for_payment_uri("sc1deadbeef", Some(100), Some("Alice")).expect("must generate");
        assert!(!ascii.is_empty());
    }
}
