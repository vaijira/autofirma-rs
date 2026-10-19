//! Serialization of PDF objects, text strings and dates.
//!
//! lopdf parses the document, but its writer is private and rewrites whole
//! files; signatures need an incremental update whose bytes we control.

use lopdf::{Dictionary, Object, StringFormat};

pub(crate) use crate::time::DateTime;
use crate::time::days_from_civil;

/// Appends the PDF syntax of `object` to `out`.
pub(crate) fn write_object(out: &mut Vec<u8>, object: &Object) {
    match object {
        Object::Null => out.extend_from_slice(b"null"),
        Object::Boolean(value) => out.extend_from_slice(if *value { b"true" } else { b"false" }),
        Object::Integer(value) => out.extend_from_slice(value.to_string().as_bytes()),
        Object::Real(value) => out.extend_from_slice(format_number(*value).as_bytes()),
        Object::Name(name) => write_name(out, name),
        Object::String(text, StringFormat::Literal) => write_literal_string(out, text),
        Object::String(text, StringFormat::Hexadecimal) => {
            out.push(b'<');
            out.extend_from_slice(crate::digest::to_hex(text).as_bytes());
            out.push(b'>');
        }
        Object::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                write_object(out, item);
            }
            out.push(b']');
        }
        Object::Dictionary(dict) => write_dictionary(out, dict),
        Object::Stream(stream) => {
            let mut dict = stream.dict.clone();
            dict.set("Length", stream.content.len() as i64);
            write_dictionary(out, &dict);
            out.extend_from_slice(b"\nstream\n");
            out.extend_from_slice(&stream.content);
            out.extend_from_slice(b"\nendstream");
        }
        Object::Reference((id, generation)) => {
            out.extend_from_slice(format!("{id} {generation} R").as_bytes());
        }
    }
}

pub(crate) fn write_dictionary(out: &mut Vec<u8>, dict: &Dictionary) {
    out.extend_from_slice(b"<<");
    for (key, value) in dict.iter() {
        write_name(out, key);
        out.push(b' ');
        write_object(out, value);
    }
    out.extend_from_slice(b">>");
}

fn write_name(out: &mut Vec<u8>, name: &[u8]) {
    out.push(b'/');
    for &b in name {
        let delimiter = b"()<>[]{}/%#".contains(&b);
        if (0x21..=0x7e).contains(&b) && !delimiter {
            out.push(b);
        } else {
            out.extend_from_slice(format!("#{b:02X}").as_bytes());
        }
    }
}

fn write_literal_string(out: &mut Vec<u8>, text: &[u8]) {
    out.push(b'(');
    for &b in text {
        match b {
            b'(' | b')' | b'\\' => {
                out.push(b'\\');
                out.push(b);
            }
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\n' => out.extend_from_slice(b"\\n"),
            _ => out.push(b),
        }
    }
    out.push(b')');
}

/// Formats a number without exponent and with at most 4 decimals.
pub(crate) fn format_number(value: f32) -> String {
    if value.fract() == 0.0 && value.abs() < 1e9 {
        return format!("{}", value as i64);
    }
    let text = format!("{value:.4}");
    let text = text.trim_end_matches('0').trim_end_matches('.');
    if text == "-0" {
        "0".to_string()
    } else {
        text.to_string()
    }
}

/// A PDF text string: PDFDocEncoding when possible (it matches Latin-1 for the
/// printable characters), UTF-16BE with a byte order mark otherwise.
pub(crate) fn text_string(text: &str) -> Object {
    let latin1 = text
        .chars()
        .all(|c| matches!(c as u32, 0x20..=0x7e | 0xa1..=0xff) && c != '\u{ad}');
    let bytes = if latin1 {
        text.chars().map(|c| c as u8).collect()
    } else {
        let mut bytes = vec![0xfe, 0xff];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_be_bytes());
        }
        bytes
    };
    Object::String(bytes, StringFormat::Literal)
}

/// Decodes a PDF text string (PDFDocEncoding treated as Latin-1, or UTF-16BE).
pub(crate) fn decode_text_string(bytes: &[u8]) -> String {
    if let Some(utf16) = bytes.strip_prefix(&[0xfe, 0xff]) {
        let units: Vec<u16> = utf16
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&pair| u16::from_be_bytes(pair))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    if let Some(utf8) = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        return String::from_utf8_lossy(utf8).into_owned();
    }
    bytes.iter().map(|&b| b as char).collect()
}

impl DateTime {
    /// PDF date string (`D:20261016160754+02'00'`).
    pub fn to_pdf(self) -> String {
        let sign = if self.offset_minutes < 0 { '-' } else { '+' };
        let offset = self.offset_minutes.unsigned_abs();
        let zone = if offset == 0 {
            "Z".to_string()
        } else {
            format!("{sign}{:02}'{:02}'", offset / 60, offset % 60)
        };
        format!(
            "D:{:04}{:02}{:02}{:02}{:02}{:02}{zone}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

/// Parses a PDF date string (`D:YYYYMMDDHHmmSSOHH'mm'`, every part after the
/// year optional) into a Unix time.
pub(crate) fn parse_pdf_date(text: &str) -> Option<i64> {
    let text = text.strip_prefix("D:").unwrap_or(text);
    let digits = |range: std::ops::Range<usize>, default: i64| -> Option<i64> {
        match text.get(range) {
            Some(part) if part.bytes().all(|b| b.is_ascii_digit()) => part.parse().ok(),
            Some(_) => None,
            None => Some(default),
        }
    };
    let year = digits(0..4, 0)?;
    if text.len() < 4 {
        return None;
    }
    let month = digits(4..6, 1)?;
    let day = digits(6..8, 1)?;
    let hour = digits(8..10, 0)?;
    let minute = digits(10..12, 0)?;
    let second = digits(12..14, 0)?;
    let zone = text.get(14..).unwrap_or("");
    let offset = match zone.as_bytes().first() {
        Some(sign @ (b'+' | b'-')) => {
            let numbers: Vec<i64> = zone[1..]
                .split('\'')
                .filter(|part| !part.is_empty())
                .filter_map(|part| part.parse().ok())
                .collect();
            let minutes =
                numbers.first().copied().unwrap_or(0) * 60 + numbers.get(1).copied().unwrap_or(0);
            if *sign == b'-' { -minutes } else { minutes }
        }
        _ => 0,
    };
    Some(
        days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
            - offset * 60,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_string(object: &Object) -> String {
        let mut out = Vec::new();
        write_object(&mut out, object);
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn serializes_objects() {
        let mut dict = Dictionary::new();
        dict.set("Type", Object::Name(b"Sig".to_vec()));
        dict.set("ByteRange", vec![0.into(), 10.into()]);
        dict.set("Name", Object::string_literal("a(b)\\c"));
        dict.set("Odd", Object::Name(b"A B#".to_vec()));
        dict.set("P", Object::Reference((12, 0)));
        dict.set("R", Object::Real(0.5));
        assert_eq!(
            to_string(&Object::Dictionary(dict)),
            "<</Type /Sig/ByteRange [0 10]/Name (a\\(b\\)\\\\c)/Odd /A#20B#23/P 12 0 R/R 0.5>>"
        );
    }

    #[test]
    fn numbers() {
        assert_eq!(format_number(72.0), "72");
        assert_eq!(format_number(1.25), "1.25");
        assert_eq!(format_number(-0.00001), "0");
    }

    #[test]
    fn text_strings() {
        assert_eq!(
            text_string("Señor"),
            Object::String(b"Se\xf1or".to_vec(), StringFormat::Literal)
        );
        let Object::String(bytes, _) = text_string("€") else {
            unreachable!()
        };
        assert_eq!(bytes, [0xfe, 0xff, 0x20, 0xac]);
        assert_eq!(decode_text_string(&bytes), "€");
        assert_eq!(decode_text_string(b"Se\xf1or"), "Señor");
    }

    #[test]
    fn dates() {
        // 2026-10-16T14:07:54Z
        let unix = 1_792_159_674;
        let date = DateTime::from_unix(unix, 120);
        assert_eq!(date.to_pdf(), "D:20261016160754+02'00'");
        assert_eq!(date.weekday, 4); // Friday
        assert_eq!(DateTime::from_unix(unix, 0).to_pdf(), "D:20261016140754Z");
        assert_eq!(parse_pdf_date("D:20261016160754+02'00'"), Some(unix));
        assert_eq!(parse_pdf_date("D:20261016140754Z"), Some(unix));
        assert_eq!(parse_pdf_date("D:2026"), Some(1_767_225_600));
        assert_eq!(parse_pdf_date("garbage"), None);
        assert_eq!(DateTime::from_unix(-1, 0).year, 1969);
    }
}
