//! Text of visible signatures: AutoFirma's `layer2Text` placeholders
//! (`$$SUBJECTCN$$`, `$$SIGNDATE=dd/MM/yyyy$$`...), the obfuscation of
//! identifiers (DNI/NIE) in certificate fields, and a subset of Java's
//! `SimpleDateFormat` with Spanish names.

use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

use super::pdf::DateTime;
use crate::{
    algorithm::oid,
    cert::{name_attribute, name_attributes},
};

/// Default text when neither a text nor a rubric image is given, as in AutoFirma.
pub(crate) fn default_template(has_reason: bool, has_location: bool) -> String {
    let mut text =
        "Firmado por $$SUBJECTCN$$\nFecha: $$SIGNDATE=dd/MM/yyyy HH:mm:ss z$$".to_string();
    if has_reason {
        text.push_str("\nMotivo: $$REASON$$");
    }
    if has_location {
        text.push_str("\nLugar de firma: $$LOCATION$$");
    }
    text
}

/// Mask used to hide identifiers in certificate fields (AutoFirma's
/// `obfuscationMask`, `char;minDigits;positions;shift`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextMask {
    /// Replacement character.
    pub obfuscated_char: char,
    /// Minimum number of consecutive digits for a word to be an identifier.
    pub min_length: usize,
    /// Positions left in clear (`true`), applied to the digits of the identifier.
    pub positions: Vec<bool>,
    /// Shift the mask when the identifier has fewer digits than positions.
    pub shift: bool,
}

impl Default for TextMask {
    /// `*;3;false,false,false,true,true,true,true;true`: shows the 4 middle digits of a DNI.
    fn default() -> Self {
        TextMask {
            obfuscated_char: '*',
            min_length: 3,
            positions: vec![false, false, false, true, true, true, true],
            shift: true,
        }
    }
}

impl TextMask {
    /// Parses AutoFirma's `obfuscationMask` syntax.
    pub fn parse(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.split(';').collect();
        let [character, min_length, positions, shift] = parts.as_slice() else {
            return None;
        };
        let mut chars = character.chars();
        let (Some(obfuscated_char), None) = (chars.next(), chars.next()) else {
            return None;
        };
        let min_length = min_length.parse().ok()?;
        let list: Vec<&str> = positions.split(',').collect();
        if list.len() <= 1 {
            return None;
        }
        // Trailing `false` values are dropped.
        let last = list
            .iter()
            .rposition(|p| p.trim().eq_ignore_ascii_case("true"))?;
        if last == 0 {
            return None;
        }
        let positions = list[..=last]
            .iter()
            .map(|p| p.trim().eq_ignore_ascii_case("true"))
            .collect();
        Some(TextMask {
            obfuscated_char,
            min_length,
            positions,
            shift: shift.trim().eq_ignore_ascii_case("true"),
        })
    }

    /// Hides the identifiers of `text`: every word (run of letters and digits)
    /// containing at least `min_length` consecutive digits.
    ///
    /// Port of AutoFirma's `PdfVisibleAreasUtils.obfuscateIds`, including its
    /// quirk of counting the digits of the whole text rather than of the word.
    pub fn apply(&self, text: &str) -> String {
        let mut chars: Vec<char> = text.chars().collect();
        let mut digit_count = 0;
        let mut start = 0;
        let mut found = false;
        for i in 0..chars.len() {
            if chars[i].is_alphanumeric() {
                if chars[i].is_numeric() {
                    digit_count += 1;
                    if digit_count == self.min_length {
                        found = true;
                    }
                } else {
                    digit_count = 0;
                }
            } else {
                if found {
                    self.obfuscate(&mut chars, start, i - start);
                    found = false;
                }
                start = i + 1;
            }
        }
        if found {
            let len = chars.len() - start;
            self.obfuscate(&mut chars, start, len);
        }
        chars.into_iter().collect()
    }

    fn obfuscate(&self, text: &mut [char], pos: usize, len: usize) {
        let digits = text.iter().filter(|c| c.is_numeric()).count();
        let plain = self.positions.iter().filter(|&&p| p).count();

        if digits >= plain {
            // Only digits in clear positions are kept; letters are always hidden.
            let mut mask = self.positions.clone();
            if self.shift && digits < mask.len() {
                // Drop hidden positions from the start until the mask fits.
                let omit = mask.len() - digits;
                let mut omitted = 0;
                let mut shifted = Vec::with_capacity(digits);
                for &position in &self.positions {
                    if position || omitted >= omit {
                        shifted.push(position);
                    } else {
                        omitted += 1;
                    }
                }
                mask = shifted;
            }
            let mut j = 0;
            for c in &mut text[pos..pos + len] {
                if c.is_numeric() {
                    if j >= mask.len() || !mask[j] {
                        *c = self.obfuscated_char;
                    }
                    j += 1;
                } else {
                    *c = self.obfuscated_char;
                }
            }
        } else {
            // Not enough digits: apply the mask from the end.
            let mut mask_pos = self.positions.len() as isize - 1;
            for c in text[pos..pos + len].iter_mut().rev() {
                if mask_pos < 0 || !self.positions[mask_pos as usize] {
                    *c = self.obfuscated_char;
                }
                mask_pos -= 1;
            }
        }
    }
}

/// Data available to the placeholders.
#[derive(Debug)]
pub(crate) struct LayerTextContext<'a> {
    pub certificate: &'a Certificate,
    pub signing_time: i64,
    pub utc_offset_minutes: i32,
    pub reason: Option<&'a str>,
    pub location: Option<&'a str>,
    pub contact: Option<&'a str>,
    /// Mask applied to the subject CN and DN, `None` to show them as they are.
    pub mask: Option<&'a TextMask>,
}

/// Whether the certificate is a pseudonym certificate. AutoFirma does not hide
/// identifiers in them by default.
pub(crate) fn is_pseudonym(certificate: &Certificate) -> bool {
    name_attribute(certificate.tbs_certificate().subject(), oid::PSEUDONYM).is_some()
}

/// Replaces the placeholders of `template`.
pub(crate) fn expand(template: &str, ctx: &LayerTextContext<'_>) -> String {
    let tbs = ctx.certificate.tbs_certificate();
    let subject = tbs.subject();
    let attr = |oid| name_attribute(subject, oid).unwrap_or_default();
    let masked = |text: String| match ctx.mask {
        Some(mask) => mask.apply(&text),
        None => text,
    };

    let subject_cn =
        name_attribute(subject, oid::COMMON_NAME).unwrap_or_else(|| subject.to_string());
    let issuer_cn =
        name_attribute(tbs.issuer(), oid::COMMON_NAME).unwrap_or_else(|| tbs.issuer().to_string());
    let ous = name_attributes(subject, oid::ORGANIZATIONAL_UNIT);

    let mut text = template
        .replace("$$SUBJECTCN$$", &masked(subject_cn))
        .replace("$$ISSUERCN$$", &issuer_cn)
        .replace("$$CERTSERIAL$$", &decimal(tbs.serial_number().as_bytes()))
        .replace("$$OU$$", ous.first().map(String::as_str).unwrap_or(""))
        .replace("$$OUS$$", &ous.join(", "))
        .replace("$$TITLE$$", &attr(oid::TITLE))
        .replace("$$SUBJECTDN$$", &masked(subject.to_string()))
        .replace("$$GIVENNAME$$", &attr(oid::GIVEN_NAME))
        .replace("$$SURNAME$$", &attr(oid::SURNAME))
        .replace("$$ORGANIZATION$$", &attr(oid::ORGANIZATION))
        .replace("$$REASON$$", ctx.reason.unwrap_or(""))
        .replace("$$LOCATION$$", ctx.location.unwrap_or(""))
        .replace("$$CONTACT$$", ctx.contact.unwrap_or(""));
    if let Some(pseudonym) = name_attribute(subject, oid::PSEUDONYM) {
        text = text.replace("$$PSEUDONYM$$", &pseudonym);
    }

    let date = DateTime::from_unix(ctx.signing_time, ctx.utc_offset_minutes);
    const PREFIX: &str = "$$SIGNDATE";
    while let Some(start) = text.find(PREFIX) {
        let Some(end) = text[start + PREFIX.len()..]
            .find("$$")
            .map(|i| start + PREFIX.len() + i + 2)
        else {
            break;
        };
        let tag = &text[start..end];
        let pattern = tag
            .trim_start_matches(PREFIX)
            .trim_end_matches("$$")
            .strip_prefix('=')
            .unwrap_or(DEFAULT_DATE_PATTERN);
        let formatted = format_date(pattern, &date);
        text.replace_range(start..end, &formatted);
    }
    text
}

/// Java's default `SimpleDateFormat()` pattern for the Spanish locale.
const DEFAULT_DATE_PATTERN: &str = "d/M/yy, H:mm";

const MONTHS: [&str; 12] = [
    "enero",
    "febrero",
    "marzo",
    "abril",
    "mayo",
    "junio",
    "julio",
    "agosto",
    "septiembre",
    "octubre",
    "noviembre",
    "diciembre",
];
const DAYS: [&str; 7] = [
    "lunes",
    "martes",
    "miércoles",
    "jueves",
    "viernes",
    "sábado",
    "domingo",
];

/// Formats `date` with a subset of Java's `SimpleDateFormat` patterns
/// (`y M d H h m s S E a z Z X` and quoted text), Spanish names.
pub(crate) fn format_date(pattern: &str, date: &DateTime) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' {
            // '' is a literal quote; 'text' is literal text.
            if chars.get(i + 1) == Some(&'\'') {
                out.push('\'');
                i += 2;
                continue;
            }
            i += 1;
            while i < chars.len() {
                if chars[i] == '\'' {
                    if chars.get(i + 1) == Some(&'\'') {
                        out.push('\'');
                        i += 2;
                        continue;
                    }
                    break;
                }
                out.push(chars[i]);
                i += 1;
            }
            i += 1;
            continue;
        }
        if !c.is_ascii_alphabetic() {
            out.push(c);
            i += 1;
            continue;
        }
        let mut count = 1;
        while chars.get(i + count) == Some(&c) {
            count += 1;
        }
        i += count;
        let number = |value: i64| format!("{value:0count$}");
        let offset = date.offset_minutes;
        let (sign, abs) = (if offset < 0 { '-' } else { '+' }, offset.unsigned_abs());
        match c {
            'y' if count == 2 => out.push_str(&format!("{:02}", date.year.rem_euclid(100))),
            'y' => out.push_str(&number(date.year)),
            'M' if count >= 4 => out.push_str(MONTHS[date.month as usize - 1]),
            'M' if count == 3 => out.push_str(&MONTHS[date.month as usize - 1][..3]),
            'M' => out.push_str(&number(date.month.into())),
            'd' => out.push_str(&number(date.day.into())),
            'H' => out.push_str(&number(date.hour.into())),
            'k' => out.push_str(&number(if date.hour == 0 { 24 } else { date.hour.into() })),
            'h' => out.push_str(&number(match date.hour % 12 {
                0 => 12,
                h => h.into(),
            })),
            'K' => out.push_str(&number((date.hour % 12).into())),
            'm' => out.push_str(&number(date.minute.into())),
            's' => out.push_str(&number(date.second.into())),
            'S' => out.push_str(&number(0)),
            'E' if count >= 4 => out.push_str(DAYS[date.weekday as usize]),
            'E' => out.push_str(&DAYS[date.weekday as usize][..3]),
            'a' => out.push_str(if date.hour < 12 { "a. m." } else { "p. m." }),
            // Only the offset is known, not the zone name.
            'z' | 'O' => {
                out.push_str("GMT");
                if abs != 0 {
                    out.push_str(&format!("{sign}{:02}:{:02}", abs / 60, abs % 60));
                }
            }
            'Z' => out.push_str(&format!("{sign}{:02}{:02}", abs / 60, abs % 60)),
            'X' if abs == 0 => out.push('Z'),
            'X' if count == 1 => out.push_str(&format!("{sign}{:02}", abs / 60)),
            'X' if count == 2 => out.push_str(&format!("{sign}{:02}{:02}", abs / 60, abs % 60)),
            'X' => out.push_str(&format!("{sign}{:02}:{:02}", abs / 60, abs % 60)),
            // Unsupported letters are copied as they are.
            other => out.extend(std::iter::repeat_n(other, count)),
        }
    }
    out
}

/// Decimal representation of a big-endian unsigned integer (certificate serial
/// numbers, as Java's `BigInteger.toString()`).
fn decimal(bytes: &[u8]) -> String {
    let mut digits = vec![0u8]; // little-endian base 10
    for &byte in bytes {
        let mut carry = u32::from(byte);
        for digit in &mut digits {
            let value = u32::from(*digit) * 256 + carry;
            *digit = (value % 10) as u8;
            carry = value / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    while digits.len() > 1 && digits.last() == Some(&0) {
        digits.pop();
    }
    digits.iter().rev().map(|d| char::from(b'0' + d)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::{SigningKey, tests::load};

    #[test]
    fn default_mask_hides_dni() {
        let mask = TextMask::default();
        // Same output as AutoFirma 1.9 for this certificate.
        assert_eq!(
            mask.apply("ESPAÑOL ESPAÑOL JUAN - 99999999R"),
            "ESPAÑOL ESPAÑOL JUAN - ***9999**"
        );
        assert_eq!(mask.apply("Sin identificadores"), "Sin identificadores");
    }

    #[test]
    fn parses_masks() {
        assert_eq!(
            TextMask::parse("*;3;false,false,false,true,true,true,true;true"),
            Some(TextMask::default())
        );
        let mask = TextMask::parse("#;4;true,true,false,false;false").unwrap();
        assert_eq!(mask.positions, [true, true]);
        assert_eq!(mask.obfuscated_char, '#');
        assert!(TextMask::parse("*;3;true").is_none());
        assert!(TextMask::parse("**;3;true,true;true").is_none());
    }

    #[test]
    fn formats_dates() {
        // 2026-10-16T14:07:54Z
        let date = DateTime::from_unix(1_792_159_674, 120);
        assert_eq!(
            format_date("dd/MM/yyyy HH:mm:ss", &date),
            "16/10/2026 16:07:54"
        );
        assert_eq!(format_date(DEFAULT_DATE_PATTERN, &date), "16/10/26, 16:07");
        assert_eq!(
            format_date("EEEE d 'de' MMMM", &date),
            "viernes 16 de octubre"
        );
        assert_eq!(
            format_date("h:mm a z Z XXX", &date),
            "4:07 p. m. GMT+02:00 +0200 +02:00"
        );
        assert_eq!(format_date("''yy''", &date), "'26'");
    }

    #[test]
    fn serial_in_decimal() {
        assert_eq!(decimal(&[0x01, 0x00]), "256");
        assert_eq!(decimal(&[0xff, 0xff, 0xff, 0xff, 0xff]), "1099511627775");
        assert_eq!(decimal(&[]), "0");
    }

    #[test]
    fn expands_placeholders() {
        let key = &load("rsa.p12")[0];
        let mask = TextMask::default();
        let ctx = LayerTextContext {
            certificate: &key.certificate_chain()[0],
            signing_time: 1_792_159_674,
            utc_offset_minutes: 120,
            reason: Some("Conforme"),
            location: None,
            contact: None,
            mask: Some(&mask),
        };
        assert_eq!(
            expand(
                "Firmado por $$SUBJECTCN$$ ($$GIVENNAME$$ $$SURNAME$$) el $$SIGNDATE=dd/MM/yyyy$$. \
                 $$REASON$$ en [$$LOCATION$$]. Emisor: $$ISSUERCN$$",
                &ctx
            ),
            "Firmado por ESPAÑOL ESPAÑOL JUAN - ***9999** (JUAN ESPAÑOL) el 16/10/2026. \
             Conforme en []. Emisor: autofirma-rs Test CA"
        );
        assert!(!is_pseudonym(ctx.certificate));
        assert_eq!(
            expand(&default_template(true, false), &ctx),
            "Firmado por ESPAÑOL ESPAÑOL JUAN - ***9999**\nFecha: 16/10/2026 16:07:54 GMT+02:00\nMotivo: Conforme"
        );
    }
}
