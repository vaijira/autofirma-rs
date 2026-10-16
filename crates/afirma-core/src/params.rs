//! AutoFirma's `extraParams`: the `key=value` options of every signature
//! operation, with the same names AutoFirma uses (`mode`, `signReason`,
//! `layer2Text`...), so existing integrations and servers understand them.

use serde::{Deserialize, Serialize};

use crate::{
    cades::{CadesParams, SignatureMode},
    pades::{
        CertificationLevel, FontColor, FontFamily, PadesParams, SignaturePages, VisibleSignature,
    },
    policy::SignaturePolicy,
};

/// Ordered list of AutoFirma extra parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtraParams(pub Vec<(String, String)>);

impl ExtraParams {
    /// Adds (or replaces) a parameter.
    pub fn set(&mut self, key: &str, value: impl Into<String>) {
        let value = value.into();
        match self.0.iter_mut().find(|(k, _)| k == key) {
            Some(entry) => entry.1 = value,
            None => self.0.push((key.to_string(), value)),
        }
    }

    /// Value of a parameter.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Whether there are no parameters.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Java `.properties` text, as `java.util.Properties.store` writes it
    /// (characters outside ASCII escaped as `\uXXXX`).
    pub fn to_properties(&self) -> String {
        let mut out = String::new();
        for (key, value) in &self.0 {
            escape(&mut out, key, true);
            out.push('=');
            escape(&mut out, value, false);
            out.push('\n');
        }
        out
    }

    /// Adds the parameters of a signature policy.
    fn set_policy(&mut self, policy: &SignaturePolicy) {
        self.set("policyIdentifier", policy.identifier.clone());
        self.set("policyIdentifierHash", policy.hash_base64.clone());
        self.set(
            "policyIdentifierHashAlgorithm",
            match policy.hash_algorithm {
                crate::digest::DigestAlgorithm::Sha1 => "http://www.w3.org/2000/09/xmldsig#sha1",
                crate::digest::DigestAlgorithm::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
                crate::digest::DigestAlgorithm::Sha384 => {
                    "http://www.w3.org/2001/04/xmldsig-more#sha384"
                }
                crate::digest::DigestAlgorithm::Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
            },
        );
        if let Some(qualifier) = &policy.qualifier {
            self.set("policyQualifier", qualifier.clone());
        }
    }
}

/// Escapes a key or value of a `.properties` file.
fn escape(out: &mut String, text: &str, key: bool) {
    for (i, c) in text.chars().enumerate() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\x0c' => out.push_str("\\f"),
            '=' | ':' | '#' | '!' => {
                out.push('\\');
                out.push(c);
            }
            ' ' if key || i == 0 => out.push_str("\\ "),
            ' '..='~' => out.push(c),
            _ => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04X}"));
                }
            }
        }
    }
}

impl From<&CadesParams> for ExtraParams {
    fn from(params: &CadesParams) -> Self {
        let mut extra = ExtraParams::default();
        extra.set(
            "mode",
            match params.mode {
                SignatureMode::Explicit => "explicit",
                SignatureMode::Implicit => "implicit",
            },
        );
        if let Some(description) = &params.content_description {
            extra.set("contentDescription", description.clone());
        }
        if let Some(policy) = &params.policy {
            extra.set_policy(policy);
        }
        extra
    }
}

impl From<&PadesParams> for ExtraParams {
    fn from(params: &PadesParams) -> Self {
        let mut extra = ExtraParams::default();
        if let Some(policy) = &params.policy {
            extra.set_policy(policy);
        }
        for (key, value) in [
            ("signReason", &params.reason),
            ("signatureProductionCity", &params.location),
            ("signerContact", &params.contact),
        ] {
            if let Some(value) = value {
                extra.set(key, value.clone());
            }
        }
        let level = match params.certification {
            CertificationLevel::NotCertified => None,
            CertificationLevel::NoChanges => Some("1"),
            CertificationLevel::FormFilling => Some("2"),
            CertificationLevel::FormFillingAndAnnotations => Some("3"),
        };
        if let Some(level) = level {
            extra.set("certificationLevel", level);
        }
        if let Some(password) = &params.password {
            extra.set("ownerPassword", password.clone());
            extra.set("userPassword", password.clone());
        }
        if params.allow_signing_certified {
            extra.set("allowSigningCertifiedPdfs", "true");
        }
        if let Some(size) = params.reserved_size {
            extra.set("signReservedSize", size.to_string());
        }
        if let Some(visible) = &params.visible {
            add_visible(&mut extra, visible);
        }
        extra
    }
}

fn add_visible(extra: &mut ExtraParams, visible: &VisibleSignature) {
    let pages = match &visible.pages {
        SignaturePages::Last => "-1".to_string(),
        SignaturePages::All => "all".to_string(),
        SignaturePages::Append => "append".to_string(),
        SignaturePages::Pages(pages) => pages
            .iter()
            .map(i32::to_string)
            .collect::<Vec<_>>()
            .join(","),
    };
    extra.set("signaturePages", pages);
    let rect = visible.rect;
    for (key, value) in [
        ("signaturePositionOnPageLowerLeftX", rect.llx),
        ("signaturePositionOnPageLowerLeftY", rect.lly),
        ("signaturePositionOnPageUpperRightX", rect.urx),
        ("signaturePositionOnPageUpperRightY", rect.ury),
    ] {
        extra.set(key, (value.round() as i64).to_string());
    }
    if let Some(text) = &visible.text {
        extra.set("layer2Text", text.clone());
    }
    let font = visible.font;
    extra.set(
        "layer2FontFamily",
        match font.family {
            FontFamily::Courier => "0",
            FontFamily::Helvetica => "1",
            FontFamily::Times => "2",
        },
    );
    extra.set("layer2FontSize", (font.size.round() as i64).to_string());
    extra.set(
        "layer2FontStyle",
        (u8::from(font.bold) | u8::from(font.italic) << 1).to_string(),
    );
    extra.set(
        "layer2FontColor",
        match font.color {
            FontColor::Black => "black",
            FontColor::White => "white",
            FontColor::LightGray => "lightGray",
            FontColor::Gray => "gray",
            FontColor::DarkGray => "darkGray",
            FontColor::Red => "red",
            FontColor::Pink => "pink",
        },
    );
    if let Some(image) = &visible.image {
        use base64ct::{Base64, Encoding};
        extra.set("signatureRubricImage", Base64::encode_string(image));
    }
    if let Some(obfuscate) = visible.obfuscate {
        extra.set("obfuscateCertText", obfuscate.to_string());
    }
    if let Some(mask) = &visible.mask {
        let positions: Vec<&str> = mask
            .positions
            .iter()
            .map(|&p| if p { "true" } else { "false" })
            .collect();
        extra.set(
            "obfuscationMask",
            format!(
                "{};{};{};{}",
                mask.obfuscated_char,
                mask.min_length,
                positions.join(","),
                mask.shift
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        digest::DigestAlgorithm,
        format::SignatureFormat,
        pades::{Font, Rect},
        policy::PolicyPreset,
    };

    #[test]
    fn properties_escaping() {
        let mut extra = ExtraParams::default();
        extra.set("layer2Text", "Firmado por $$SUBJECTCN$$\nel día");
        extra.set("a key", " =x:€");
        assert_eq!(
            extra.to_properties(),
            "layer2Text=Firmado por $$SUBJECTCN$$\\nel d\\u00EDa\na\\ key=\\ \\=x\\:\\u20AC\n"
        );
        extra.set("a key", "2");
        assert_eq!(extra.get("a key"), Some("2"));
    }

    #[test]
    fn cades_params() {
        let extra = ExtraParams::from(&CadesParams {
            digest: DigestAlgorithm::Sha512,
            mode: SignatureMode::Implicit,
            policy: Some(PolicyPreset::Age19.policy(SignatureFormat::Cades)),
            signing_time: 0,
            content_description: None,
        });
        assert_eq!(extra.get("mode"), Some("implicit"));
        assert_eq!(
            extra.get("policyIdentifier"),
            Some("2.16.724.1.3.1.1.2.1.9")
        );
        assert_eq!(
            extra.get("policyIdentifierHashAlgorithm"),
            Some("http://www.w3.org/2000/09/xmldsig#sha1")
        );
    }

    #[test]
    fn pades_params() {
        let extra = ExtraParams::from(&PadesParams {
            reason: Some("Prueba".to_string()),
            certification: CertificationLevel::FormFilling,
            visible: Some(VisibleSignature {
                pages: SignaturePages::Pages(vec![1, -1]),
                rect: Rect {
                    llx: 72.0,
                    lly: 72.4,
                    urx: 272.0,
                    ury: 142.0,
                },
                text: Some("$$SUBJECTCN$$".to_string()),
                font: Font {
                    family: FontFamily::Helvetica,
                    bold: true,
                    italic: true,
                    ..Font::default()
                },
                image: None,
                obfuscate: Some(false),
                mask: None,
            }),
            ..PadesParams::new(0)
        });
        for (key, value) in [
            ("signReason", "Prueba"),
            ("certificationLevel", "2"),
            ("signaturePages", "1,-1"),
            ("signaturePositionOnPageLowerLeftY", "72"),
            ("layer2Text", "$$SUBJECTCN$$"),
            ("layer2FontFamily", "1"),
            ("layer2FontStyle", "3"),
            ("obfuscateCertText", "false"),
        ] {
            assert_eq!(extra.get(key), Some(value), "{key}");
        }
    }
}
