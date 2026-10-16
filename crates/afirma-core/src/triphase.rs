//! Client side of AutoFirma's triphase signature protocol
//! (`afirma-server-triphase-signer`).
//!
//! 1. **pre**: the client sends the document (or its id), the certificate chain
//!    and the options; the server builds the signature and returns, for every
//!    signature, the bytes to sign (`PRE`) in an XML session.
//! 2. The client signs every `PRE` with the private key (PKCS#1 v1.5 or ECDSA)
//!    and adds the result as `PK1`.
//! 3. **post**: the client sends the session back; the server inserts the
//!    signature values and returns `OK NEWID=<id>`, where the id is usually the
//!    signed document in Base64.
//!
//! The client only needs the certificate chain and raw signatures, which makes it
//! a good fit for keys that cannot do more (smart cards, WebCrypto). Network
//! access is up to the caller: this module builds the request bodies
//! (`application/x-www-form-urlencoded`) and parses the responses.

use base64ct::{Base64, Base64Url, Encoding};
use bergshamra_xml::uppsala::{self, NodeKind};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{
    algorithm::KeyType,
    digest::DigestAlgorithm,
    error::{Error, Result},
    keystore::SigningKey,
    params::ExtraParams,
};

/// Signature format handled by the server (`format` parameter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriphaseFormat {
    /// CAdES (`cades`).
    Cades,
    /// PAdES (`pades`).
    Pades,
    /// XAdES (`xades`).
    Xades,
    /// FacturaE (`facturae`).
    Facturae,
}

impl TriphaseFormat {
    fn name(self) -> &'static str {
        match self {
            TriphaseFormat::Cades => "cades",
            TriphaseFormat::Pades => "pades",
            TriphaseFormat::Xades => "xades",
            TriphaseFormat::Facturae => "facturae",
        }
    }
}

/// Operation on the document (`cop` parameter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoOperation {
    /// New signature (`sign`).
    Sign,
    /// Co-signature (`cosign`).
    Cosign,
    /// Counter-signature (`countersign`).
    Countersign,
}

impl CryptoOperation {
    fn name(self) -> &'static str {
        match self {
            CryptoOperation::Sign => "sign",
            CryptoOperation::Cosign => "cosign",
            CryptoOperation::Countersign => "countersign",
        }
    }
}

/// Parameters shared by the pre and post requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriphaseRequest {
    /// Signature format.
    pub format: TriphaseFormat,
    /// Operation.
    pub operation: CryptoOperation,
    /// Digest algorithm.
    pub digest: DigestAlgorithm,
    /// Type of the signer's key.
    pub key_type: KeyType,
    /// Certificate chain (DER), leaf first.
    #[serde(with = "chain_serde")]
    pub chain: Vec<Vec<u8>>,
    /// Document id understood by the server's `DocumentManager`. With the
    /// default one it is the document itself in Base64; see [`document_id`].
    pub document_id: String,
    /// AutoFirma extra parameters.
    pub params: ExtraParams,
}

mod chain_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_bytes::ByteBuf;

    pub fn serialize<S: Serializer>(chain: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        let bufs: Vec<ByteBuf> = chain.iter().cloned().map(ByteBuf::from).collect();
        bufs.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let bufs = Vec::<ByteBuf>::deserialize(d)?;
        Ok(bufs.into_iter().map(ByteBuf::into_vec).collect())
    }
}

/// Document id for servers that receive the document itself: URL-safe Base64.
pub fn document_id(document: &[u8]) -> String {
    Base64Url::encode_string(document)
}

impl TriphaseRequest {
    /// Java signature algorithm name (`SHA512withRSA`, `SHA256withECDSA`...).
    pub fn algorithm(&self) -> String {
        let digest = self.digest.name().replace('-', "");
        match self.key_type {
            KeyType::Rsa => format!("{digest}withRSA"),
            KeyType::EcP256 | KeyType::EcP384 => format!("{digest}withECDSA"),
        }
    }

    fn body(&self, op: &str, session: Option<&TriphaseData>) -> String {
        let chain: Vec<String> = self
            .chain
            .iter()
            .map(|c| Base64Url::encode_string(c))
            .collect();
        let mut fields = vec![
            ("op", op.to_string()),
            ("cop", self.operation.name().to_string()),
            ("format", self.format.name().to_string()),
            ("algo", self.algorithm()),
            ("cert", chain.join(",")),
            ("doc", self.document_id.clone()),
        ];
        if let Some(session) = session {
            fields.push((
                "session",
                Base64Url::encode_string(session.to_xml().as_bytes()),
            ));
        }
        if !self.params.is_empty() {
            fields.push((
                "params",
                Base64Url::encode_string(self.params.to_properties().as_bytes()),
            ));
        }
        fields
            .into_iter()
            .map(|(key, value)| format!("{key}={}", form_encode(&value)))
            .collect::<Vec<_>>()
            .join("&")
    }

    /// Body of the pre-sign request.
    pub fn presign_body(&self) -> String {
        self.body("pre", None)
    }

    /// Body of the post-sign request with the signed `session`.
    pub fn postsign_body(&self, session: &TriphaseData) -> String {
        self.body("post", Some(session))
    }
}

/// `application/x-www-form-urlencoded` value encoding.
fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'*' => {
                out.push(char::from(b))
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// One signature of a triphase session (`<firma>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriSign {
    /// `Id` attribute.
    pub id: Option<String>,
    /// `signid` attribute.
    pub signature_id: Option<String>,
    /// Parameters (`<param n="...">`), in document order.
    pub params: Vec<(String, String)>,
}

impl TriSign {
    /// Value of a parameter.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    fn set(&mut self, key: &str, value: String) {
        match self.params.iter_mut().find(|(k, _)| k == key) {
            Some(entry) => entry.1 = value,
            None => self.params.push((key.to_string(), value)),
        }
    }

    fn remove(&mut self, key: &str) {
        self.params.retain(|(k, _)| k != key);
    }
}

/// Triphase session data (`<xml><firmas>...</firmas></xml>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriphaseData {
    /// `format` attribute.
    pub format: Option<String>,
    /// Signatures.
    pub signs: Vec<TriSign>,
}

impl TriphaseData {
    /// Parses the XML session.
    pub fn parse(xml: &[u8]) -> Result<Self> {
        let invalid = |msg: &str| Error::Triphase(format!("sesión trifásica no válida: {msg}"));
        let text = std::str::from_utf8(xml).map_err(|_| invalid("no es UTF-8"))?;
        let doc = uppsala::parse(text).map_err(|e| invalid(&e.to_string()))?;
        let elements = |id| {
            doc.children(id)
                .into_iter()
                .filter_map(|child| match doc.node_kind(child) {
                    Some(NodeKind::Element(element)) => Some((child, element)),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        let root = doc.document_element().ok_or_else(|| invalid("vacía"))?;
        let (signs_id, signs_element) = elements(root)
            .into_iter()
            .next()
            .filter(|(_, e)| e.name.local_name.eq_ignore_ascii_case("firmas"))
            .ok_or_else(|| invalid("falta el nodo 'firmas'"))?;

        let signs = elements(signs_id)
            .into_iter()
            .map(|(sign_id, sign)| TriSign {
                id: sign.get_attribute("Id").map(str::to_string),
                signature_id: sign.get_attribute("signid").map(str::to_string),
                params: elements(sign_id)
                    .into_iter()
                    .filter_map(|(param_id, param)| {
                        let key = param.get_attribute("n")?.to_string();
                        Some((key, doc.text_content_deep(param_id).trim().to_string()))
                    })
                    .collect(),
            })
            .collect();
        Ok(TriphaseData {
            format: signs_element.get_attribute("format").map(str::to_string),
            signs,
        })
    }

    /// Serializes the session as AutoFirma does.
    pub fn to_xml(&self) -> String {
        let mut out = String::from("<xml>\n <firmas");
        if let Some(format) = &self.format {
            out.push_str(&format!(" format=\"{}\"", xml_escape(format)));
        }
        out.push_str(">\n");
        for sign in &self.signs {
            out.push_str("  <firma");
            if let Some(id) = &sign.id {
                out.push_str(&format!(" Id=\"{}\"", xml_escape(id)));
            }
            if let Some(signature_id) = &sign.signature_id {
                out.push_str(&format!(" signid=\"{}\"", xml_escape(signature_id)));
            }
            out.push_str(">\n");
            for (key, value) in &sign.params {
                out.push_str(&format!(
                    "   <param n=\"{}\">{}</param>\n",
                    xml_escape(key),
                    xml_escape(value)
                ));
            }
            out.push_str("  </firma>\n");
        }
        out.push_str(" </firmas>\n</xml>");
        out
    }

    /// Signs the `PRE` value of every signature, adding the result as `PK1`.
    /// `PRE` is then removed unless the server asked to keep it (`NEED_PRE`).
    pub fn sign(&mut self, key: &dyn SigningKey, digest: DigestAlgorithm) -> Result<()> {
        if self.signs.is_empty() {
            return Err(Error::Triphase(
                "el servidor no ha devuelto prefirmas".to_string(),
            ));
        }
        for (i, sign) in self.signs.iter_mut().enumerate() {
            let pre = sign
                .get("PRE")
                .ok_or_else(|| Error::Triphase(format!("falta la prefirma número {i}")))?;
            let mut pre = decode_base64(pre)
                .ok_or_else(|| Error::Triphase(format!("prefirma {i} no válida")))?;
            let signature = key.sign_raw(digest, &pre);
            pre.zeroize();
            sign.set("PK1", Base64::encode_string(&signature?));
            if !sign
                .get("NEED_PRE")
                .is_some_and(|v| v.eq_ignore_ascii_case("true"))
            {
                sign.remove("PRE");
            }
        }
        Ok(())
    }
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Decodes standard or URL-safe Base64, with or without padding or line breaks.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let mut normalized: String = text
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    while !normalized.len().is_multiple_of(4) {
        normalized.push('=');
    }
    Base64::decode_vec(&normalized).ok()
}

/// Error text of a server response, if it is one (`ERR-nn:...`).
fn server_error(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    text.starts_with("ERR-").then(|| text.to_string())
}

/// Parses the response to the pre-sign request.
pub fn parse_presign_response(body: &[u8]) -> Result<TriphaseData> {
    if let Some(error) = server_error(body) {
        return Err(Error::Triphase(format!(
            "error del servidor en la prefirma: {error}"
        )));
    }
    if body.len() <= 8 {
        return Err(Error::Triphase(
            "no se han obtenido datos de la prefirma".to_string(),
        ));
    }
    let xml = decode_base64(&String::from_utf8_lossy(body))
        .ok_or_else(|| Error::Triphase("la prefirma no está en Base64".to_string()))?;
    TriphaseData::parse(&xml)
}

/// Parses the response to the post-sign request: the new document id, decoded
/// from Base64 (with the default `DocumentManager`, the signed document).
pub fn parse_postsign_response(body: &[u8]) -> Result<Vec<u8>> {
    if let Some(error) = server_error(body) {
        return Err(Error::Triphase(format!(
            "error del servidor en la postfirma: {error}"
        )));
    }
    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    let id = text.strip_prefix("OK NEWID=").ok_or_else(|| {
        let shown: String = text.chars().take(80).collect();
        Error::Triphase(format!(
            "la firma trifásica no ha finalizado correctamente: {shown}"
        ))
    })?;
    decode_base64(id)
        .ok_or_else(|| Error::Triphase("el resultado del servidor no es válido".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cades::{self, CadesParams, SignatureMode},
        keystore::tests::load,
        pades::{self, PadesParams},
    };

    const SESSION: &str = r#"<xml>
 <firmas format="pades">
  <firma Id="7c1b">
   <param n="PRE">MTIz</param>
   <param n="TIME">1792159674000</param>
   <param n="NEED_PRE">true</param>
  </firma>
 </firmas>
</xml>"#;

    #[test]
    fn session_round_trip() {
        let data = TriphaseData::parse(SESSION.as_bytes()).unwrap();
        assert_eq!(data.format.as_deref(), Some("pades"));
        assert_eq!(data.signs.len(), 1);
        assert_eq!(data.signs[0].id.as_deref(), Some("7c1b"));
        assert_eq!(data.signs[0].get("PRE"), Some("MTIz"));
        assert_eq!(data.to_xml(), SESSION);
        assert!(TriphaseData::parse(b"<xml><otro/></xml>").is_err());
    }

    #[test]
    fn request_bodies() {
        let key = &load("rsa.p12")[0];
        let request = TriphaseRequest {
            format: TriphaseFormat::Pades,
            operation: CryptoOperation::Sign,
            digest: DigestAlgorithm::Sha512,
            key_type: key.key_type(),
            chain: vec![key.certificate_der().to_vec(), vec![0xfb, 0xff]],
            document_id: document_id(b"%PDF?"),
            params: ExtraParams(vec![("signReason".to_string(), "Prueba".to_string())]),
        };
        assert_eq!(request.algorithm(), "SHA512withRSA");
        let body = request.presign_body();
        assert!(body.starts_with("op=pre&cop=sign&format=pades&algo=SHA512withRSA&cert="));
        // URL-safe Base64, chain separated by commas.
        assert!(body.contains("%2C-_8%3D&doc=JVBERj8%3D&params="), "{body}");
    }

    #[test]
    fn responses() {
        assert!(matches!(
            parse_presign_response(b"ERR-11:Error en la prefirma"),
            Err(Error::Triphase(msg)) if msg.contains("ERR-11")
        ));
        let data = parse_presign_response(Base64Url::encode_string(SESSION.as_bytes()).as_bytes())
            .unwrap();
        assert_eq!(data.signs[0].get("TIME"), Some("1792159674000"));
        assert_eq!(
            parse_postsign_response(b"OK NEWID=aG9sYQ==\r\n").unwrap(),
            b"hola"
        );
        assert!(parse_postsign_response(b"KO").is_err());
    }

    /// Plays the server with our own CAdES and PAdES code, the way
    /// `afirma-server-triphase-signer` does: pre builds the signature and sends
    /// the signed attributes; post rebuilds it with the same time and inserts
    /// the client's signature value.
    #[test]
    fn full_flow_with_a_local_server() {
        for keystore in ["rsa.p12", "ec.p12"] {
            let key = &load(keystore)[0];

            // CAdES.
            let params = CadesParams {
                digest: DigestAlgorithm::Sha256,
                mode: SignatureMode::Implicit,
                policy: None,
                signing_time: 1_792_159_674,
                content_description: None,
            };
            let server_pre = |data: &[u8]| {
                let prepared =
                    cades::prepare(data, key.certificate_chain(), key.key_type(), &params).unwrap();
                let session = TriphaseData {
                    format: Some("cades".to_string()),
                    signs: vec![TriSign {
                        id: Some("1".to_string()),
                        signature_id: None,
                        params: vec![(
                            "PRE".to_string(),
                            Base64::encode_string(prepared.to_be_signed()),
                        )],
                    }],
                };
                (
                    prepared,
                    Base64Url::encode_string(session.to_xml().as_bytes()),
                )
            };
            let (prepared, response) = server_pre(b"datos");
            let mut session = parse_presign_response(response.as_bytes()).unwrap();
            session.sign(key, params.digest).unwrap();
            assert!(session.signs[0].get("PRE").is_none());
            let pk1 = decode_base64(session.signs[0].get("PK1").unwrap()).unwrap();
            let signature = prepared.finish(&pk1).unwrap();
            let response = format!("OK NEWID={}", Base64Url::encode_string(&signature));
            let signature = parse_postsign_response(response.as_bytes()).unwrap();
            assert!(
                cades::verify(&signature, None).unwrap().is_valid(),
                "{keystore}"
            );

            // PAdES.
            let pdf = std::fs::read(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/data/pades/doc.pdf"
            ))
            .unwrap();
            let prepared = pades::prepare(
                &pdf,
                key.certificate_chain(),
                key.key_type(),
                &PadesParams::new(1_792_159_674),
            )
            .unwrap();
            let mut session = TriphaseData {
                format: Some("pades".to_string()),
                signs: vec![TriSign {
                    id: None,
                    signature_id: None,
                    params: vec![
                        (
                            "PRE".to_string(),
                            Base64::encode_string(prepared.to_be_signed()),
                        ),
                        ("NEED_PRE".to_string(), "true".to_string()),
                    ],
                }],
            };
            session.sign(key, DigestAlgorithm::Sha512).unwrap();
            assert!(session.signs[0].get("PRE").is_some());
            let pk1 = decode_base64(session.signs[0].get("PK1").unwrap()).unwrap();
            let signed = prepared.finish(&pk1).unwrap();
            assert!(
                pades::verify(&signed, None).unwrap().is_valid(),
                "{keystore}"
            );
        }
    }
}
