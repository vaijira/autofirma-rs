//! Client of AutoFirma's JSON batch signing service (`afirma-crypto-batch-client`,
//! `BatchSigner.signJSON`). A web application describes a batch of signatures
//! in JSON; the documents stay on its servers:
//!
//! 1. **presign**: the client posts the batch and its certificate chain; the
//!    server answers with a triphase session holding the data to sign of every
//!    signature (`td`) and the signatures that already failed (`results`).
//! 2. The client signs every `PRE` with the private key, as in a triphase
//!    signature ([`TriphaseData::sign`]).
//! 3. **postsign**: the client posts the batch (with the failed signatures
//!    marked), the chain and the signed session; the server builds and stores
//!    the signatures and answers with the result of each one.
//!
//! As with [`crate::triphase`], network access is up to the caller: this module
//! builds the request bodies and parses the responses. Only JSON batches are
//! supported (AutoFirma's XML batches are deprecated).

use base64ct::{Base64, Base64Url, Encoding};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    digest::DigestAlgorithm,
    error::{Error, Result},
    keystore::SigningKey,
    triphase::{TriSign, TriphaseData},
};

/// Result of one signature of the batch (AutoFirma's `BatchDataResult`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchResult {
    /// Id of the signature in the batch.
    pub id: String,
    /// `DONE_AND_SAVED`, `ERROR_PRE`, `ERROR_POST`, `SKIPPED`...
    pub result: String,
    /// Details of an error.
    pub description: Option<String>,
}

impl BatchResult {
    /// Whether the signature was made and stored.
    pub fn is_ok(&self) -> bool {
        self.result == "DONE_AND_SAVED"
    }

    /// The result in Spanish.
    pub fn text(&self) -> &'static str {
        match self.result.as_str() {
            "DONE_AND_SAVED" => "Firmado y guardado",
            "DONE_BUT_NOT_SAVED_YET" => "Firmado, sin guardar todavía",
            "DONE_BUT_SAVED_SKIPPED" => "Firmado, no se guardó",
            "DONE_BUT_ERROR_SAVING" => "Firmado, pero no se pudo guardar",
            "ERROR_PRE" => "Error en la prefirma",
            "ERROR_POST" => "Error en la postfirma",
            "SKIPPED" => "Omitido",
            "SAVE_ROLLBACKED" => "Guardado deshecho",
            "NOT_STARTED" => "No iniciado",
            _ => "Resultado desconocido",
        }
    }
}

/// What to do after signing the pre-signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatchStep {
    /// Post this body to the postsign service.
    Post(String),
    /// Nothing to sign: these are the results.
    Done(Vec<BatchResult>),
}

fn invalid(message: impl std::fmt::Display) -> Error {
    Error::Batch(message.to_string())
}

fn parse_json(json: &[u8], what: &str) -> Result<Value> {
    serde_json::from_slice(json).map_err(|e| invalid(format!("{what} no es un JSON válido: {e}")))
}

/// Digest algorithm of the batch, from its `algorithm` (`SHA512withRSA`,
/// `SHA256withECDSA`, `SHA-256`...).
pub fn digest(batch: &[u8]) -> Result<DigestAlgorithm> {
    let json = parse_json(batch, "el lote")?;
    let algorithm = json
        .get("algorithm")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("el lote no indica el algoritmo de firma"))?;
    let name = algorithm.to_ascii_uppercase().replace('-', "");
    [
        ("SHA512", DigestAlgorithm::Sha512),
        ("SHA384", DigestAlgorithm::Sha384),
        ("SHA256", DigestAlgorithm::Sha256),
        ("SHA1", DigestAlgorithm::Sha1),
    ]
    .into_iter()
    .find(|(prefix, _)| name.starts_with(prefix))
    .map(|(_, digest)| digest)
    .ok_or_else(|| invalid(format!("algoritmo no soportado: {algorithm}")))
}

/// Certificate chain as the batch services expect it: URL-safe Base64, `;`-separated.
fn certificates(chain: &[Vec<u8>]) -> String {
    chain
        .iter()
        .map(|cert| Base64Url::encode_string(cert))
        .collect::<Vec<_>>()
        .join(";")
}

/// Body of the presign request (`application/x-www-form-urlencoded`).
pub fn presign_body(batch: &[u8], chain: &[Vec<u8>]) -> String {
    format!(
        "json={}&certs={}",
        Base64Url::encode_string(batch),
        certificates(chain)
    )
}

/// Body of the postsign request.
fn postsign_body(batch: &[u8], chain: &[Vec<u8>], session: &TriphaseData) -> String {
    format!(
        "json={}&certs={}&tridata={}",
        Base64Url::encode_string(batch),
        certificates(chain),
        Base64Url::encode_string(session_to_json(session).as_bytes())
    )
}

/// Triphase session from its JSON form, with the signatures grouped
/// (`{"signs":[{"signinfo":[...]}]}`) or not (`{"signinfo":[...]}`).
fn session_from_json(json: &Value) -> Result<TriphaseData> {
    let sign_info = |info: &Value| -> Result<TriSign> {
        let text = |key: &str| info.get(key).and_then(Value::as_str).map(str::to_string);
        let params = info
            .get("params")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("firma del lote sin parámetros"))?
            .iter()
            .map(|(key, value)| {
                let value = match value {
                    Value::String(value) => value.clone(),
                    other => other.to_string(),
                };
                (key.clone(), value)
            })
            .collect();
        Ok(TriSign {
            id: Some(text("id").ok_or_else(|| invalid("firma del lote sin identificador"))?),
            signature_id: text("signid"),
            params,
        })
    };
    let infos: Vec<&Value> = match json.get("signs").and_then(Value::as_array) {
        Some(signs) => signs
            .iter()
            .filter_map(|sign| sign.get("signinfo").and_then(Value::as_array))
            .flatten()
            .collect(),
        None => json
            .get("signinfo")
            .and_then(Value::as_array)
            .map(|infos| infos.iter().collect())
            .unwrap_or_default(),
    };
    Ok(TriphaseData {
        format: json
            .get("format")
            .and_then(Value::as_str)
            .map(str::to_string),
        signs: infos.into_iter().map(sign_info).collect::<Result<_>>()?,
    })
}

/// JSON form of a triphase session, as AutoFirma's `TriphaseDataParser` writes it.
fn session_to_json(session: &TriphaseData) -> String {
    let infos: Vec<Value> = session
        .signs
        .iter()
        .map(|sign| {
            let mut info = Map::new();
            if let Some(id) = &sign.id {
                info.insert("id".to_string(), Value::String(id.clone()));
            }
            if let Some(signature_id) = &sign.signature_id {
                info.insert("signid".to_string(), Value::String(signature_id.clone()));
            }
            let params: Map<String, Value> = sign
                .params
                .iter()
                .map(|(key, value)| (key.clone(), Value::String(value.clone())))
                .collect();
            info.insert("params".to_string(), Value::Object(params));
            Value::Object(info)
        })
        .collect();
    let mut json = Map::new();
    if let Some(format) = &session.format {
        json.insert("format".to_string(), Value::String(format.clone()));
    }
    json.insert("signinfo".to_string(), Value::Array(infos));
    Value::Object(json).to_string()
}

fn parse_results(json: Option<&Value>) -> Result<Vec<BatchResult>> {
    json.and_then(Value::as_array)
        .map(|results| {
            results
                .iter()
                .map(|result| {
                    let text =
                        |key: &str| result.get(key).and_then(Value::as_str).map(str::to_string);
                    Ok(BatchResult {
                        id: text("id").ok_or_else(|| invalid("resultado sin identificador"))?,
                        result: text("result").ok_or_else(|| invalid("resultado sin estado"))?,
                        description: text("description"),
                    })
                })
                .collect()
        })
        .unwrap_or(Ok(Vec::new()))
}

/// The batch with the signatures of `errors` marked as finished with their
/// result, so the postsign service skips them (AutoFirma's `JSONBatchInfo.updateResults`).
fn mark_errors(batch: &[u8], errors: &[BatchResult]) -> Result<Vec<u8>> {
    let mut json = parse_json(batch, "el lote")?;
    if let Some(signs) = json.get_mut("singlesigns").and_then(Value::as_array_mut) {
        for sign in signs.iter_mut().filter_map(Value::as_object_mut) {
            let id = sign.get("id").and_then(Value::as_str).unwrap_or_default();
            let Some(error) = errors.iter().find(|e| e.id == id) else {
                continue;
            };
            for key in ["datareference", "format", "suboperation", "extraparams"] {
                sign.remove(key);
            }
            sign.insert("result".to_string(), Value::String(error.result.clone()));
            if let Some(description) = &error.description {
                sign.insert(
                    "description".to_string(),
                    Value::String(description.clone()),
                );
            }
        }
    }
    Ok(json.to_string().into_bytes())
}

/// Error text of a server response that is not JSON (`ERR-nn:...`, HTML...).
fn check_server_error(body: &[u8], step: &str) -> Result<()> {
    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    if text.starts_with('{') {
        return Ok(());
    }
    let shown: String = text.chars().take(120).collect();
    Err(invalid(format!("error del servidor en la {step}: {shown}")))
}

/// Parses the presign response, signs its pre-signatures with `key` and
/// returns the body of the postsign request (or the results, if nothing is
/// left to sign).
pub fn sign_presigned(
    batch: &[u8],
    presign_response: &[u8],
    key: &dyn SigningKey,
) -> Result<BatchStep> {
    check_server_error(presign_response, "prefirma")?;
    let response = parse_json(presign_response, "la respuesta de prefirma")?;
    let errors = parse_results(response.get("results"))?;
    let Some(session) = response.get("td").filter(|td| !td.is_null()) else {
        return Ok(BatchStep::Done(errors));
    };
    let mut session = session_from_json(session)?;
    if session.signs.is_empty() {
        return Ok(BatchStep::Done(errors));
    }
    let batch = if errors.is_empty() {
        batch.to_vec()
    } else {
        mark_errors(batch, &errors)?
    };
    session.sign(key, digest(&batch)?)?;
    let chain = key
        .certificate_chain()
        .iter()
        .map(crate::cert::to_der)
        .collect::<Result<Vec<_>>>()?;
    Ok(BatchStep::Post(postsign_body(&batch, &chain, &session)))
}

/// Parses the postsign response: the result of every signature.
pub fn parse_postsign_response(body: &[u8]) -> Result<Vec<BatchResult>> {
    check_server_error(body, "postfirma")?;
    let response = parse_json(body, "la respuesta de postfirma")?;
    parse_results(response.get("signs"))
}

/// Decodes a batch given in Base64 (as web pages pass it) or returns it as is
/// if it is already JSON.
pub fn decode_batch(input: &[u8]) -> Result<Vec<u8>> {
    let text = String::from_utf8_lossy(input);
    let text = text.trim();
    if text.starts_with('{') {
        return Ok(text.as_bytes().to_vec());
    }
    let compact: String = text
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    let decoded = Base64::decode_vec(&compact)
        .or_else(|_| {
            Base64::decode_vec(&format!(
                "{compact}{}",
                "=".repeat((4 - compact.len() % 4) % 4)
            ))
        })
        .map_err(|_| invalid("el lote no es JSON ni está en Base64"))?;
    parse_json(&decoded, "el lote")?;
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cades::{self, CadesParams, SignatureMode},
        keystore::tests::load,
    };

    const BATCH: &str = r#"{"algorithm":"SHA256withRSA","format":"CAdES","suboperation":"sign","singlesigns":[{"id":"1","datareference":"ZG9j"},{"id":"2","datareference":"bm9wZQ=="}]}"#;

    fn form_value<'a>(body: &'a str, key: &str) -> &'a str {
        body.split('&')
            .find_map(|field| field.strip_prefix(&format!("{key}=")))
            .unwrap()
    }

    #[test]
    fn digests_and_inputs() {
        assert_eq!(digest(BATCH.as_bytes()).unwrap(), DigestAlgorithm::Sha256);
        assert_eq!(
            digest(br#"{"algorithm":"SHA-512"}"#).unwrap(),
            DigestAlgorithm::Sha512
        );
        assert!(digest(br#"{"algorithm":"MD5withRSA"}"#).is_err());
        assert!(digest(b"{}").is_err());
        let encoded = Base64::encode_string(BATCH.as_bytes());
        assert_eq!(decode_batch(encoded.as_bytes()).unwrap(), BATCH.as_bytes());
        assert_eq!(decode_batch(BATCH.as_bytes()).unwrap(), BATCH.as_bytes());
        assert!(decode_batch(b"hola").is_err());
    }

    /// Plays both batch services with our CAdES code: presign prepares the
    /// signatures, postsign finishes them with the client's PKCS#1 values.
    #[test]
    fn full_flow_with_a_local_server() {
        for keystore in ["rsa.p12", "ec.p12"] {
            let key = &load(keystore)[0];
            let chain: Vec<Vec<u8>> = key
                .certificate_chain()
                .iter()
                .map(|c| crate::cert::to_der(c).unwrap())
                .collect();
            let body = presign_body(BATCH.as_bytes(), &chain);
            let received = Base64Url::decode_vec(form_value(&body, "json")).unwrap();
            assert_eq!(received, BATCH.as_bytes());
            assert_eq!(form_value(&body, "certs").split(';').count(), 2);

            // Presign: signature 1 is prepared, signature 2 fails.
            let params = CadesParams {
                digest: DigestAlgorithm::Sha256,
                mode: SignatureMode::Explicit,
                policy: None,
                signing_time: 1_792_428_983,
                content_description: None,
            };
            let prepared =
                cades::prepare(b"doc", key.certificate_chain(), key.key_type(), &params).unwrap();
            let presign = format!(
                r#"{{"td":{{"format":"CAdES","signs":[{{"signinfo":[{{"id":"1","params":{{"PRE":"{}","NEED_PRE":"true"}}}}]}}]}},"results":[{{"id":"2","result":"ERROR_PRE","description":"No existe"}}]}}"#,
                Base64::encode_string(prepared.to_be_signed())
            );
            let BatchStep::Post(body) =
                sign_presigned(BATCH.as_bytes(), presign.as_bytes(), key).unwrap()
            else {
                panic!("nothing to post");
            };

            // Postsign: the batch has signature 2 marked; the session has PK1.
            let batch: Value =
                serde_json::from_slice(&Base64Url::decode_vec(form_value(&body, "json")).unwrap())
                    .unwrap();
            assert_eq!(batch["singlesigns"][1]["result"], "ERROR_PRE");
            assert!(batch["singlesigns"][1].get("datareference").is_none());
            assert_eq!(batch["singlesigns"][0]["datareference"], "ZG9j");
            let session: Value = serde_json::from_slice(
                &Base64Url::decode_vec(form_value(&body, "tridata")).unwrap(),
            )
            .unwrap();
            assert_eq!(session["format"], "CAdES");
            let info = &session["signinfo"][0];
            assert_eq!(info["id"], "1");
            let pk1 = Base64::decode_vec(info["params"]["PK1"].as_str().unwrap()).unwrap();
            let signature = prepared.finish(&pk1).unwrap();
            assert!(
                cades::verify(&signature, Some(b"doc")).unwrap().is_valid(),
                "{keystore}"
            );

            let results = parse_postsign_response(
                br#"{"signs":[{"id":"1","result":"DONE_AND_SAVED"},{"id":"2","result":"ERROR_PRE","description":"No existe"}]}"#,
            )
            .unwrap();
            assert!(results[0].is_ok() && !results[1].is_ok());
            assert_eq!(results[1].text(), "Error en la prefirma");
        }
    }

    #[test]
    fn nothing_to_sign_and_server_errors() {
        let key = &load("rsa.p12")[0];
        let step = sign_presigned(
            BATCH.as_bytes(),
            br#"{"results":[{"id":"1","result":"ERROR_PRE"},{"id":"2","result":"ERROR_PRE"}]}"#,
            key,
        )
        .unwrap();
        let BatchStep::Done(results) = step else {
            panic!("unexpected post");
        };
        assert_eq!(results.len(), 2);
        assert!(matches!(
            sign_presigned(BATCH.as_bytes(), b"ERR-21: lote no valido", key),
            Err(Error::Batch(msg)) if msg.contains("ERR-21")
        ));
        assert!(parse_postsign_response(b"<html>500</html>").is_err());
        // Ungrouped sessions are read too.
        let session = session_from_json(
            &serde_json::from_str(
                r#"{"signinfo":[{"id":"a","signid":"s","params":{"PRE":"MTIz","N":1}}]}"#,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(session.signs[0].signature_id.as_deref(), Some("s"));
        assert_eq!(session.signs[0].get("N"), Some("1"));
        let json: Value = serde_json::from_str(&session_to_json(&session)).unwrap();
        assert_eq!(json["signinfo"][0]["params"]["PRE"], "MTIz");
    }
}
