use std::rc::Rc;

use afirma_core::{
    Error as CoreError,
    cades::{SignerReport, SignerStatus},
    job::{Job, JobOutput},
    package::PackageReport,
    pades::{CertificationLevel, PdfSignatureReport},
    validation::Verification,
    xades::XadesVerifyReport,
};
use dominator::{Dom, clone, html};
use futures_signals::signal::{Mutable, SignalExt};
use wasm_bindgen_futures::spawn_local;

use crate::{
    components::file_picker::{FilePicker, LoadedFile},
    css::{
        CARD_CLASS, CARD_TITLE_CLASS, CHIP_CLASS, DETAILS_LIST_CLASS, ERROR_CLASS, STATUS_CLASS,
        TILE_CLASS, VERDICT_CLASS,
    },
    state::format_date_time,
    worker::WorkerClient,
};

/// Checks the integrity of a signature or signed document as soon as it is
/// opened, asking for the signed data of detached signatures.
#[derive(Debug)]
pub struct Verifier {
    worker: Rc<WorkerClient>,
    signature: Rc<LoadedFile>,
    data: Mutable<Option<Rc<LoadedFile>>>,
    /// Password of an encrypted PDF, shared with the signing panel.
    password: Mutable<Option<String>>,
    /// Set when the PDF turns out to be encrypted.
    needs_password: Mutable<bool>,
    missing_data: Mutable<bool>,
    result: Mutable<Option<Rc<Verification>>>,
    busy: Mutable<bool>,
    error: Mutable<Option<String>>,
}

impl Verifier {
    pub fn new(
        worker: Rc<WorkerClient>,
        signature: Rc<LoadedFile>,
        data: Option<Rc<LoadedFile>>,
        password: Mutable<Option<String>>,
        needs_password: Mutable<bool>,
    ) -> Rc<Self> {
        Rc::new(Self {
            worker,
            signature,
            data: Mutable::new(data),
            password,
            needs_password,
            missing_data: Mutable::new(false),
            result: Mutable::new(None),
            busy: Mutable::new(false),
            error: Mutable::new(None),
        })
    }

    pub fn verify(this: &Rc<Self>) {
        let job = Job::Verify {
            signature: this.signature.data.clone(),
            data: this.data.get_cloned().map(|file| file.data.clone()),
            password: this.password.get_cloned(),
        };
        this.result.set(None);
        this.error.set(None);
        this.busy.set(true);
        spawn_local(clone!(this => async move {
            match this.worker.run(job).await {
                Ok(JobOutput::Verification(verification)) => {
                    this.missing_data.set(false);
                    this.result.set(Some(Rc::new(verification)));
                }
                Ok(other) => log::error!("Unexpected worker output: {other:?}"),
                Err(err) => {
                    let message = err.to_string();
                    if message == CoreError::MissingSignedData.to_string() {
                        this.missing_data.set(true);
                    } else if message == CoreError::PdfPasswordRequired.to_string()
                        || message == CoreError::WrongPdfPassword.to_string()
                    {
                        // The document asks for the password and reports wrong ones.
                        this.needs_password.set_neq(true);
                    } else {
                        this.error.set(Some(message));
                    }
                }
            }
            this.busy.set(false);
        }));
    }

    pub fn render(this: &Rc<Self>) -> Dom {
        let data_picker = FilePicker::new(
            "verify_data",
            "Seleccionar el fichero firmado",
            "*/*",
            clone!(this => move |result| match result {
                Ok(file) => {
                    this.data.set(Some(Rc::new(file)));
                    Self::verify(&this);
                }
                Err(err) => this.error.set(Some(err)),
            }),
        );

        html!("section", {
            .class(&*CARD_CLASS)
            .attr("id", "verify_card")
            .attr("aria-labelledby", "verify_title")
            .child(html!("h2", { .attr("id", "verify_title").class(&*CARD_TITLE_CLASS).text("Verificación") }))
            .child_signal(this.missing_data.signal().map(move |missing| missing.then(|| html!("div", {
                .children(&mut [
                    html!("p", {
                        .style("margin-top", "0")
                        .text("Es una firma separada de los datos: para comprobarla, seleccione también el \
                               fichero que se firmó.")
                    }),
                    FilePicker::render(&data_picker),
                ])
            }))))
            .child_signal(this.busy.signal().map(|busy| {
                busy.then(|| html!("p", { .class(&*STATUS_CLASS).attr("role", "status").text("Verificando…") }))
            }))
            .child_signal(this.error.signal_cloned().map(|error| {
                error.map(|error| html!("p", { .class(&*ERROR_CLASS).attr("role", "alert").text(&error) }))
            }))
            .child_signal(this.result.signal_cloned().map(|result| result.map(|result| render_result(&result))))
            .child(html!("p", {
                .class(&*crate::css::MUTED_CLASS)
                .style("margin-top", "1rem")
                .text("Se comprueba que los datos no han cambiado y que cada firma corresponde a su \
                       certificado; no se consulta la confianza ni la revocación de los certificados.")
            }))
        })
    }
}

fn render_result(verification: &Verification) -> Dom {
    let (summary, cards) = describe(verification);
    let valid = verification.is_valid();

    html!("div", {
        .attr("id", "verify_result")
        .attr("role", "status")
        .children(&mut [
            html!("p", {
                .attr("id", "verify_summary")
                .class(&*VERDICT_CLASS)
                .style("color", if valid { "var(--ok)" } else { "var(--danger)" })
                .style("background", if valid { "var(--ok-soft)" } else { "var(--danger-soft)" })
                .children(&mut [
                    html!("span", { .attr("aria-hidden", "true").text(if valid { "✔" } else { "✘" }) }),
                    html!("span", {
                        .text(&format!(
                            "{} {summary}",
                            if valid { "Firmas válidas." } else { "Hay firmas no válidas." }
                        ))
                    }),
                ])
            }),
        ])
        .children(cards)
    })
}

/// Summary and one card per signature.
fn describe(verification: &Verification) -> (String, Vec<Dom>) {
    match verification {
        Verification::Cades(report) => (
            format!(
                "Firma CAdES {} con {} firmante(s){}.",
                if report.implicit {
                    "implícita"
                } else {
                    "explícita"
                },
                report.signers.iter().filter(|s| s.depth == 0).count(),
                countersignatures(report.signers.iter().filter(|s| s.depth > 0).count()),
            ),
            report
                .signers
                .iter()
                .map(|signer| render_signer(signer, None, &[]))
                .collect(),
        ),
        Verification::Pades(report) if report.signatures.is_empty() => {
            ("El PDF no contiene firmas.".to_string(), Vec::new())
        }
        Verification::Pades(report) => (
            format!("El PDF contiene {} firma(s).", report.signatures.len()),
            report
                .signatures
                .iter()
                .map(|signature| render_signer(&signature.signer, Some(signature), &[]))
                .collect(),
        ),
        Verification::Xades(report) => (
            format!(
                "Documento XML con {} firma(s){}.",
                report
                    .signatures
                    .iter()
                    .filter(|s| s.signer.depth == 0)
                    .count(),
                countersignatures(
                    report
                        .signatures
                        .iter()
                        .filter(|s| s.signer.depth > 0)
                        .count()
                ),
            ),
            xml_cards(report),
        ),
        Verification::Odf(report) => describe_package("OpenDocument", report),
        Verification::Ooxml(report) => describe_package("Office (OOXML)", report),
        Verification::Asic(report) => {
            let (summary, cards) = describe(&report.signature);
            (
                format!(
                    "Contenedor ASiC-S con el fichero «{}». {summary}",
                    report.file_name
                ),
                cards,
            )
        }
    }
}

/// `, con N contrafirma(s)` when there are counter-signatures.
fn countersignatures(count: usize) -> String {
    if count == 0 {
        String::new()
    } else {
        format!(" y {count} contrafirma(s)")
    }
}

/// One card per XML signature.
fn xml_cards(report: &XadesVerifyReport) -> Vec<Dom> {
    report
        .signatures
        .iter()
        .map(|signature| {
            let mut extra = vec![(
                "Formato",
                if signature.xades { "XAdES" } else { "XMLDSig" }.to_string(),
            )];
            if !signature.claimed_roles.is_empty() {
                extra.push(("Papel", signature.claimed_roles.join(", ")));
            }
            if let Some(city) = &signature.production_city {
                extra.push(("Lugar", city.clone()));
            }
            render_signer(&signature.signer, None, &extra)
        })
        .collect()
}

fn describe_package(kind: &str, report: &PackageReport) -> (String, Vec<Dom>) {
    let mut summary = format!(
        "Documento {kind} con {} firma(s).",
        report.signatures.signatures.len()
    );
    let mut cards = xml_cards(&report.signatures);
    if !report.unsigned_parts.is_empty() {
        summary.push_str(" Hay partes del documento sin firmar.");
        cards.push(html!("article", {
            .class(&*TILE_CLASS)
            .attr("id", "verify_unsigned_parts")
            .attr("data-status", "invalid")
            .children(&mut [
                html!("p", {
                    .style("margin", "0 0 0.5rem")
                    .text("Partes que alguna firma no cubre (añadidas o cambiadas después de firmar):")
                }),
                html!("ul", {
                    .style("margin", "0")
                    .children(report.unsigned_parts.iter().map(|part| html!("li", { .text(part) })))
                }),
            ])
        }));
    }
    (summary, cards)
}

fn status_text(status: &SignerStatus) -> String {
    match status {
        SignerStatus::Valid => "Válida".to_string(),
        SignerStatus::DigestMismatch => "No válida: los datos firmados han cambiado".to_string(),
        SignerStatus::InvalidSignature => {
            "No válida: la firma no corresponde al certificado".to_string()
        }
        SignerStatus::CertificateNotFound => {
            "No se puede comprobar: falta el certificado".to_string()
        }
        SignerStatus::CertificateMismatch => {
            "No válida: el certificado incluido no es el que se firmó".to_string()
        }
        SignerStatus::Unsupported(what) => format!("No se puede comprobar: {what} no soportado"),
    }
}

fn render_signer(
    signer: &SignerReport,
    pdf: Option<&PdfSignatureReport>,
    extra: &[(&'static str, String)],
) -> Dom {
    let document_timestamp = pdf.is_some_and(|p| p.sub_filter == "ETSI.RFC3161");
    let valid = signer.status == SignerStatus::Valid;
    let badge = match signer.depth {
        0 => None,
        1 => Some("Contrafirma".to_string()),
        depth => Some(format!("Contrafirma de nivel {depth}")),
    };
    let mut rows: Vec<(&str, String)> = extra.to_vec();
    if let Some(cert) = &signer.certificate {
        rows.push(("Emisor", cert.issuer_cn.clone()));
    }
    if let Some(digest) = signer.digest {
        rows.push(("Algoritmo", digest.name().to_string()));
    }
    let time = signer
        .signing_time
        .or_else(|| pdf.and_then(|p| p.claimed_time));
    if let Some(time) = time {
        rows.push((
            if document_timestamp {
                "Fecha del sello"
            } else {
                "Fecha declarada"
            },
            format_date_time(time),
        ));
    }
    if !document_timestamp {
        for timestamp in &signer.timestamps {
            let mut text = match timestamp.time {
                Some(time) => format_date_time(time),
                None => "sin fecha".to_string(),
            };
            if let Some(tsa) = &timestamp.tsa {
                text.push_str(&format!(" ({tsa})"));
            }
            if timestamp.status != SignerStatus::Valid {
                text.push_str(&format!(" — {}", status_text(&timestamp.status)));
            }
            rows.push(("Sello de tiempo", text));
        }
    }
    if let Some(policy) = &signer.policy {
        rows.push(("Política", policy.clone()));
    }
    if let Some(pdf) = pdf {
        rows.push(("Campo", pdf.field.clone()));
        rows.push((
            "Tipo",
            if document_timestamp {
                "sello de tiempo del documento (ETSI.RFC3161)".to_string()
            } else {
                pdf.sub_filter.clone()
            },
        ));
        if let Some(reason) = &pdf.reason {
            rows.push(("Motivo", reason.clone()));
        }
        if let Some(location) = &pdf.location {
            rows.push(("Lugar", location.clone()));
        }
        if let Some(level) = pdf.certification {
            rows.push((
                "Certificación",
                match level {
                    CertificationLevel::NoChanges => "no se permiten cambios",
                    CertificationLevel::FormFilling => "se permite rellenar formularios y firmar",
                    CertificationLevel::FormFillingAndAnnotations => {
                        "se permiten formularios, firmas y anotaciones"
                    }
                    CertificationLevel::NotCertified => "no",
                }
                .to_string(),
            ));
        }
        rows.push((
            "Alcance",
            if pdf.covers_whole_document {
                "cubre todo el documento".to_string()
            } else {
                "el documento se modificó después de esta firma (por ejemplo, con firmas posteriores)"
                    .to_string()
            },
        ));
    }

    html!("article", {
        .class(&*TILE_CLASS)
        // Counter-signatures under the signature they sign.
        .style("margin-left", &format!("{}rem", 1.5 * signer.depth.min(4) as f32))
        .attr("data-depth", &signer.depth.to_string())
        .attr("data-status", match signer.status {
            SignerStatus::Valid => "valid",
            _ => "invalid",
        })
        .child(html!("div", {
            .style("display", "flex")
            .style("align-items", "baseline")
            .style("gap", "0.5rem")
            .children(&mut [
                html!("span", {
                    .attr("aria-hidden", "true")
                    .style("color", if valid { "var(--ok)" } else { "var(--danger)" })
                    .text(if valid { "✔" } else { "✘" })
                }),
                html!("span", {
                    .style("font-weight", "600")
                    .style("flex", "1")
                    .style("word-break", "break-word")
                    .text(signer.certificate.as_ref().map_or("Firmante desconocido", |cert| cert.subject_cn.as_str()))
                }),
            ])
            .apply_if(badge.is_some(), |dom| dom.child(html!("span", {
                .class(&*CHIP_CLASS)
                .style("font-size", "0.75rem")
                .text(badge.as_deref().unwrap_or_default())
            })))
        }))
        .child(html!("p", {
            .style("margin", "0.15rem 0 0.5rem 1.4rem")
            .style("font-size", "0.875rem")
            .style("color", if valid { "var(--ok)" } else { "var(--danger)" })
            .text(&status_text(&signer.status))
        }))
        .child(html!("dl", {
            .class(&*DETAILS_LIST_CLASS)
            .style("margin-left", "1.4rem")
            .style("font-size", "0.875rem")
            .children(rows.into_iter().flat_map(|(name, value)| {
                [
                    html!("dt", { .style("color", "var(--muted)").text(name) }),
                    html!("dd", { .style("margin", "0").text(&value) }),
                ]
            }))
        }))
    })
}
