use std::rc::Rc;

use afirma_core::{
    Error as CoreError,
    cades::{SignerReport, SignerStatus},
    job::{Job, JobOutput},
    pades::{CertificationLevel, PdfSignatureReport},
    validation::Verification,
};
use dominator::{Dom, clone, events, html, with_node};
use futures_signals::signal::{Mutable, SignalExt};
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlInputElement;

use crate::{
    components::file_picker::{FilePicker, LoadedFile},
    css::{CARD_CLASS, ERROR_CLASS},
    state::format_date_time,
    worker::WorkerClient,
};

/// What the verification still needs from the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Missing {
    Nothing,
    /// Explicit CAdES signature: the signed file.
    SignedData,
    /// Encrypted PDF: its password.
    Password,
}

/// "Verificar" view: checks the integrity of CAdES signatures and signed PDFs.
#[derive(Debug)]
pub struct VerifyPage {
    worker: Rc<WorkerClient>,
    signature: Mutable<Option<Rc<LoadedFile>>>,
    data: Mutable<Option<Rc<LoadedFile>>>,
    password: Mutable<Option<String>>,
    missing: Mutable<Missing>,
    result: Mutable<Option<Rc<Verification>>>,
    busy: Mutable<bool>,
    error: Mutable<Option<String>>,
}

impl VerifyPage {
    pub fn new(worker: Rc<WorkerClient>) -> Rc<Self> {
        Rc::new(Self {
            worker,
            signature: Mutable::new(None),
            data: Mutable::new(None),
            password: Mutable::new(None),
            missing: Mutable::new(Missing::Nothing),
            result: Mutable::new(None),
            busy: Mutable::new(false),
            error: Mutable::new(None),
        })
    }

    fn verify(this: &Rc<Self>) {
        let Some(signature) = this.signature.get_cloned() else {
            return;
        };
        let job = Job::Verify {
            signature: signature.data.clone(),
            data: this.data.get_cloned().map(|file| file.data.clone()),
            password: this.password.get_cloned(),
        };
        this.result.set(None);
        this.error.set(None);
        this.busy.set(true);
        spawn_local(clone!(this => async move {
            match this.worker.run(job).await {
                Ok(JobOutput::Verification(verification)) => {
                    this.missing.set(Missing::Nothing);
                    this.result.set(Some(Rc::new(verification)));
                }
                Ok(other) => log::error!("Unexpected worker output: {other:?}"),
                Err(err) => {
                    let message = err.to_string();
                    let missing = if message == CoreError::MissingSignedData.to_string() {
                        Missing::SignedData
                    } else if message == CoreError::PdfPasswordRequired.to_string()
                        || message == CoreError::WrongPdfPassword.to_string()
                    {
                        Missing::Password
                    } else {
                        Missing::Nothing
                    };
                    this.missing.set(missing);
                    if missing == Missing::Nothing || this.password.lock_ref().is_some() {
                        this.error.set(Some(message));
                    }
                }
            }
            this.busy.set(false);
        }));
    }

    pub fn render(this: &Rc<Self>) -> Dom {
        let signature_picker = FilePicker::new(
            "verify_file",
            "Seleccionar firma o PDF firmado",
            "*/*",
            clone!(this => move |result| match result {
                Ok(file) => {
                    this.signature.set(Some(Rc::new(file)));
                    this.data.set(None);
                    this.password.set(None);
                    Self::verify(&this);
                }
                Err(err) => this.error.set(Some(err)),
            }),
        );
        let data_picker = FilePicker::new(
            "verify_data",
            "Seleccionar fichero firmado",
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
            .children(&mut [
                html!("h2", { .text("Verificar") }),
                html!("p", {
                    .text("Compruebe la integridad de una firma CAdES (.csig, .p7s) o de las firmas de un PDF. \
                           Se verifica que los datos no han cambiado y que la firma corresponde al certificado; \
                           no se consulta la confianza ni la revocación del certificado.")
                }),
                FilePicker::render(&signature_picker),
            ])
            .child_signal(this.missing.signal().map(clone!(this, data_picker => move |missing| match missing {
                Missing::Nothing => None,
                Missing::SignedData => Some(html!("div", {
                    .style("margin", "1rem 0")
                    .children(&mut [
                        html!("p", { .text("Es una firma explícita: seleccione también el fichero que se firmó.") }),
                        FilePicker::render(&data_picker),
                    ])
                })),
                Missing::Password => Some(Self::render_password(&this)),
            })))
            .child_signal(this.busy.signal().map(|busy| busy.then(|| html!("p", { .attr("role", "status").text("Verificando…") }))))
            .child_signal(this.error.signal_cloned().map(|error| {
                error.map(|error| html!("p", { .class(&*ERROR_CLASS).attr("role", "alert").text(&error) }))
            }))
            .child_signal(this.result.signal_cloned().map(|result| result.map(|result| Self::render_result(&result))))
        })
    }

    fn render_password(this: &Rc<Self>) -> Dom {
        let password = Mutable::new(String::new());
        html!("form", {
            .style("margin", "1rem 0")
            .event_with_options(&dominator::EventOptions::preventable(), clone!(this, password => move |event: events::Submit| {
                event.prevent_default();
                this.password.set(Some(password.get_cloned()));
                Self::verify(&this);
            }))
            .children(&mut [
                html!("label", { .attr("for", "verify_password").text("El PDF está protegido. Contraseña: ") }),
                html!("input" => HtmlInputElement, {
                    .attr("type", "password")
                    .attr("id", "verify_password")
                    .attr("autocomplete", "off")
                    .with_node!(element => {
                        .event(clone!(password => move |_: events::Input| password.set(element.value())))
                    })
                }),
                html!("button", { .attr("type", "submit").attr("id", "verify_unlock").text("Abrir") }),
            ])
        })
    }

    fn render_result(verification: &Verification) -> Dom {
        let (summary, cards): (String, Vec<Dom>) = match verification {
            Verification::Cades(report) => (
                format!(
                    "Firma CAdES {} con {} firmante(s).",
                    if report.implicit {
                        "implícita"
                    } else {
                        "explícita"
                    },
                    report.signers.len()
                ),
                report
                    .signers
                    .iter()
                    .map(|signer| render_signer(signer, None))
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
                    .map(|signature| render_signer(&signature.signer, Some(signature)))
                    .collect(),
            ),
        };
        let valid = verification.is_valid();

        html!("div", {
            .attr("id", "verify_result")
            .attr("role", "status")
            .style("margin-top", "1rem")
            .children(&mut [
                html!("p", {
                    .attr("id", "verify_summary")
                    .style("font-weight", "600")
                    .style("color", if valid { "var(--ok, #1b7a2f)" } else { "#ba3939" })
                    .text(&format!(
                        "{} {summary}",
                        if valid { "✔ Firmas válidas." } else { "✘ Hay firmas no válidas." }
                    ))
                }),
            ])
            .children(cards)
        })
    }
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
        SignerStatus::Unsupported(what) => format!("No se puede comprobar: {what} no soportado"),
    }
}

fn render_signer(signer: &SignerReport, pdf: Option<&PdfSignatureReport>) -> Dom {
    let mut rows: Vec<(&str, String)> = vec![("Estado", status_text(&signer.status))];
    if let Some(cert) = &signer.certificate {
        rows.push(("Firmante", cert.subject_cn.clone()));
        rows.push(("Emisor", cert.issuer_cn.clone()));
    }
    if let Some(digest) = signer.digest {
        rows.push(("Algoritmo", digest.name().to_string()));
    }
    let time = signer
        .signing_time
        .or_else(|| pdf.and_then(|p| p.claimed_time));
    if let Some(time) = time {
        rows.push(("Fecha declarada", format_date_time(time)));
    }
    if let Some(policy) = &signer.policy {
        rows.push(("Política", policy.clone()));
    }
    if let Some(pdf) = pdf {
        rows.push(("Campo", pdf.field.clone()));
        rows.push(("Tipo", pdf.sub_filter.clone()));
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
        .class(&*CARD_CLASS)
        .attr("data-status", match signer.status {
            SignerStatus::Valid => "valid",
            _ => "invalid",
        })
        .child(html!("dl", {
            .style("display", "grid")
            .style("grid-template-columns", "max-content 1fr")
            .style("gap", "0.15rem 1rem")
            .style("margin", "0")
            .style("word-break", "break-word")
            .children(rows.into_iter().flat_map(|(name, value)| {
                [
                    html!("dt", { .style("color", "var(--muted)").text(name) }),
                    html!("dd", { .style("margin", "0").text(&value) }),
                ]
            }))
        }))
    })
}
