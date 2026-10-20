use std::rc::Rc;

use afirma_core::{
    batch::{BatchResult, BatchStep},
    cades::SignatureMode,
    digest::DigestAlgorithm,
    format::SignatureFormat,
    job::{Job, JobOutput, KeyEntry},
    massive::{MassiveFile, MassiveOperation, MassiveParams, MassiveResult},
    multisign::CounterSignTarget,
    policy::PolicyPreset,
    xades::XadesFormat,
};
use anyhow::anyhow;
use dominator::{Dom, clone, events, html, link, with_node};
use futures_signals::{
    map_ref,
    signal::{Mutable, SignalExt},
    signal_vec::{MutableVec, SignalVecExt},
};
use wasm_bindgen_futures::spawn_local;
use web_sys::{HtmlInputElement, HtmlTextAreaElement};

use super::sign::{select, text_input};
use crate::{
    components::file_picker::{FilePicker, LoadedFile, MultiFilePicker},
    css::{ERROR_CLASS, INFO_TABLE_CLASS, OPTIONS_CLASS},
    router::Route,
    state::{Keys, now, utc_offset_minutes},
    utils::{format_size, http, web},
    worker::WorkerClient,
};

/// Options of the multi-file signature, with AutoFirma's defaults.
#[derive(Debug)]
struct MassiveOptions {
    operation: Mutable<MassiveOperation>,
    /// `None` for the default format of each file.
    format: Mutable<Option<SignatureFormat>>,
    digest: Mutable<DigestAlgorithm>,
    policy: Mutable<Option<PolicyPreset>>,
    mode: Mutable<SignatureMode>,
    xades_format: Mutable<XadesFormat>,
    reason: Mutable<String>,
    location: Mutable<String>,
}

/// State of one of the two sections of the page.
#[derive(Debug, Default)]
struct Progress {
    busy: Mutable<Option<&'static str>>,
    error: Mutable<Option<String>>,
}

impl Progress {
    fn render(&self) -> Vec<Dom> {
        vec![
            html!("p", {
                .attr("role", "status")
                .visible_signal(self.busy.signal().map(|busy| busy.is_some()))
                .text_signal(self.busy.signal().map(|busy| busy.unwrap_or_default()))
            }),
            html!("div", {
                .child_signal(self.error.signal_cloned().map(|error| {
                    error.map(|error| html!("p", { .class(&*ERROR_CLASS).attr("role", "alert").text(&error) }))
                }))
            }),
        ]
    }
}

/// "Firma por lotes" view: many local files at once (into a ZIP file), or a
/// JSON batch of a signature service.
#[derive(Debug)]
pub struct BatchPage {
    worker: Rc<WorkerClient>,
    keys: Rc<Keys>,
    files: MutableVec<Rc<LoadedFile>>,
    options: MassiveOptions,
    massive: Progress,
    massive_result: Mutable<Option<Rc<MassiveResult>>>,
    /// JSON batch, as given (JSON or Base64).
    batch: Mutable<String>,
    presign_url: Mutable<String>,
    postsign_url: Mutable<String>,
    json: Progress,
    json_results: Mutable<Option<Rc<Vec<BatchResult>>>>,
}

impl BatchPage {
    pub fn new(worker: Rc<WorkerClient>, keys: Rc<Keys>) -> Rc<Self> {
        Rc::new(Self {
            worker,
            keys,
            files: MutableVec::new(),
            options: MassiveOptions {
                operation: Mutable::new(MassiveOperation::Sign),
                format: Mutable::new(None),
                digest: Mutable::new(DigestAlgorithm::Sha512),
                policy: Mutable::new(None),
                mode: Mutable::new(SignatureMode::Explicit),
                xades_format: Mutable::new(XadesFormat::Enveloping),
                reason: Mutable::new(String::new()),
                location: Mutable::new(String::new()),
            },
            massive: Progress::default(),
            massive_result: Mutable::new(None),
            batch: Mutable::new(String::new()),
            presign_url: Mutable::new(String::new()),
            postsign_url: Mutable::new(String::new()),
            json: Progress::default(),
            json_results: Mutable::new(None),
        })
    }

    fn massive_params(&self) -> MassiveParams {
        let options = &self.options;
        let text = |value: &Mutable<String>| {
            let value = value.get_cloned().trim().to_string();
            (!value.is_empty()).then_some(value)
        };
        MassiveParams {
            operation: options.operation.get(),
            format: options.format.get(),
            digest: options.digest.get(),
            policy: options.policy.get(),
            signing_time: now(),
            utc_offset_minutes: utc_offset_minutes(),
            cades_mode: options.mode.get(),
            xades_format: options.xades_format.get(),
            reason: text(&options.reason),
            location: text(&options.location),
        }
    }

    fn sign_files(this: &Rc<Self>) {
        let Some(entry) = this.keys.selected_entry() else {
            return;
        };
        let files: Vec<MassiveFile> = this
            .files
            .lock_ref()
            .iter()
            .map(|file| MassiveFile {
                name: file.name.clone(),
                data: file.data.clone(),
            })
            .collect();
        if files.is_empty() {
            return;
        }
        let job = Job::SignMassive {
            files,
            key_id: entry.id,
            params: Box::new(this.massive_params()),
        };
        this.massive_result.set(None);
        this.massive.error.set(None);
        this.massive.busy.set(Some("Firmando los ficheros…"));
        spawn_local(clone!(this => async move {
            match this.worker.run(job).await {
                Ok(JobOutput::Massive(result)) => this.massive_result.set(Some(Rc::new(result))),
                Ok(other) => log::error!("Unexpected worker output: {other:?}"),
                Err(err) => this.massive.error.set(Some(err.to_string())),
            }
            this.massive.busy.set(None);
        }));
    }

    fn sign_json_batch(this: &Rc<Self>) {
        let Some(entry) = this.keys.selected_entry() else {
            return;
        };
        this.json_results.set(None);
        this.json.error.set(None);
        spawn_local(clone!(this => async move {
            match Self::run_json_batch(&this, &entry).await {
                Ok(results) => this.json_results.set(Some(Rc::new(results))),
                Err(err) => this.json.error.set(Some(err.to_string())),
            }
            this.json.busy.set(None);
        }));
    }

    /// The JSON batch protocol: presign on the server, sign the pre-signatures
    /// here (in the worker), postsign on the server.
    async fn run_json_batch(this: &Rc<Self>, entry: &KeyEntry) -> anyhow::Result<Vec<BatchResult>> {
        let presign_url = this.presign_url.get_cloned().trim().to_string();
        let postsign_url = this.postsign_url.get_cloned().trim().to_string();
        if presign_url.is_empty() || postsign_url.is_empty() {
            return Err(anyhow!(
                "Indique las direcciones de los servicios de prefirma y postfirma del lote"
            ));
        }
        this.json.busy.set(Some("Preparando el lote…"));
        let (batch, body) = match this
            .worker
            .run(Job::BatchPresign {
                batch: this.batch.get_cloned().into_bytes(),
                key_id: entry.id,
            })
            .await?
        {
            JobOutput::BatchPresign { batch, body } => (batch, body),
            other => return Err(anyhow!("Respuesta inesperada del worker: {other:?}")),
        };
        this.json.busy.set(Some("Prefirma en el servidor…"));
        let presign_response = http::post_form(&presign_url, &body).await?;
        this.json.busy.set(Some("Firmando…"));
        let step = match this
            .worker
            .run(Job::SignBatch {
                batch,
                presign_response,
                key_id: entry.id,
            })
            .await?
        {
            JobOutput::Batch(step) => step,
            other => return Err(anyhow!("Respuesta inesperada del worker: {other:?}")),
        };
        let body = match step {
            BatchStep::Done(results) => return Ok(results),
            BatchStep::Post(body) => body,
        };
        this.json.busy.set(Some("Postfirma en el servidor…"));
        let response = http::post_form(&postsign_url, &body).await?;
        match this.worker.run(Job::BatchResults { response }).await? {
            JobOutput::BatchResults(results) => Ok(results),
            other => Err(anyhow!("Respuesta inesperada del worker: {other:?}")),
        }
    }

    pub fn render(this: &Rc<Self>) -> Dom {
        html!("section", {
            .children(&mut [
                html!("h2", { .text("Firma por lotes") }),
                html!("p", {
                    .children(&mut [
                        html!("span", { .text("Certificado: ") }),
                        html!("span", {
                            .attr("id", "batch_certificate")
                            .child_signal(this.keys.selected_signal().map(|entry: Option<KeyEntry>| Some(match entry {
                                Some(entry) => html!("span", { .text(&entry.certificate.subject_cn) }),
                                None => html!("span", {
                                    .children(&mut [
                                        html!("span", { .text("ninguno. ") }),
                                        link!(Route::Certs.hash(), { .text("Importe un certificado") }),
                                    ])
                                }),
                            })))
                        }),
                    ])
                }),
                Self::render_massive(this),
                Self::render_json(this),
            ])
        })
    }

    fn render_massive(this: &Rc<Self>) -> Dom {
        let picker = MultiFilePicker::new(
            "batch_files",
            "Añadir ficheros",
            clone!(this => move |result| match result {
                Ok(files) => {
                    this.massive.error.set(None);
                    this.massive_result.set(None);
                    this.files.lock_mut().extend(files.into_iter().map(Rc::new));
                }
                Err(err) => this.massive.error.set(Some(err)),
            }),
        );
        let options = &this.options;

        html!("section", {
            .attr("id", "batch_massive")
            .children(&mut [
                html!("h3", { .text("Varios ficheros") }),
                html!("p", {
                    .text("Firme, cofirme o contrafirme varios ficheros a la vez con el mismo certificado. \
                           Los resultados se descargan en un fichero ZIP; los ficheros no salen de su equipo.")
                }),
                html!("div", {
                    .style("display", "flex")
                    .style("gap", "0.5rem")
                    .style("align-items", "center")
                    .child(MultiFilePicker::render(&picker))
                    .child(html!("button", {
                        .attr("type", "button")
                        .attr("id", "batch_clear")
                        .text("Quitar todos")
                        .attr_signal("disabled", this.files.signal_vec_cloned().len().map(|n| (n == 0).then_some("")))
                        .event(clone!(this => move |_: events::Click| {
                            this.files.lock_mut().clear();
                            this.massive_result.set(None);
                        }))
                    }))
                }),
                html!("ul", {
                    .attr("id", "batch_file_list")
                    .children_signal_vec(this.files.signal_vec_cloned().map(|file| html!("li", {
                        .text(&format!("{} ({})", file.name, format_size(file.data.len())))
                    })))
                }),
                html!("div", {
                    .class(&*OPTIONS_CLASS)
                    .children(&mut [
                        html!("label", { .attr("for", "batch_operation").text("Operación") }),
                        select(
                            "batch_operation",
                            &[
                                ("sign", "Firmar"),
                                ("cosign", "Cofirmar firmas"),
                                ("leafs", "Contrafirmar las últimas firmas"),
                                ("tree", "Contrafirmar todas las firmas"),
                            ],
                            "sign",
                            clone!(this => move |value| this.options.operation.set(match value.as_str() {
                                "cosign" => MassiveOperation::Cosign,
                                "leafs" => MassiveOperation::Countersign(CounterSignTarget::Leafs),
                                "tree" => MassiveOperation::Countersign(CounterSignTarget::Tree),
                                _ => MassiveOperation::Sign,
                            })),
                        ),
                    ])
                    .child_signal(options.operation.signal().map(clone!(this => move |operation| {
                        (operation == MassiveOperation::Sign).then(|| html!("div", {
                            .style("display", "contents")
                            .children(&mut [
                                html!("label", { .attr("for", "batch_format").text("Formato") }),
                                select(
                                    "batch_format",
                                    &[
                                        ("auto", "El adecuado para cada fichero (PAdES para PDF, XAdES para XML...)"),
                                        ("cades", "CAdES"),
                                        ("xades", "XAdES"),
                                        ("pades", "PAdES (solo PDF)"),
                                    ],
                                    match this.options.format.get() {
                                        Some(SignatureFormat::Cades) => "cades",
                                        Some(SignatureFormat::Xades) => "xades",
                                        Some(SignatureFormat::Pades) => "pades",
                                        _ => "auto",
                                    },
                                    clone!(this => move |value| this.options.format.set(match value.as_str() {
                                        "cades" => Some(SignatureFormat::Cades),
                                        "xades" => Some(SignatureFormat::Xades),
                                        "pades" => Some(SignatureFormat::Pades),
                                        _ => None,
                                    })),
                                ),
                                html!("label", { .attr("for", "batch_mode").text("CAdES") }),
                                select(
                                    "batch_mode",
                                    &[
                                        ("explicit", "Explícita (sin incluir los datos)"),
                                        ("implicit", "Implícita (incluye los datos)"),
                                    ],
                                    match this.options.mode.get() {
                                        SignatureMode::Explicit => "explicit",
                                        SignatureMode::Implicit => "implicit",
                                    },
                                    clone!(this => move |value| this.options.mode.set(match value.as_str() {
                                        "implicit" => SignatureMode::Implicit,
                                        _ => SignatureMode::Explicit,
                                    })),
                                ),
                                html!("label", { .attr("for", "batch_xades_format").text("XAdES") }),
                                select(
                                    "batch_xades_format",
                                    &[
                                        ("enveloping", "Envolvente"),
                                        ("enveloped", "Envuelta (ficheros XML; los demás, envolvente)"),
                                        ("detached", "Separada"),
                                    ],
                                    match this.options.xades_format.get() {
                                        XadesFormat::Enveloping => "enveloping",
                                        XadesFormat::Enveloped => "enveloped",
                                        XadesFormat::Detached => "detached",
                                    },
                                    clone!(this => move |value| this.options.xades_format.set(match value.as_str() {
                                        "enveloped" => XadesFormat::Enveloped,
                                        "detached" => XadesFormat::Detached,
                                        _ => XadesFormat::Enveloping,
                                    })),
                                ),
                                html!("label", { .attr("for", "batch_reason").text("Motivo (PDF)") }),
                                text_input("batch_reason", &this.options.reason),
                            ])
                        }))
                    })))
                    .children(&mut [
                        html!("label", { .attr("for", "batch_digest").text("Algoritmo") }),
                        select(
                            "batch_digest",
                            &[("sha512", "SHA-512"), ("sha384", "SHA-384"), ("sha256", "SHA-256")],
                            "sha512",
                            clone!(this => move |value| this.options.digest.set(match value.as_str() {
                                "sha256" => DigestAlgorithm::Sha256,
                                "sha384" => DigestAlgorithm::Sha384,
                                _ => DigestAlgorithm::Sha512,
                            })),
                        ),
                        html!("label", { .attr("for", "batch_policy").text("Política de firma") }),
                        select(
                            "batch_policy",
                            &[
                                ("none", "Ninguna (BES)"),
                                ("age19", PolicyPreset::Age19.name()),
                                ("age18", PolicyPreset::Age18.name()),
                            ],
                            "none",
                            clone!(this => move |value| this.options.policy.set(match value.as_str() {
                                "age19" => Some(PolicyPreset::Age19),
                                "age18" => Some(PolicyPreset::Age18),
                                _ => None,
                            })),
                        ),
                        html!("label", { .attr("for", "batch_location").text("Lugar") }),
                        text_input("batch_location", &this.options.location),
                    ])
                }),
                html!("button", {
                    .attr("type", "button")
                    .attr("id", "batch_sign_button")
                    .text_signal(this.files.signal_vec_cloned().len().map(|n| match n {
                        0 => "Firmar ficheros".to_string(),
                        1 => "Firmar 1 fichero".to_string(),
                        n => format!("Firmar {n} ficheros"),
                    }))
                    .attr_signal("disabled", map_ref! {
                        let key = this.keys.selected.signal(),
                        let busy = this.massive.busy.signal(),
                        let count = this.files.signal_vec_cloned().len() => {
                            (key.is_none() || busy.is_some() || *count == 0).then_some("")
                        }
                    })
                    .event(clone!(this => move |_: events::Click| Self::sign_files(&this)))
                }),
            ])
            .children(&mut this.massive.render())
            .child_signal(this.massive_result.signal_cloned().map(|result| result.map(|result| Self::render_massive_result(&result))))
        })
    }

    fn render_massive_result(result: &Rc<MassiveResult>) -> Dom {
        let signed = result.signed();
        html!("div", {
            .attr("id", "batch_result")
            .attr("role", "status")
            .children(&mut [
                html!("p", {
                    .attr("id", "batch_summary")
                    .text(&format!("{signed} de {} fichero(s) firmados.", result.results.len()))
                }),
                html!("table", {
                    .class(&*INFO_TABLE_CLASS)
                    .children(result.results.iter().map(|file| html!("tr", {
                        .attr("data-status", if file.result.is_ok() { "ok" } else { "error" })
                        .children(&mut [
                            html!("th", {
                                .attr("scope", "row")
                                .style("text-align", "left")
                                .style("padding-right", "1rem")
                                .text(&file.name)
                            }),
                            html!("td", {
                                .text(&match &file.result {
                                    Ok(name) => format!("✔ {name}"),
                                    Err(err) => format!("✘ {err}"),
                                })
                            }),
                        ])
                    })))
                }),
            ])
            .apply_if(signed > 0, |dom| dom.child(html!("button", {
                .attr("type", "button")
                .attr("id", "batch_download")
                .text("Descargar firmas.zip")
                .event(clone!(result => move |_: events::Click| {
                    if let Err(err) = web::download(&result.zip, "firmas.zip", "application/zip") {
                        log::error!("{err}");
                    }
                }))
            })))
        })
    }

    fn render_json(this: &Rc<Self>) -> Dom {
        let picker = FilePicker::new(
            "batch_json_file",
            "Cargar lote desde un fichero",
            "application/json,.json,.txt",
            clone!(this => move |result| match result {
                Ok(file) => {
                    this.json.error.set(None);
                    this.json_results.set(None);
                    this.batch.set(String::from_utf8_lossy(&file.data).into_owned());
                }
                Err(err) => this.json.error.set(Some(err)),
            }),
        );
        let url_input = |id: &str, value: &Mutable<String>, placeholder: &str| {
            html!("input" => HtmlInputElement, {
                .attr("type", "url")
                .attr("id", id)
                .attr("placeholder", placeholder)
                .prop("value", value.get_cloned())
                .with_node!(element => {
                    .event(clone!(value => move |_: events::Input| value.set(element.value())))
                })
            })
        };

        html!("section", {
            .attr("id", "batch_json")
            .children(&mut [
                html!("h3", { .text("Lote de un servicio de firma") }),
                html!("p", {
                    .text("Firme un lote JSON de un servicio de firma por lotes de AutoFirma. Los documentos \
                           están en el servidor: solo se firman aquí sus huellas, y la clave privada no sale de \
                           este navegador. El servidor debe admitir peticiones desde esta página (CORS).")
                }),
                FilePicker::render(&picker),
                html!("div", {
                    .class(&*OPTIONS_CLASS)
                    .children(&mut [
                        html!("label", { .attr("for", "batch_json_text").text("Lote (JSON o Base64)") }),
                        html!("textarea" => HtmlTextAreaElement, {
                            .attr("id", "batch_json_text")
                            .attr("rows", "5")
                            .attr("spellcheck", "false")
                            .style("font-family", "monospace")
                            .attr("placeholder", r#"{"algorithm":"SHA512withRSA","format":"CAdES","suboperation":"sign","singlesigns":[...]}"#)
                            .prop_signal("value", this.batch.signal_cloned())
                            .with_node!(element => {
                                .event(clone!(this => move |_: events::Input| this.batch.set(element.value())))
                            })
                        }),
                        html!("label", { .attr("for", "batch_presign_url").text("Servicio de prefirma") }),
                        url_input("batch_presign_url", &this.presign_url, "https://servidor/afirma-server-triphase-signer/presign"),
                        html!("label", { .attr("for", "batch_postsign_url").text("Servicio de postfirma") }),
                        url_input("batch_postsign_url", &this.postsign_url, "https://servidor/afirma-server-triphase-signer/postsign"),
                    ])
                }),
                html!("button", {
                    .attr("type", "button")
                    .attr("id", "batch_json_button")
                    .text("Firmar lote")
                    .attr_signal("disabled", map_ref! {
                        let key = this.keys.selected.signal(),
                        let busy = this.json.busy.signal(),
                        let empty = this.batch.signal_ref(|batch| batch.trim().is_empty()) => {
                            (key.is_none() || busy.is_some() || *empty).then_some("")
                        }
                    })
                    .event(clone!(this => move |_: events::Click| Self::sign_json_batch(&this)))
                }),
            ])
            .children(&mut this.json.render())
            .child_signal(this.json_results.signal_cloned().map(|results| results.map(|results| Self::render_json_results(&results))))
        })
    }

    fn render_json_results(results: &[BatchResult]) -> Dom {
        let done = results.iter().filter(|r| r.is_ok()).count();
        html!("div", {
            .attr("id", "batch_json_result")
            .attr("role", "status")
            .children(&mut [
                html!("p", {
                    .attr("id", "batch_json_summary")
                    .text(&format!("{done} de {} firma(s) del lote realizadas.", results.len()))
                }),
                html!("table", {
                    .class(&*INFO_TABLE_CLASS)
                    .children(results.iter().map(|result| html!("tr", {
                        .attr("data-status", if result.is_ok() { "ok" } else { "error" })
                        .children(&mut [
                            html!("th", {
                                .attr("scope", "row")
                                .style("text-align", "left")
                                .style("padding-right", "1rem")
                                .text(&result.id)
                            }),
                            html!("td", {
                                .text(&match &result.description {
                                    Some(description) => format!("{}: {description}", result.text()),
                                    None => result.text().to_string(),
                                })
                            }),
                        ])
                    })))
                }),
            ])
        })
    }
}
