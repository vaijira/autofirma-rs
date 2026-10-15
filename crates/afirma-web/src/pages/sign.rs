use std::rc::Rc;

use afirma_core::{
    cades::{CadesParams, SignatureMode},
    digest::DigestAlgorithm,
    format::{DataKind, SignatureFormat},
    job::{FileAnalysis, Job, JobOutput, KeyEntry},
    policy::PolicyPreset,
};
use dominator::{Dom, clone, events, html, link, with_node};
use futures_signals::{
    map_ref,
    signal::{Mutable, SignalExt},
};
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlSelectElement;

use crate::{
    components::file_picker::{FilePicker, LoadedFile},
    css::{ERROR_CLASS, INFO_TABLE_CLASS, OPTIONS_CLASS},
    router::Route,
    state::{Keys, now},
    utils::{format_size, web},
    worker::WorkerClient,
};

/// File selected for signing together with its analysis.
#[derive(Debug)]
struct Selected {
    file: LoadedFile,
    analysis: FileAnalysis,
}

/// A signature ready to download.
#[derive(Debug)]
struct SignatureResult {
    data: Vec<u8>,
    file_name: String,
}

/// CAdES options, with AutoFirma's defaults.
#[derive(Debug)]
struct Options {
    digest: Mutable<DigestAlgorithm>,
    mode: Mutable<SignatureMode>,
    policy: Mutable<Option<PolicyPreset>>,
}

/// "Firmar" view: pick a file, choose the options and sign it.
#[derive(Debug)]
pub struct SignPage {
    worker: Rc<WorkerClient>,
    keys: Rc<Keys>,
    selected: Mutable<Option<Rc<Selected>>>,
    options: Options,
    signature: Mutable<Option<Rc<SignatureResult>>>,
    busy: Mutable<Option<&'static str>>,
    error: Mutable<Option<String>>,
}

impl SignPage {
    pub fn new(worker: Rc<WorkerClient>, keys: Rc<Keys>) -> Rc<Self> {
        Rc::new(Self {
            worker,
            keys,
            selected: Mutable::new(None),
            options: Options {
                digest: Mutable::new(DigestAlgorithm::Sha512),
                mode: Mutable::new(SignatureMode::Explicit),
                policy: Mutable::new(None),
            },
            signature: Mutable::new(None),
            busy: Mutable::new(None),
            error: Mutable::new(None),
        })
    }

    fn load(this: &Rc<Self>, result: Result<LoadedFile, String>) {
        let file = match result {
            Ok(file) => file,
            Err(err) => {
                this.error.set(Some(err));
                return;
            }
        };
        this.error.set(None);
        this.selected.set(None);
        this.signature.set(None);
        this.busy.set(Some("Analizando…"));
        spawn_local(clone!(this => async move {
            // The worker gets its own copy; the UI keeps the original for signing.
            match this.worker.run(Job::Analyze { data: file.data.clone() }).await {
                Ok(JobOutput::Analysis(analysis)) => {
                    this.selected.set(Some(Rc::new(Selected { file, analysis })));
                }
                Ok(other) => log::error!("Unexpected worker output: {other:?}"),
                Err(err) => this.error.set(Some(err.to_string())),
            }
            this.busy.set(None);
        }));
    }

    fn sign(this: &Rc<Self>) {
        let (Some(selected), Some(key_id)) = (this.selected.get_cloned(), this.keys.selected.get())
        else {
            return;
        };
        let params = CadesParams {
            digest: this.options.digest.get(),
            mode: this.options.mode.get(),
            policy: this
                .options
                .policy
                .get()
                .map(|preset| preset.policy(SignatureFormat::Cades)),
            signing_time: now(),
            content_description: content_description(selected.analysis.kind),
        };

        this.error.set(None);
        this.signature.set(None);
        this.busy.set(Some("Firmando…"));
        spawn_local(clone!(this => async move {
            let job = Job::SignCades { data: selected.file.data.clone(), key_id, params };
            match this.worker.run(job).await {
                Ok(JobOutput::Signature(data)) => {
                    this.signature.set(Some(Rc::new(SignatureResult {
                        data,
                        file_name: format!("{}.csig", selected.file.name),
                    })));
                }
                Ok(other) => log::error!("Unexpected worker output: {other:?}"),
                Err(err) => this.error.set(Some(err.to_string())),
            }
            this.busy.set(None);
        }));
    }

    pub fn render(this: &Rc<Self>) -> Dom {
        let picker = FilePicker::new(
            "sign_file",
            "Seleccionar fichero",
            "*/*",
            clone!(this => move |result| SignPage::load(&this, result)),
        );

        html!("section", {
            .children(&mut [
                html!("h2", { .text("Firmar") }),
                html!("p", { .text("Seleccione el fichero que desea firmar. El fichero no sale de su equipo.") }),
                FilePicker::render(&picker),
            ])
            .child_signal(this.selected.signal_cloned().map(|selected| {
                selected.map(|selected| Self::render_file_info(&selected))
            }))
            .child_signal(this.selected.signal_cloned().map(clone!(this => move |selected| {
                selected.map(|selected| Self::render_sign_form(&this, &selected))
            })))
            .child_signal(this.busy.signal().map(|busy| busy.map(|text| html!("p", { .text(text) }))))
            .child_signal(this.error.signal_cloned().map(|error| {
                error.map(|error| html!("p", {
                    .class(&*ERROR_CLASS)
                    .attr("role", "alert")
                    .text(&error)
                }))
            }))
            .child_signal(this.signature.signal_cloned().map(|signature| {
                signature.map(|signature| Self::render_signature(&signature))
            }))
        })
    }

    fn render_file_info(selected: &Rc<Selected>) -> Dom {
        let analysis = &selected.analysis;
        let row = |name: &str, value: &str, id: &str| {
            html!("tr", {
                .attr("id", id)
                .children(&mut [
                    html!("th", { .attr("scope", "row").style("text-align", "left").style("padding-right", "1rem").text(name) }),
                    html!("td", { .text(value) }),
                ])
            })
        };

        html!("table", {
            .attr("id", "file_info")
            .class(&*INFO_TABLE_CLASS)
            .children(&mut [
                row("Nombre", &selected.file.name, "file_name"),
                row("Tamaño", &format_size(analysis.size), "file_size"),
                row("Tipo", analysis.kind.description(), "file_kind"),
                row("Formato recomendado", analysis.default_format.name(), "file_format"),
                html!("tr", {
                    .attr("id", "file_sha256")
                    .children(&mut [
                        html!("th", { .attr("scope", "row").style("text-align", "left").style("padding-right", "1rem").text("SHA-256") }),
                        html!("td", { .style("font-family", "monospace").text(&analysis.sha256) }),
                    ])
                }),
            ])
        })
    }

    fn render_sign_form(this: &Rc<Self>, selected: &Rc<Selected>) -> Dom {
        let default_format = selected.analysis.default_format;

        html!("div", {
            .children(&mut [
                html!("div", {
                    .class(&*OPTIONS_CLASS)
                    .children(&mut [
                        html!("label", { .attr("for", "sign_format").text("Formato") }),
                        html!("select", {
                            .attr("id", "sign_format")
                            .child(html!("option", { .attr("value", "cades").text("CAdES") }))
                        }),
                        html!("label", { .attr("for", "sign_mode").text("Modo") }),
                        select(
                            "sign_mode",
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
                        html!("label", { .attr("for", "sign_digest").text("Algoritmo") }),
                        select(
                            "sign_digest",
                            &[("sha512", "SHA-512"), ("sha384", "SHA-384"), ("sha256", "SHA-256")],
                            match this.options.digest.get() {
                                DigestAlgorithm::Sha256 => "sha256",
                                DigestAlgorithm::Sha384 => "sha384",
                                _ => "sha512",
                            },
                            clone!(this => move |value| this.options.digest.set(match value.as_str() {
                                "sha256" => DigestAlgorithm::Sha256,
                                "sha384" => DigestAlgorithm::Sha384,
                                _ => DigestAlgorithm::Sha512,
                            })),
                        ),
                        html!("label", { .attr("for", "sign_policy").text("Política de firma") }),
                        select(
                            "sign_policy",
                            &[
                                ("none", "Ninguna (CAdES-BES)"),
                                ("age19", PolicyPreset::Age19.name()),
                                ("age18", PolicyPreset::Age18.name()),
                            ],
                            match this.options.policy.get() {
                                None => "none",
                                Some(PolicyPreset::Age19) => "age19",
                                Some(PolicyPreset::Age18) => "age18",
                            },
                            clone!(this => move |value| this.options.policy.set(match value.as_str() {
                                "age19" => Some(PolicyPreset::Age19),
                                "age18" => Some(PolicyPreset::Age18),
                                _ => None,
                            })),
                        ),
                        html!("span", { .text("Certificado") }),
                        html!("span", {
                            .attr("id", "sign_certificate")
                            .child_signal(this.keys.selected_signal().map(|entry: Option<KeyEntry>| Some(match entry {
                                Some(entry) => html!("span", { .text(&entry.certificate.subject_cn) }),
                                None => html!("span", {
                                    .children(&mut [
                                        html!("span", { .text("Ninguno. ") }),
                                        link!(Route::Certs.hash(), { .text("Importe un certificado") }),
                                    ])
                                }),
                            })))
                        }),
                    ])
                }),
            ])
            .apply_if(default_format != SignatureFormat::Cades, |dom| {
                dom.child(html!("p", {
                    .style("color", "var(--muted)")
                    .text(&format!(
                        "AutoFirma usaría {} para este fichero; ese formato estará disponible en una próxima fase. \
                         Puede firmarlo ya en CAdES.",
                        default_format.name()
                    ))
                }))
            })
            .child(html!("button", {
                .attr("type", "button")
                .attr("id", "sign_button")
                .text("Firmar")
                .attr_signal("disabled", map_ref! {
                    let key = this.keys.selected.signal(),
                    let busy = this.busy.signal() => (key.is_none() || busy.is_some()).then_some("")
                })
                .event(clone!(this => move |_: events::Click| Self::sign(&this)))
            }))
        })
    }

    fn render_signature(signature: &Rc<SignatureResult>) -> Dom {
        html!("div", {
            .attr("id", "signature_result")
            .attr("role", "status")
            .style("margin-top", "1rem")
            .children(&mut [
                html!("p", {
                    .text(&format!("Firma CAdES generada ({}).", format_size(signature.data.len())))
                }),
                html!("button", {
                    .attr("type", "button")
                    .attr("id", "download_signature")
                    .text(&format!("Descargar {}", signature.file_name))
                    .event(clone!(signature => move |_: events::Click| {
                        if let Err(err) = web::download(&signature.data, &signature.file_name, "application/pkcs7-signature") {
                            log::error!("{err}");
                        }
                    }))
                }),
            ])
        })
    }
}

/// `contentHint` description, as AutoFirma writes it.
fn content_description(kind: DataKind) -> Option<String> {
    match kind {
        DataKind::Binary => None,
        kind => Some(kind.description().to_string()),
    }
}

fn select(
    id: &str,
    options: &[(&str, &str)],
    current: &str,
    on_change: impl Fn(String) + 'static,
) -> Dom {
    html!("select" => HtmlSelectElement, {
        .attr("id", id)
        .children(options.iter().map(|(value, label)| {
            html!("option", {
                .attr("value", value)
                .prop("selected", *value == current)
                .text(label)
            })
        }))
        .with_node!(element => {
            .event(move |_: events::Change| on_change(element.value()))
        })
    })
}
