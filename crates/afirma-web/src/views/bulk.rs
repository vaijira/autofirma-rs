use std::rc::Rc;

use afirma_core::{
    cades::SignatureMode,
    digest::DigestAlgorithm,
    format::SignatureFormat,
    job::{Job, JobOutput},
    massive::{MassiveFile, MassiveOperation, MassiveParams, MassiveResult},
    multisign::CounterSignTarget,
    policy::PolicyPreset,
    xades::XadesFormat,
};
use dominator::{Dom, clone, events, html};
use futures_signals::{
    map_ref,
    signal::{Mutable, SignalExt},
    signal_vec::{MutableVec, SignalVecExt},
};
use wasm_bindgen_futures::spawn_local;

use crate::{
    app::App,
    components::{
        file_picker::{LoadedFile, file_input, open_file_input},
        form::{choice, differs, field, group, hint, text_input},
    },
    css::{
        ACTIONS_CLASS, CARD_CLASS, CARD_TITLE_CLASS, CHIP_CLASS, CHIP_MODIFIED_CLASS, CHIPS_CLASS,
        DISCLOSURE_CLASS, ELLIPSIS_CLASS, ERROR_CLASS, MUTED_CLASS, STATUS_CLASS, VERDICT_CLASS,
    },
    state::{now, utc_offset_minutes},
    utils::{format_size, web},
};

/// Many files at once with the same certificate, into a ZIP file.
#[derive(Debug)]
pub struct Bulk {
    app: Rc<App>,
    files: MutableVec<Rc<LoadedFile>>,
    operation: Mutable<MassiveOperation>,
    /// `None` for the default format of each file.
    format: Mutable<Option<SignatureFormat>>,
    reason: Mutable<String>,
    busy: Mutable<Option<&'static str>>,
    error: Mutable<Option<String>>,
    result: Mutable<Option<Rc<MassiveResult>>>,
}

impl Bulk {
    pub fn new(app: &Rc<App>, files: Vec<LoadedFile>) -> Rc<Self> {
        Rc::new(Self {
            app: app.clone(),
            files: MutableVec::new_with_values(files.into_iter().map(Rc::new).collect()),
            operation: Mutable::new(MassiveOperation::Sign),
            format: Mutable::new(None),
            reason: Mutable::new(String::new()),
            busy: Mutable::new(None),
            error: Mutable::new(None),
            result: Mutable::new(None),
        })
    }

    fn params(&self) -> MassiveParams {
        let prefs = &self.app.prefs;
        let text = |value: &Mutable<String>| {
            let value = value.get_cloned().trim().to_string();
            (!value.is_empty()).then_some(value)
        };
        MassiveParams {
            operation: self.operation.get(),
            format: self.format.get(),
            digest: prefs.digest.get(),
            policy: prefs.policy.get(),
            signing_time: now(),
            utc_offset_minutes: utc_offset_minutes(),
            cades_mode: prefs.cades_mode.get(),
            xades_format: prefs.xades_format.get(),
            reason: text(&self.reason),
            location: text(&prefs.location),
        }
    }

    fn sign(this: &Rc<Self>) {
        let Some(entry) = this.app.keys.selected_entry() else {
            this.app.certificates.show();
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
            params: Box::new(this.params()),
        };
        this.result.set(None);
        this.error.set(None);
        this.busy.set(Some("Firmando los ficheros…"));
        spawn_local(clone!(this => async move {
            match this.app.worker.run(job).await {
                Ok(JobOutput::Massive(result)) => this.result.set(Some(Rc::new(result))),
                Ok(other) => log::error!("Unexpected worker output: {other:?}"),
                Err(err) => this.error.set(Some(err.to_string())),
            }
            this.busy.set(None);
        }));
    }

    pub fn render(this: &Rc<Self>) -> Dom {
        html!("section", {
            .class(&*CARD_CLASS)
            .attr("id", "batch_massive")
            .attr("aria-labelledby", "batch_title")
            .child_signal(this.result.signal_cloned().map(clone!(this => move |result| Some(match result {
                Some(result) => Self::render_result(&this, &result),
                None => Self::render_form(&this),
            }))))
        })
    }

    fn render_form(this: &Rc<Self>) -> Dom {
        html!("div", {
            .children(&mut [
                html!("h2", {
                    .attr("id", "batch_title")
                    .class(&*CARD_TITLE_CLASS)
                    .text_signal(this.files.signal_vec_cloned().len().map(|n| format!("Firmar {n} ficheros a la vez")))
                }),
                html!("ul", {
                    .attr("id", "batch_file_list")
                    .style("list-style", "none")
                    .style("padding", "0")
                    .style("margin", "0 0 1rem")
                    .style("display", "grid")
                    .style("gap", "0.35rem")
                    .children_signal_vec(this.files.signal_vec_cloned().map(clone!(this => move |file| html!("li", {
                        .style("display", "flex")
                        .style("gap", "0.75rem")
                        .style("align-items", "center")
                        .children(&mut [
                            html!("span", { .class(&*ELLIPSIS_CLASS).style("flex", "1").text(&file.name) }),
                            html!("span", { .class(&*MUTED_CLASS).text(&format_size(file.data.len())) }),
                            html!("button", {
                                .attr("type", "button")
                                .attr("aria-label", &format!("Quitar {}", file.name))
                                .class("link")
                                .style("text-decoration-line", "none")
                                .text("×")
                                .event(clone!(this, file => move |_: events::Click| {
                                    this.files.lock_mut().retain(|f| !Rc::ptr_eq(f, &file));
                                    if this.files.lock_ref().is_empty() {
                                        App::reset(&this.app);
                                    }
                                }))
                            }),
                        ])
                    }))))
                }),
                html!("div", {
                    .style("margin-bottom", "1rem")
                    .children(&mut [
                        html!("button", {
                            .attr("type", "button")
                            .text("Añadir más ficheros")
                            .event(|_: events::Click| open_file_input("batch_files"))
                        }),
                        file_input("batch_files", "*/*", true, clone!(this => move |result| match result {
                            Ok(files) => this.files.lock_mut().extend(files.into_iter().map(Rc::new)),
                            Err(err) => this.error.set(Some(err)),
                        })),
                    ])
                }),
                html!("p", { .class(&*MUTED_CLASS).style("margin-bottom", "0.4rem").text("Se firmará así:") }),
                Self::render_summary(this),
                Self::render_customize(this),
            ])
            .child_signal(this.busy.signal().map(|busy| {
                busy.map(|text| html!("p", { .class(&*STATUS_CLASS).attr("role", "status").text(text) }))
            }))
            .child_signal(this.error.signal_cloned().map(|error| {
                error.map(|error| html!("p", { .class(&*ERROR_CLASS).attr("role", "alert").text(&error) }))
            }))
            .child(html!("div", {
                .class(&*ACTIONS_CLASS)
                .child(html!("button", {
                    .attr("type", "button")
                    .attr("id", "batch_sign_button")
                    .class("primary")
                    .text_signal(map_ref! {
                        let key = this.app.keys.selected.signal(),
                        let count = this.files.signal_vec_cloned().len() => match (key, count) {
                            (None, _) => "Elegir certificado y firmar".to_string(),
                            (_, 1) => "Firmar 1 fichero".to_string(),
                            (_, n) => format!("Firmar {n} ficheros"),
                        }
                    })
                    .attr_signal("disabled", map_ref! {
                        let busy = this.busy.signal(),
                        let count = this.files.signal_vec_cloned().len() => {
                            (busy.is_some() || *count == 0).then_some("")
                        }
                    })
                    .event(clone!(this => move |_: events::Click| Self::sign(&this)))
                }))
            }))
        })
    }

    fn render_summary(this: &Rc<Self>) -> Dom {
        let prefs = &this.app.prefs;
        let chip = |text: &str, modified: bool| {
            html!("li", {
                .class(&*CHIP_CLASS)
                .apply_if(modified, |dom| dom.class(&*CHIP_MODIFIED_CLASS))
                .text(text)
            })
        };
        html!("ul", {
            .attr("id", "batch_summary_chips")
            .class(&*CHIPS_CLASS)
            .child_signal(map_ref! {
                let operation = this.operation.signal(),
                let format = this.format.signal() => {
                    Some(chip(&match (operation, format) {
                        (MassiveOperation::Sign, None) => "Cada fichero en su formato (PAdES para PDF, XAdES para XML…)".to_string(),
                        (MassiveOperation::Sign, Some(format)) => format!("Todos en {}", format.name()),
                        (MassiveOperation::Cosign, _) => "Cofirma de cada firma".to_string(),
                        (MassiveOperation::Countersign(CounterSignTarget::Leafs), _) => "Contrafirma de las últimas firmas".to_string(),
                        (MassiveOperation::Countersign(CounterSignTarget::Tree), _) => "Contrafirma de todas las firmas".to_string(),
                    }, *operation != MassiveOperation::Sign || format.is_some()))
                }
            })
            .child_signal(prefs.digest.signal().map(move |digest| {
                Some(chip(digest.name(), digest != DigestAlgorithm::Sha512))
            }))
            .child_signal(prefs.policy.signal().map(move |policy| Some(match policy {
                None => chip("Sin política de firma", false),
                Some(PolicyPreset::Age19) => chip("Política AGE v1.9", true),
                Some(PolicyPreset::Age18) => chip("Política AGE v1.8", true),
            })))
            .child(chip("Resultado en firmas.zip", false))
        })
    }

    fn render_customize(this: &Rc<Self>) -> Dom {
        let prefs = &this.app.prefs;
        html!("details", {
            .attr("id", "batch_customize")
            .class(&*DISCLOSURE_CLASS)
            .child(html!("summary", { .style("font-weight", "600").text("Personalizar") }))
            .child(group("Tipo de firma", &mut {
                let mut rows: Vec<Dom> = Vec::new();
                rows.extend(field(
                    "batch_operation",
                    "Operación",
                    differs(&this.operation, MassiveOperation::Sign),
                    choice("batch_operation", &this.operation, &[
                        (MassiveOperation::Sign, "sign", "Firmar"),
                        (MassiveOperation::Cosign, "cosign", "Cofirmar firmas"),
                        (MassiveOperation::Countersign(CounterSignTarget::Leafs), "leafs", "Contrafirmar las últimas firmas"),
                        (MassiveOperation::Countersign(CounterSignTarget::Tree), "tree", "Contrafirmar todas las firmas"),
                    ]),
                ));
                rows.push(hint("Cofirmar un PDF o un documento ODF u OOXML firmado añade otra firma."));
                rows
            }))
            .child_signal(this.operation.signal().map(clone!(this => move |operation| {
                (operation == MassiveOperation::Sign).then(|| {
                    let prefs = &this.app.prefs;
                    let mut rows: Vec<Dom> = Vec::new();
                    rows.extend(field(
                        "batch_format",
                        "Formato",
                        differs(&this.format, None),
                        choice("batch_format", &this.format, &[
                            (None, "auto", "El de cada fichero (PAdES para PDF, XAdES para XML…)"),
                            (Some(SignatureFormat::Cades), "cades", "CAdES"),
                            (Some(SignatureFormat::Xades), "xades", "XAdES"),
                            (Some(SignatureFormat::Pades), "pades", "PAdES (solo PDF)"),
                        ]),
                    ));
                    rows.extend(field(
                        "batch_mode",
                        "CAdES",
                        prefs.cades_mode.modified_signal(),
                        choice("batch_mode", &prefs.cades_mode, &[
                            (SignatureMode::Explicit, "explicit", "Datos fuera de la firma (explícita)"),
                            (SignatureMode::Implicit, "implicit", "Datos dentro de la firma (implícita)"),
                        ]),
                    ));
                    rows.extend(field(
                        "batch_xades_format",
                        "XAdES",
                        prefs.xades_format.modified_signal(),
                        choice("batch_xades_format", &prefs.xades_format, &[
                            (XadesFormat::Enveloping, "enveloping", "Envolvente"),
                            (XadesFormat::Enveloped, "enveloped", "Envuelta (ficheros XML; los demás, envolvente)"),
                            (XadesFormat::Detached, "detached", "Separada"),
                        ]),
                    ));
                    rows.extend(field(
                        "batch_reason",
                        "Motivo (PDF)",
                        this.reason.signal_ref(|reason| !reason.is_empty()),
                        text_input("batch_reason", &this.reason, "Opcional"),
                    ));
                    group("Formato", &mut rows)
                })
            })))
            .child(group("General", &mut {
                let mut rows: Vec<Dom> = Vec::new();
                rows.extend(field(
                    "batch_digest",
                    "Algoritmo",
                    prefs.digest.modified_signal(),
                    choice("batch_digest", &prefs.digest, &[
                        (DigestAlgorithm::Sha512, "sha512", "SHA-512 (recomendado)"),
                        (DigestAlgorithm::Sha384, "sha384", "SHA-384"),
                        (DigestAlgorithm::Sha256, "sha256", "SHA-256"),
                    ]),
                ));
                rows.extend(field(
                    "batch_policy",
                    "Política de firma",
                    prefs.policy.modified_signal(),
                    choice("batch_policy", &prefs.policy, &[
                        (None, "none", "Ninguna (firma básica, BES)"),
                        (Some(PolicyPreset::Age19), "age19", PolicyPreset::Age19.name()),
                        (Some(PolicyPreset::Age18), "age18", PolicyPreset::Age18.name()),
                    ]),
                ));
                rows.extend(field(
                    "batch_location",
                    "Lugar",
                    prefs.location.modified_signal(),
                    text_input("batch_location", &prefs.location, "Opcional, p. ej. Madrid"),
                ));
                rows
            }))
        })
    }

    fn render_result(this: &Rc<Self>, result: &Rc<MassiveResult>) -> Dom {
        let signed = result.signed();
        let total = result.results.len();
        let all = signed == total;
        html!("div", {
            .attr("id", "batch_result")
            .attr("role", "status")
            .children(&mut [
                html!("h2", { .attr("id", "batch_title").class(&*CARD_TITLE_CLASS).text("Firmas listas") }),
                html!("p", {
                    .attr("id", "batch_summary")
                    .class(&*VERDICT_CLASS)
                    .style("color", if all { "var(--ok)" } else { "var(--danger)" })
                    .style("background", if all { "var(--ok-soft)" } else { "var(--danger-soft)" })
                    .text(&format!("{signed} de {total} fichero(s) firmados."))
                }),
                html!("ul", {
                    .style("list-style", "none")
                    .style("padding", "0")
                    .style("margin", "0.75rem 0 0")
                    .style("display", "grid")
                    .style("gap", "0.35rem")
                    .children(result.results.iter().map(|file| html!("li", {
                        .attr("data-status", if file.result.is_ok() { "ok" } else { "error" })
                        .style("word-break", "break-word")
                        .children(&mut [
                            html!("span", {
                                .style("color", if file.result.is_ok() { "var(--ok)" } else { "var(--danger)" })
                                .text(if file.result.is_ok() { "✔ " } else { "✘ " })
                            }),
                            html!("span", { .style("font-weight", "500").text(&file.name) }),
                            html!("span", {
                                .class(&*MUTED_CLASS)
                                .text(&match &file.result {
                                    Ok(name) => format!(" → {name}"),
                                    Err(err) => format!(" — {err}"),
                                })
                            }),
                        ])
                    })))
                }),
            ])
            .child(html!("div", {
                .class(&*ACTIONS_CLASS)
                .style("justify-content", "flex-start")
                .apply_if(signed > 0, |dom| dom.child(html!("button", {
                    .attr("type", "button")
                    .attr("id", "batch_download")
                    .class("primary")
                    .text("Descargar firmas.zip")
                    .event(clone!(result => move |_: events::Click| {
                        if let Err(err) = web::download(&result.zip, "firmas.zip", "application/zip") {
                            log::error!("{err}");
                        }
                    }))
                })))
                .child(html!("button", {
                    .attr("type", "button")
                    .attr("id", "sign_another")
                    .text("Firmar otros ficheros")
                    .event(clone!(this => move |_: events::Click| App::reset(&this.app)))
                }))
            }))
            .child(html!("button", {
                .attr("type", "button")
                .class("link")
                .style("margin-top", "0.5rem")
                .text("Volver a las opciones de firma")
                .event(clone!(this => move |_: events::Click| this.result.set(None)))
            }))
        })
    }
}
