use std::rc::Rc;

use afirma_core::{
    cert::{CertificateInfo, ValidityStatus},
    job::{Job, JobOutput, KeyEntry},
    keystore::filters::{CertFilter, matches_all},
};
use dominator::{Dom, clone, events, html, with_node};
use futures_signals::{
    signal::{Mutable, SignalExt},
    signal_vec::SignalVecExt,
};
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlInputElement;

use crate::{
    components::file_picker::{FilePicker, LoadedFile},
    css::{CARD_CLASS, CARD_SELECTED_CLASS, DIALOG_BACKDROP_CLASS, DIALOG_CLASS, ERROR_CLASS},
    state::{Keys, format_date, now},
    worker::WorkerClient,
};

/// "Certificados" view: import PKCS#12 keystores and choose the signing certificate.
#[derive(Debug)]
pub struct CertsPage {
    worker: Rc<WorkerClient>,
    keys: Rc<Keys>,
    /// Keystore waiting for its password.
    pending: Mutable<Option<Rc<LoadedFile>>>,
    password_error: Mutable<Option<String>>,
    error: Mutable<Option<String>>,
    busy: Mutable<bool>,
    only_valid: Mutable<bool>,
}

impl CertsPage {
    pub fn new(worker: Rc<WorkerClient>, keys: Rc<Keys>) -> Rc<Self> {
        Rc::new(Self {
            worker,
            keys,
            pending: Mutable::new(None),
            password_error: Mutable::new(None),
            error: Mutable::new(None),
            busy: Mutable::new(false),
            only_valid: Mutable::new(true),
        })
    }

    fn unlock(this: &Rc<Self>, password: String) {
        let Some(file) = this.pending.get_cloned() else {
            return;
        };
        this.busy.set(true);
        spawn_local(clone!(this => async move {
            let job = Job::LoadPkcs12 { data: file.data.clone(), password };
            match this.worker.run(job).await {
                Ok(JobOutput::Keys(entries)) => {
                    this.keys.add(entries);
                    this.pending.set(None);
                    this.password_error.set(None);
                }
                Ok(other) => log::error!("Unexpected worker output: {other:?}"),
                Err(err) => this.password_error.set(Some(err.to_string())),
            }
            this.busy.set(false);
        }));
    }

    fn remove(this: &Rc<Self>, key_id: u32) {
        spawn_local(clone!(this => async move {
            match this.worker.run(Job::RemoveKey { key_id }).await {
                Ok(_) => this.keys.remove(key_id),
                Err(err) => this.error.set(Some(err.to_string())),
            }
        }));
    }

    pub fn render(this: &Rc<Self>) -> Dom {
        let picker = FilePicker::new(
            "import_p12",
            "Importar certificado (.p12 / .pfx)",
            ".p12,.pfx,application/x-pkcs12",
            clone!(this => move |result| match result {
                Ok(file) => {
                    this.error.set(None);
                    this.password_error.set(None);
                    this.pending.set(Some(Rc::new(file)));
                }
                Err(err) => this.error.set(Some(err)),
            }),
        );

        html!("section", {
            .children(&mut [
                html!("h2", { .text("Certificados") }),
                html!("p", {
                    .text("Importe su certificado de firma desde un fichero PKCS#12 (.p12 o .pfx). \
                           La clave privada se descifra y se guarda solo en la memoria de esta pestaña; \
                           desaparece al cerrarla.")
                }),
                FilePicker::render(&picker),
                html!("label", {
                    .style("display", "block")
                    .style("margin", "1rem 0")
                    .children(&mut [
                        html!("input" => HtmlInputElement, {
                            .attr("type", "checkbox")
                            .attr("id", "only_valid")
                            .prop("checked", this.only_valid.get())
                            .with_node!(element => {
                                .event(clone!(this => move |_: events::Change| {
                                    this.only_valid.set(element.checked());
                                }))
                            })
                        }),
                        html!("span", { .text(" Mostrar solo certificados vigentes y aptos para firma") }),
                    ])
                }),
            ])
            .child_signal(this.error.signal_cloned().map(|error| {
                error.map(|error| html!("p", { .class(&*ERROR_CLASS).attr("role", "alert").text(&error) }))
            }))
            .child(html!("div", {
                .attr("id", "cert_list")
                .children_signal_vec(this.keys.entries.signal_vec_cloned()
                    .filter_signal_cloned(clone!(this => move |entry| {
                        let certificate = entry.certificate.clone();
                        this.only_valid.signal().map(move |only_valid| {
                            !only_valid || matches_all(
                                &[CertFilter::NonExpired, CertFilter::SigningCert],
                                &certificate,
                                now(),
                            )
                        })
                    }))
                    .map(clone!(this => move |entry| Self::render_entry(&this, entry))))
            }))
            .child_signal(this.keys.entries.signal_vec_cloned().len().map(|len| {
                (len == 0).then(|| html!("p", { .text("No hay ningún certificado importado.") }))
            }))
            .child_signal(this.pending.signal_cloned().map(clone!(this => move |pending| {
                pending.map(|file| Self::render_password_dialog(&this, &file))
            })))
        })
    }

    fn render_entry(this: &Rc<Self>, entry: KeyEntry) -> Dom {
        let id = entry.id;
        let cert = &entry.certificate;
        let selected = this
            .keys
            .selected
            .signal()
            .map(move |selected| selected == Some(id));

        html!("article", {
            .class(&*CARD_CLASS)
            .class_signal(&*CARD_SELECTED_CLASS, selected)
            .attr("data-key-id", &id.to_string())
            .children(&mut [
                html!("label", {
                    .style("display", "flex")
                    .style("gap", "0.5rem")
                    .style("align-items", "baseline")
                    .style("font-weight", "600")
                    .children(&mut [
                        html!("input" => HtmlInputElement, {
                            .attr("type", "radio")
                            .attr("name", "signing_key")
                            .prop_signal("checked", this.keys.selected.signal().map(move |s| s == Some(id)))
                            .event(clone!(this => move |_: events::Change| this.keys.selected.set(Some(id))))
                        }),
                        html!("span", { .text(&cert.subject_cn) }),
                    ])
                }),
                Self::render_details(cert),
                html!("button", {
                    .attr("type", "button")
                    .text("Quitar")
                    .event(clone!(this => move |_: events::Click| Self::remove(&this, id)))
                }),
            ])
        })
    }

    fn render_details(cert: &CertificateInfo) -> Dom {
        let validity = match cert.validity_at(now()) {
            ValidityStatus::Valid => "Vigente",
            ValidityStatus::Expired => "Caducado",
            ValidityStatus::NotYetValid => "Aún no válido",
        };
        let mut usage = Vec::new();
        if cert.digital_signature {
            usage.push("firma digital");
        }
        if cert.non_repudiation {
            usage.push("no repudio");
        }
        if cert.is_ca {
            usage.push("autoridad de certificación");
        }
        let rows = [
            ("Emisor", cert.issuer_cn.clone()),
            (
                "Validez",
                format!(
                    "{} – {} ({validity})",
                    format_date(cert.not_before),
                    format_date(cert.not_after)
                ),
            ),
            ("Uso", usage.join(", ")),
            (
                "Clave",
                cert.key_type
                    .map(|k| k.name())
                    .unwrap_or("desconocida")
                    .to_string(),
            ),
            (
                "Cualificado",
                if cert.qualified { "Sí" } else { "No" }.to_string(),
            ),
            ("Número de serie", cert.serial.clone()),
            ("Huella SHA-1", cert.sha1_fingerprint.clone()),
            ("Sujeto", cert.subject.clone()),
        ];

        html!("dl", {
            .style("display", "grid")
            .style("grid-template-columns", "max-content 1fr")
            .style("gap", "0.15rem 1rem")
            .style("word-break", "break-all")
            .children(rows.into_iter().flat_map(|(name, value)| {
                [
                    html!("dt", { .style("color", "var(--muted)").text(name) }),
                    html!("dd", { .style("margin", "0").text(&value) }),
                ]
            }))
        })
    }

    fn render_password_dialog(this: &Rc<Self>, file: &LoadedFile) -> Dom {
        let password = Mutable::new(String::new());

        html!("div", {
            .class(&*DIALOG_BACKDROP_CLASS)
            .child(html!("form", {
                .class(&*DIALOG_CLASS)
                .attr("role", "dialog")
                .attr("aria-modal", "true")
                .attr("aria-labelledby", "password_title")
                .event_with_options(&dominator::EventOptions::preventable(), clone!(this, password => move |event: events::Submit| {
                    event.prevent_default();
                    Self::unlock(&this, password.replace(String::new()));
                }))
                .children(&mut [
                    html!("h3", {
                        .attr("id", "password_title")
                        .style("margin-top", "0")
                        .text("Contraseña del almacén")
                    }),
                    html!("p", { .text(&format!("Introduzca la contraseña de «{}».", file.name)) }),
                    html!("input" => HtmlInputElement, {
                        .attr("type", "password")
                        .attr("id", "p12_password")
                        .attr("autocomplete", "off")
                        .attr("aria-label", "Contraseña")
                        .style("width", "100%")
                        .style("box-sizing", "border-box")
                        .focused(true)
                        .with_node!(element => {
                            .event(clone!(password => move |_: events::Input| {
                                password.set(element.value());
                            }))
                        })
                    }),
                ])
                .child_signal(this.password_error.signal_cloned().map(|error| {
                    error.map(|error| html!("p", { .class(&*ERROR_CLASS).attr("role", "alert").text(&error) }))
                }))
                .child(html!("div", {
                    .style("display", "flex")
                    .style("gap", "0.5rem")
                    .style("justify-content", "flex-end")
                    .style("margin-top", "1rem")
                    .children(&mut [
                        html!("button", {
                            .attr("type", "button")
                            .text("Cancelar")
                            .event(clone!(this => move |_: events::Click| {
                                this.pending.set(None);
                                this.password_error.set(None);
                            }))
                        }),
                        html!("button", {
                            .attr("type", "submit")
                            .attr("id", "p12_unlock")
                            .attr_signal("disabled", this.busy.signal().map(|busy| busy.then_some("")))
                            .text("Aceptar")
                        }),
                    ])
                }))
            }))
        })
    }
}
