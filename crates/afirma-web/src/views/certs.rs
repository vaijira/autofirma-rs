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
    components::{
        dialog::modal,
        file_picker::{FilePicker, LoadedFile},
        form::checkbox,
    },
    css::{
        ACTIONS_CLASS, DETAILS_LIST_CLASS, ELLIPSIS_CLASS, ERROR_CLASS, MUTED_CLASS, TILE_CLASS,
        TILE_SELECTED_CLASS,
    },
    state::{Keys, format_date, now},
    worker::WorkerClient,
};

/// The signing certificate: a button in the header and the dialog to import
/// PKCS#12 keystores and choose among their keys.
#[derive(Debug)]
pub struct Certificates {
    worker: Rc<WorkerClient>,
    keys: Rc<Keys>,
    open: Mutable<bool>,
    /// Keystore waiting for its password.
    pending: Mutable<Option<Rc<LoadedFile>>>,
    password_error: Mutable<Option<String>>,
    error: Mutable<Option<String>>,
    busy: Mutable<bool>,
    only_valid: Mutable<bool>,
}

impl Certificates {
    pub fn new(worker: Rc<WorkerClient>, keys: Rc<Keys>) -> Rc<Self> {
        Rc::new(Self {
            worker,
            keys,
            open: Mutable::new(false),
            pending: Mutable::new(None),
            password_error: Mutable::new(None),
            error: Mutable::new(None),
            busy: Mutable::new(false),
            only_valid: Mutable::new(true),
        })
    }

    pub fn show(&self) {
        self.open.set_neq(true);
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
                    let first = this.keys.entries.lock_ref().is_empty();
                    this.keys.add(entries);
                    this.pending.set(None);
                    this.password_error.set(None);
                    // Back to the task the certificate was needed for.
                    if first {
                        this.open.set(false);
                    }
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

    /// Header button: the selected certificate, or an invitation to import one.
    pub fn render_button(this: &Rc<Self>) -> Dom {
        html!("button", {
            .attr("type", "button")
            .attr("id", "cert_button")
            .attr("aria-haspopup", "dialog")
            .style("display", "flex")
            .style("align-items", "center")
            .style("gap", "0.5rem")
            .style("max-width", "min(18rem, 60vw)")
            .style("border-radius", "999px")
            .style("padding", "0.3rem 0.85rem 0.3rem 0.3rem")
            .event(clone!(this => move |_: events::Click| this.show()))
            .children_signal_vec(this.keys.selected_signal().map(|entry| match entry {
                Some(entry) => vec![
                    html!("span", {
                        .attr("aria-hidden", "true")
                        .style("display", "grid")
                        .style("place-items", "center")
                        .style("flex", "none")
                        .style("width", "1.8rem")
                        .style("height", "1.8rem")
                        .style("border-radius", "50%")
                        .style("background", "var(--accent)")
                        .style("color", "var(--on-accent)")
                        .style("font-size", "0.75rem")
                        .text(&initials(&entry.certificate.subject_cn))
                    }),
                    html!("span", {
                        .class(&*ELLIPSIS_CLASS)
                        .attr("title", &entry.certificate.subject_cn)
                        .text(&entry.certificate.subject_cn)
                    }),
                ],
                None => vec![
                    html!("span", {
                        .attr("aria-hidden", "true")
                        .style("display", "grid")
                        .style("place-items", "center")
                        .style("width", "1.8rem")
                        .style("height", "1.8rem")
                        .style("border-radius", "50%")
                        .style("background", "var(--surface-2)")
                        .text("+")
                    }),
                    html!("span", { .text("Importar certificado") }),
                ],
            }).to_signal_vec())
        })
    }

    pub fn render_dialog(this: &Rc<Self>) -> Dom {
        modal(
            "cert_dialog",
            "Certificado de firma",
            &this.open,
            clone!(this => move || {
                html!("div", {
                    .child(html!("p", {
                        .class(&*MUTED_CLASS)
                        .text("Importe su certificado desde un fichero PKCS#12 (.p12 o .pfx). La clave privada \
                               se descifra y se guarda solo en la memoria de esta pestaña: desaparece al cerrarla.")
                    }))
                    .child_signal(this.pending.signal_cloned().map(clone!(this => move |pending| Some(match pending {
                        Some(file) => Self::render_password(&this, &file),
                        None => Self::render_import(&this),
                    }))))
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
                    .child_signal(this.keys.entries.signal_vec_cloned().len().map(clone!(this => move |len| {
                        (len > 0).then(|| html!("div", {
                            .style("margin-top", "0.75rem")
                            .child(checkbox("only_valid", "Mostrar solo los certificados vigentes y aptos para firmar", &this.only_valid))
                        }))
                    })))
                })
            }),
        )
    }

    fn render_import(this: &Rc<Self>) -> Dom {
        let picker = FilePicker::new(
            "import_p12",
            "Importar fichero .p12 / .pfx",
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
        html!("div", {
            .style("margin", "1rem 0")
            .child(FilePicker::render_primary(&picker))
        })
    }

    fn render_password(this: &Rc<Self>, file: &LoadedFile) -> Dom {
        let password = Mutable::new(String::new());
        html!("form", {
            .attr("id", "p12_form")
            .style("margin", "1rem 0")
            .event_with_options(&dominator::EventOptions::preventable(), clone!(this, password => move |event: events::Submit| {
                event.prevent_default();
                Self::unlock(&this, password.replace(String::new()));
            }))
            .children(&mut [
                html!("label", {
                    .attr("for", "p12_password")
                    .style("display", "block")
                    .style("margin-bottom", "0.35rem")
                    .text(&format!("Contraseña de «{}»", file.name))
                }),
                html!("input" => HtmlInputElement, {
                    .attr("type", "password")
                    .attr("id", "p12_password")
                    .attr("autocomplete", "off")
                    .style("width", "100%")
                    .focused(true)
                    .with_node!(element => {
                        .event(clone!(password => move |_: events::Input| password.set(element.value())))
                    })
                }),
            ])
            .child_signal(this.password_error.signal_cloned().map(|error| {
                error.map(|error| html!("p", { .class(&*ERROR_CLASS).attr("role", "alert").text(&error) }))
            }))
            .child(html!("div", {
                .class(&*ACTIONS_CLASS)
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
                        .class("primary")
                        .attr_signal("disabled", this.busy.signal().map(|busy| busy.then_some("")))
                        .text("Abrir")
                    }),
                ])
            }))
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
            .class(&*TILE_CLASS)
            .class_signal(&*TILE_SELECTED_CLASS, selected)
            .attr("data-key-id", &id.to_string())
            .children(&mut [
                html!("div", {
                    .style("display", "flex")
                    .style("justify-content", "space-between")
                    .style("gap", "0.5rem")
                    .children(&mut [
                        html!("label", {
                            .style("display", "flex")
                            .style("gap", "0.6rem")
                            .style("align-items", "center")
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
                        html!("button", {
                            .attr("type", "button")
                            .class("link")
                            .text("Quitar")
                            .event(clone!(this => move |_: events::Click| Self::remove(&this, id)))
                        }),
                    ])
                }),
                html!("details", {
                    .style("margin-top", "0.35rem")
                    .children(&mut [
                        html!("summary", {
                            .class(&*MUTED_CLASS)
                            .text(&summary(cert))
                        }),
                        Self::render_details(cert),
                    ])
                }),
            ])
        })
    }

    fn render_details(cert: &CertificateInfo) -> Dom {
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
                    "{} – {}",
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
            .class(&*DETAILS_LIST_CLASS)
            .style("margin-top", "0.5rem")
            .style("font-size", "0.875rem")
            .children(rows.into_iter().flat_map(|(name, value)| {
                [
                    html!("dt", { .style("color", "var(--muted)").text(name) }),
                    html!("dd", { .style("margin", "0").text(&value) }),
                ]
            }))
        })
    }
}

/// `Emitido por X · vigente hasta 15/10/2027`.
fn summary(cert: &CertificateInfo) -> String {
    let validity = match cert.validity_at(now()) {
        ValidityStatus::Valid => format!("vigente hasta {}", format_date(cert.not_after)),
        ValidityStatus::Expired => format!("caducado el {}", format_date(cert.not_after)),
        ValidityStatus::NotYetValid => format!("válido desde {}", format_date(cert.not_before)),
    };
    format!("Emitido por {} · {validity}", cert.issuer_cn)
}

/// `JE` for `ESPAÑOL ESPAÑOL JUAN - 12345678Z`: the first letters of the first
/// two words of the name.
fn initials(common_name: &str) -> String {
    common_name
        .split(" - ")
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|word| word.chars().next())
        .filter(|c| c.is_alphabetic())
        .take(2)
        .collect::<String>()
        .to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initials_of_names() {
        assert_eq!(initials("ESPAÑOL ESPAÑOL JUAN - 12345678Z"), "EE");
        assert_eq!(initials("juan"), "J");
        assert_eq!(initials(""), "");
    }
}
