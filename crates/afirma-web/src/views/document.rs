use std::rc::Rc;

use afirma_core::{
    Error as CoreError,
    format::{DataKind, SignatureFormat},
    job::{FileAnalysis, Job, JobOutput},
    multisign::SignedKind,
    pades::PdfInfo,
};
use dominator::{Dom, clone, events, html, with_node};
use futures_signals::signal::{Mutable, SignalExt};
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlInputElement;

use super::{sign::SignPanel, verify::Verifier};
use crate::{
    app::App,
    components::{file_picker::LoadedFile, page_placement::PagePlacement},
    css::{
        ACTIONS_CLASS, CARD_CLASS, ELLIPSIS_CLASS, ERROR_CLASS, FILE_ICON_CLASS, FILE_ROW_CLASS,
        MUTED_CLASS,
    },
    utils::format_size,
};

/// An opened PDF: pages and the password that opened it.
#[derive(Debug)]
pub struct PdfDocument {
    pub info: PdfInfo,
    pub password: Option<String>,
    pub placement: Rc<PagePlacement>,
}

/// One file: verified at once if it is a signature or a signed document, and
/// ready to be signed.
#[derive(Debug)]
pub struct Document {
    app: Rc<App>,
    file: Rc<LoadedFile>,
    analysis: FileAnalysis,
    pdf: Mutable<Option<Rc<PdfDocument>>>,
    /// Password of an encrypted PDF, for both verifying and signing.
    password: Mutable<Option<String>>,
    needs_password: Mutable<bool>,
    password_error: Mutable<Option<String>>,
    /// Signed data of a detached signature, when known.
    data: Option<Rc<LoadedFile>>,
    /// Set for signatures and signed documents. The signatures of an encrypted
    /// PDF are only found once it is open.
    verifier: Mutable<Option<Rc<Verifier>>>,
    signer: Rc<SignPanel>,
}

impl Document {
    /// `data` is the signed data of a detached signature, when known.
    pub fn new(
        app: &Rc<App>,
        file: LoadedFile,
        analysis: FileAnalysis,
        data: Option<Rc<LoadedFile>>,
    ) -> Rc<Self> {
        let file = Rc::new(file);
        let pdf = Mutable::new(None);
        let signer = SignPanel::new(app, file.clone(), analysis.clone(), pdf.clone());
        let signed = analysis.signed.is_some();
        let this = Rc::new(Self {
            app: app.clone(),
            file,
            analysis,
            pdf,
            password: Mutable::new(None),
            needs_password: Mutable::new(false),
            password_error: Mutable::new(None),
            data,
            verifier: Mutable::new(None),
            signer,
        });
        if signed {
            this.add_verifier();
        }
        Self::open(&this);
        this
    }

    fn add_verifier(&self) {
        self.verifier.set(Some(Verifier::new(
            self.app.worker.clone(),
            self.file.clone(),
            self.data.clone(),
            self.password.clone(),
            self.needs_password.clone(),
        )));
    }

    /// Reads the PDF pages and verifies the signatures, with the current password.
    fn open(this: &Rc<Self>) {
        if let Some(verifier) = this.verifier.get_cloned() {
            Verifier::verify(&verifier);
        }
        if this.analysis.kind == DataKind::Pdf {
            spawn_local(clone!(this => async move { Self::open_pdf(&this).await }));
        }
    }

    async fn open_pdf(this: &Rc<Self>) {
        let password = this.password.get_cloned();
        let job = Job::PdfInfo {
            data: this.file.data.clone(),
            password: password.clone(),
        };
        match this.app.worker.run(job).await {
            Ok(JobOutput::PdfInfo(info)) => {
                this.needs_password.set_neq(false);
                this.password_error.set(None);
                // Signatures that were hidden by the encryption.
                if info.signatures > 0 && this.verifier.lock_ref().is_none() {
                    this.add_verifier();
                    if let Some(verifier) = this.verifier.get_cloned() {
                        Verifier::verify(&verifier);
                    }
                }
                let placement = PagePlacement::new(info.pages.clone());
                this.pdf.set(Some(Rc::new(PdfDocument {
                    info,
                    password,
                    placement,
                })));
            }
            Ok(other) => log::error!("Unexpected worker output: {other:?}"),
            Err(err) => {
                let message = err.to_string();
                if message == CoreError::PdfPasswordRequired.to_string()
                    || message == CoreError::WrongPdfPassword.to_string()
                {
                    this.needs_password.set_neq(true);
                    if password.is_some() {
                        this.password_error.set(Some(message));
                    }
                } else {
                    // A PDF that cannot be parsed can still be signed in CAdES.
                    this.signer.fall_back(SignatureFormat::Cades, message);
                }
            }
        }
    }

    pub fn render(this: &Rc<Self>) -> Dom {
        html!("div", {
            .style("display", "flex")
            .style("flex-direction", "column")
            .style("gap", "1rem")
            .child(Self::render_file(this))
            .child_signal(this.needs_password.signal().map(clone!(this => move |needed| {
                needed.then(|| Self::render_password(&this))
            })))
            .child_signal(this.verifier.signal_cloned().map(|verifier| {
                verifier.map(|verifier| Verifier::render(&verifier))
            }))
            .child(SignPanel::render(&this.signer))
        })
    }

    fn render_file(this: &Rc<Self>) -> Dom {
        let analysis = &this.analysis;
        let mut facts = vec![
            analysis.kind.description().to_string(),
            format_size(analysis.size),
        ];
        if let Some(signed) = analysis.signed {
            facts.push(
                match signed {
                    SignedKind::Cades | SignedKind::Xades | SignedKind::Asic => "Firma electrónica",
                    SignedKind::Facturae => "Factura firmada",
                    SignedKind::Pdf | SignedKind::Odf | SignedKind::Ooxml => "Firmado",
                }
                .to_string(),
            );
        }

        html!("section", {
            .class(&*CARD_CLASS)
            .attr("id", "file_info")
            .attr("aria-label", "Fichero")
            .children(&mut [
                html!("div", {
                    .class(&*FILE_ROW_CLASS)
                    .children(&mut [
                        html!("span", {
                            .class(&*FILE_ICON_CLASS)
                            .attr("aria-hidden", "true")
                            .text(&extension_badge(&this.file.name))
                        }),
                        html!("div", {
                            .style("flex", "1")
                            .style("min-width", "0")
                            .children(&mut [
                                html!("p", {
                                    .attr("id", "file_name")
                                    .class(&*ELLIPSIS_CLASS)
                                    .style("font-weight", "600")
                                    .attr("title", &this.file.name)
                                    .text(&this.file.name)
                                }),
                                html!("p", {
                                    .attr("id", "file_kind")
                                    .class(&*MUTED_CLASS)
                                    .text(&facts.join(" · "))
                                }),
                            ])
                        }),
                        html!("button", {
                            .attr("type", "button")
                            .attr("id", "file_close")
                            .text("Cerrar")
                            .event(clone!(this => move |_: events::Click| App::reset(&this.app)))
                        }),
                    ])
                }),
                html!("details", {
                    .style("margin-top", "0.75rem")
                    .children(&mut [
                        html!("summary", { .class(&*MUTED_CLASS).text("Huella SHA-256") }),
                        html!("code", {
                            .attr("id", "file_sha256")
                            .style("display", "block")
                            .style("margin-top", "0.35rem")
                            .style("font-size", "0.8rem")
                            .style("word-break", "break-all")
                            .text(&analysis.sha256)
                        }),
                    ])
                }),
            ])
        })
    }

    fn render_password(this: &Rc<Self>) -> Dom {
        let password = Mutable::new(String::new());
        html!("form", {
            .class(&*CARD_CLASS)
            .attr("id", "pdf_password_form")
            .event_with_options(&dominator::EventOptions::preventable(), clone!(this, password => move |event: events::Submit| {
                event.prevent_default();
                this.password.set(Some(password.get_cloned()));
                this.password_error.set(None);
                Self::open(&this);
            }))
            .children(&mut [
                html!("label", {
                    .attr("for", "pdf_password")
                    .style("display", "block")
                    .style("font-weight", "600")
                    .style("margin-bottom", "0.35rem")
                    .text("El PDF está protegido con contraseña")
                }),
                html!("div", {
                    .style("display", "flex")
                    .style("gap", "0.5rem")
                    .children(&mut [
                        html!("input" => HtmlInputElement, {
                            .attr("type", "password")
                            .attr("id", "pdf_password")
                            .attr("autocomplete", "off")
                            .style("flex", "1")
                            .focused(true)
                            .with_node!(element => {
                                .event(clone!(password => move |_: events::Input| password.set(element.value())))
                            })
                        }),
                        html!("button", {
                            .attr("type", "submit")
                            .attr("id", "pdf_unlock")
                            .class("primary")
                            .text("Abrir")
                        }),
                    ])
                }),
            ])
            .child_signal(this.password_error.signal_cloned().map(|error| {
                error.map(|error| html!("p", { .class(&*ERROR_CLASS).attr("role", "alert").text(&error) }))
            }))
        })
    }

    /// Buttons shown with a finished signature, after the download.
    pub fn render_next_steps(
        app: &Rc<App>,
        signature: Rc<LoadedFile>,
        original: Rc<LoadedFile>,
    ) -> Dom {
        html!("div", {
            .class(&*ACTIONS_CLASS)
            .style("justify-content", "flex-start")
            .children(&mut [
                html!("button", {
                    .attr("type", "button")
                    .attr("id", "verify_signature")
                    .text("Comprobar la firma")
                    .event(clone!(app => move |_: events::Click| {
                        let signature = LoadedFile { name: signature.name.clone(), data: signature.data.clone() };
                        App::open_signature(&app, signature, Some(original.clone()));
                    }))
                }),
                html!("button", {
                    .attr("type", "button")
                    .attr("id", "sign_another")
                    .text("Firmar otro fichero")
                    .event(clone!(app => move |_: events::Click| App::reset(&app)))
                }),
            ])
        })
    }
}

/// `PDF`, `XML`, `DOCX`…: the extension shown in the file icon.
fn extension_badge(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((_, ext)) if !ext.is_empty() && ext.len() <= 5 => ext.to_uppercase(),
        _ => "—".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn badges() {
        assert_eq!(extension_badge("doc.pdf"), "PDF");
        assert_eq!(extension_badge("a.b.xsig"), "XSIG");
        assert_eq!(extension_badge("README"), "—");
        assert_eq!(extension_badge("x.verylongext"), "—");
    }
}
