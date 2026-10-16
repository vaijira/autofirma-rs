use std::rc::Rc;

use afirma_core::{
    Error as CoreError,
    algorithm::KeyType,
    cades::{CadesParams, SignatureMode},
    digest::DigestAlgorithm,
    format::{DataKind, SignatureFormat},
    job::{FileAnalysis, Job, JobOutput, KeyEntry},
    pades::{
        CertificationLevel, Font, FontFamily, PadesParams, PdfInfo, SignaturePages,
        VisibleSignature,
    },
    params::ExtraParams,
    policy::PolicyPreset,
    triphase::{self, CryptoOperation, TriphaseFormat, TriphaseRequest},
};
use anyhow::anyhow;
use dominator::{Dom, clone, events, html, link, with_node};
use futures_signals::{
    map_ref,
    signal::{Mutable, SignalExt},
};
use wasm_bindgen_futures::spawn_local;
use web_sys::{HtmlInputElement, HtmlSelectElement};

use crate::{
    components::{
        file_picker::{FilePicker, LoadedFile},
        page_placement::PagePlacement,
    },
    css::{ERROR_CLASS, INFO_TABLE_CLASS, OPTIONS_CLASS},
    router::Route,
    state::{Keys, now, utc_offset_minutes},
    utils::{format_size, http, web},
    worker::WorkerClient,
};

/// File selected for signing together with its analysis.
#[derive(Debug)]
struct Selected {
    file: LoadedFile,
    analysis: FileAnalysis,
}

/// An opened PDF: pages and the password that opened it.
#[derive(Debug)]
struct PdfDocument {
    info: PdfInfo,
    password: Option<String>,
    placement: Rc<PagePlacement>,
}

/// A signature ready to download.
#[derive(Debug)]
struct SignatureResult {
    data: Vec<u8>,
    file_name: String,
    mime_type: &'static str,
    description: String,
}

/// Signature options, with AutoFirma's defaults.
#[derive(Debug)]
struct Options {
    format: Mutable<SignatureFormat>,
    digest: Mutable<DigestAlgorithm>,
    mode: Mutable<SignatureMode>,
    policy: Mutable<Option<PolicyPreset>>,
    reason: Mutable<String>,
    location: Mutable<String>,
    certification: Mutable<CertificationLevel>,
    visible: Mutable<bool>,
    /// Visible text with AutoFirma's placeholders; empty for the default text.
    text: Mutable<String>,
    font_family: Mutable<FontFamily>,
    font_size: Mutable<f32>,
    rubric: Mutable<Option<Rc<LoadedFile>>>,
    triphase: Mutable<bool>,
    server_url: Mutable<String>,
}

/// "Firmar" view: pick a file, choose the options and sign it.
#[derive(Debug)]
pub struct SignPage {
    worker: Rc<WorkerClient>,
    keys: Rc<Keys>,
    selected: Mutable<Option<Rc<Selected>>>,
    pdf: Mutable<Option<Rc<PdfDocument>>>,
    /// The selected PDF is encrypted and needs a password.
    needs_password: Mutable<bool>,
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
            pdf: Mutable::new(None),
            needs_password: Mutable::new(false),
            options: Options {
                format: Mutable::new(SignatureFormat::Cades),
                digest: Mutable::new(DigestAlgorithm::Sha512),
                mode: Mutable::new(SignatureMode::Explicit),
                policy: Mutable::new(None),
                reason: Mutable::new(String::new()),
                location: Mutable::new(String::new()),
                certification: Mutable::new(CertificationLevel::NotCertified),
                visible: Mutable::new(false),
                text: Mutable::new(String::new()),
                font_family: Mutable::new(FontFamily::Courier),
                font_size: Mutable::new(12.0),
                rubric: Mutable::new(None),
                triphase: Mutable::new(false),
                server_url: Mutable::new(String::new()),
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
        this.pdf.set(None);
        this.needs_password.set(false);
        this.signature.set(None);
        this.busy.set(Some("Analizando…"));
        spawn_local(clone!(this => async move {
            // The worker gets its own copy; the UI keeps the original for signing.
            match this.worker.run(Job::Analyze { data: file.data.clone() }).await {
                Ok(JobOutput::Analysis(analysis)) => {
                    let is_pdf = analysis.kind == DataKind::Pdf;
                    this.options.format.set(match analysis.default_format {
                        SignatureFormat::Pades => SignatureFormat::Pades,
                        _ => SignatureFormat::Cades,
                    });
                    this.selected.set(Some(Rc::new(Selected { file, analysis })));
                    if is_pdf {
                        Self::open_pdf(&this, None).await;
                    }
                }
                Ok(other) => log::error!("Unexpected worker output: {other:?}"),
                Err(err) => this.error.set(Some(err.to_string())),
            }
            this.busy.set(None);
        }));
    }

    /// Reads the pages of the selected PDF, asking for its password if needed.
    async fn open_pdf(this: &Rc<Self>, password: Option<String>) {
        let Some(selected) = this.selected.get_cloned() else {
            return;
        };
        let job = Job::PdfInfo {
            data: selected.file.data.clone(),
            password: password.clone(),
        };
        match this.worker.run(job).await {
            Ok(JobOutput::PdfInfo(info)) => {
                this.needs_password.set(false);
                this.error.set(None);
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
                    this.needs_password.set(true);
                }
                // A PDF that cannot be parsed can still be signed in CAdES.
                if password.is_some() || !this.needs_password.get() {
                    this.error.set(Some(message));
                }
                if !this.needs_password.get() {
                    this.options.format.set(SignatureFormat::Cades);
                }
            }
        }
    }

    fn pades_params(&self, pdf: &PdfDocument) -> PadesParams {
        let options = &self.options;
        let text = |value: &Mutable<String>| {
            let value = value.get_cloned();
            (!value.trim().is_empty()).then_some(value)
        };
        let visible = options.visible.get().then(|| VisibleSignature {
            pages: SignaturePages::Pages(vec![pdf.placement.page.get() as i32]),
            rect: pdf.placement.rect.get(),
            text: text(&options.text),
            font: Font {
                family: options.font_family.get(),
                size: options.font_size.get(),
                ..Font::default()
            },
            image: options.rubric.get_cloned().map(|file| file.data.clone()),
            obfuscate: None,
            mask: None,
        });
        PadesParams {
            digest: options.digest.get(),
            policy: options
                .policy
                .get()
                .map(|preset| preset.policy(SignatureFormat::Pades)),
            signing_time: now(),
            utc_offset_minutes: utc_offset_minutes(),
            reason: text(&options.reason),
            location: text(&options.location),
            contact: None,
            certification: options.certification.get(),
            visible,
            password: pdf.password.clone(),
            allow_signing_certified: false,
            reserved_size: None,
        }
    }

    fn cades_params(&self, kind: DataKind) -> CadesParams {
        CadesParams {
            digest: self.options.digest.get(),
            mode: self.options.mode.get(),
            policy: self
                .options
                .policy
                .get()
                .map(|preset| preset.policy(SignatureFormat::Cades)),
            signing_time: now(),
            content_description: content_description(kind),
        }
    }

    fn sign(this: &Rc<Self>) {
        let Some(selected) = this.selected.get_cloned() else {
            return;
        };
        let Some(entry) = this.keys.selected_entry() else {
            return;
        };
        let format = this.options.format.get();
        let pdf = this.pdf.get_cloned();

        this.error.set(None);
        this.signature.set(None);
        this.busy.set(Some("Firmando…"));
        spawn_local(clone!(this => async move {
            let result = match (format, &pdf) {
                (SignatureFormat::Pades, Some(pdf)) => {
                    let params = this.pades_params(pdf);
                    if this.options.triphase.get() {
                        let extra = ExtraParams::from(&params);
                        Self::sign_triphase(&this, &entry, TriphaseFormat::Pades, &selected.file.data, params.digest, extra).await
                    } else {
                        let job = Job::SignPades { data: selected.file.data.clone(), key_id: entry.id, params: Box::new(params) };
                        Self::run_signature_job(&this, job).await
                    }
                    .map(|data| SignatureResult {
                        description: format!("PDF firmado en PAdES ({}).", format_size(data.len())),
                        data,
                        file_name: signed_pdf_name(&selected.file.name),
                        mime_type: "application/pdf",
                    })
                }
                (SignatureFormat::Pades, None) => Err(anyhow!("Abra antes el PDF")),
                _ => {
                    let params = this.cades_params(selected.analysis.kind);
                    if this.options.triphase.get() {
                        let extra = ExtraParams::from(&params);
                        Self::sign_triphase(&this, &entry, TriphaseFormat::Cades, &selected.file.data, params.digest, extra).await
                    } else {
                        let job = Job::SignCades { data: selected.file.data.clone(), key_id: entry.id, params };
                        Self::run_signature_job(&this, job).await
                    }
                    .map(|data| SignatureResult {
                        description: format!("Firma CAdES generada ({}).", format_size(data.len())),
                        data,
                        file_name: format!("{}.csig", selected.file.name),
                        mime_type: "application/pkcs7-signature",
                    })
                }
            };
            match result {
                Ok(signature) => this.signature.set(Some(Rc::new(signature))),
                Err(err) => this.error.set(Some(err.to_string())),
            }
            this.busy.set(None);
        }));
    }

    async fn run_signature_job(this: &Rc<Self>, job: Job) -> anyhow::Result<Vec<u8>> {
        match this.worker.run(job).await? {
            JobOutput::Signature(data) => Ok(data),
            other => Err(anyhow!("Respuesta inesperada del worker: {other:?}")),
        }
    }

    /// Triphase signature: the server builds the signature, the key (in the
    /// worker) only signs the pre-signatures.
    async fn sign_triphase(
        this: &Rc<Self>,
        entry: &KeyEntry,
        format: TriphaseFormat,
        document: &[u8],
        digest: DigestAlgorithm,
        params: ExtraParams,
    ) -> anyhow::Result<Vec<u8>> {
        let url = this.options.server_url.get_cloned().trim().to_string();
        if url.is_empty() {
            return Err(anyhow!(
                "Indique la dirección del servidor de firma trifásica"
            ));
        }
        let key_type: KeyType = entry
            .certificate
            .key_type
            .ok_or_else(|| anyhow!("Tipo de clave no soportado"))?;
        let request = TriphaseRequest {
            format,
            operation: CryptoOperation::Sign,
            digest,
            key_type,
            chain: entry.chain.iter().map(|c| c.to_vec()).collect(),
            document_id: triphase::document_id(document),
            params,
        };

        this.busy.set(Some("Prefirma en el servidor…"));
        let presign_response = http::post_form(&url, &request.presign_body()).await?;
        this.busy.set(Some("Firmando…"));
        let session = match this
            .worker
            .run(Job::SignTriphase {
                presign_response,
                key_id: entry.id,
                digest,
            })
            .await?
        {
            JobOutput::Triphase(session) => session,
            other => return Err(anyhow!("Respuesta inesperada del worker: {other:?}")),
        };
        this.busy.set(Some("Postfirma en el servidor…"));
        let response = http::post_form(&url, &request.postsign_body(&session)).await?;
        Ok(triphase::parse_postsign_response(&response)?)
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
            .child_signal(this.needs_password.signal().map(clone!(this => move |needed| {
                needed.then(|| Self::render_pdf_password(&this))
            })))
            .child_signal(this.selected.signal_cloned().map(clone!(this => move |selected| {
                selected.map(|selected| Self::render_sign_form(&this, &selected))
            })))
            .child_signal(this.busy.signal().map(|busy| busy.map(|text| html!("p", { .attr("role", "status").text(text) }))))
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

    fn render_pdf_password(this: &Rc<Self>) -> Dom {
        let password = Mutable::new(String::new());
        html!("form", {
            .attr("id", "pdf_password_form")
            .style("margin", "1rem 0")
            .event_with_options(&dominator::EventOptions::preventable(), clone!(this, password => move |event: events::Submit| {
                event.prevent_default();
                let password = password.get_cloned();
                this.busy.set(Some("Abriendo el PDF…"));
                spawn_local(clone!(this => async move {
                    Self::open_pdf(&this, Some(password)).await;
                    this.busy.set(None);
                }));
            }))
            .children(&mut [
                html!("label", {
                    .attr("for", "pdf_password")
                    .text("El PDF está protegido. Contraseña: ")
                }),
                html!("input" => HtmlInputElement, {
                    .attr("type", "password")
                    .attr("id", "pdf_password")
                    .attr("autocomplete", "off")
                    .with_node!(element => {
                        .event(clone!(password => move |_: events::Input| password.set(element.value())))
                    })
                }),
                html!("button", { .attr("type", "submit").attr("id", "pdf_unlock").text("Abrir") }),
            ])
        })
    }

    fn render_sign_form(this: &Rc<Self>, selected: &Rc<Selected>) -> Dom {
        let is_pdf = selected.analysis.kind == DataKind::Pdf;
        let default_format = selected.analysis.default_format;
        let options = &this.options;
        let pades = options.format.signal().map(|f| f == SignatureFormat::Pades);

        html!("div", {
            .child(html!("div", {
                .class(&*OPTIONS_CLASS)
                .children(&mut [
                    html!("label", { .attr("for", "sign_format").text("Formato") }),
                    select(
                        "sign_format",
                        if is_pdf {
                            &[("pades", "PAdES (firma dentro del PDF)"), ("cades", "CAdES")]
                        } else {
                            &[("cades", "CAdES")]
                        },
                        match options.format.get() {
                            SignatureFormat::Pades => "pades",
                            _ => "cades",
                        },
                        clone!(this => move |value| this.options.format.set(match value.as_str() {
                            "pades" => SignatureFormat::Pades,
                            _ => SignatureFormat::Cades,
                        })),
                    ),
                    html!("label", { .attr("for", "sign_digest").text("Algoritmo") }),
                    select(
                        "sign_digest",
                        &[("sha512", "SHA-512"), ("sha384", "SHA-384"), ("sha256", "SHA-256")],
                        match options.digest.get() {
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
                            ("none", "Ninguna (BES)"),
                            ("age19", PolicyPreset::Age19.name()),
                            ("age18", PolicyPreset::Age18.name()),
                        ],
                        match options.policy.get() {
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
                ])
                .child_signal(pades.map(clone!(this => move |pades| {
                    (!pades).then(|| Self::render_cades_options(&this))
                })))
                .children(&mut [
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
            }))
            .apply_if(!matches!(default_format, SignatureFormat::Cades | SignatureFormat::Pades), |dom| {
                dom.child(html!("p", {
                    .style("color", "var(--muted)")
                    .text(&format!(
                        "AutoFirma usaría {} para este fichero; ese formato estará disponible en una próxima fase. \
                         Puede firmarlo ya en CAdES.",
                        default_format.name()
                    ))
                }))
            })
            .child_signal({
                let page = this.clone();
                map_ref! {
                    let pades = options.format.signal().map(|f| f == SignatureFormat::Pades),
                    let pdf = this.pdf.signal_cloned() => move {
                        match (pades, pdf) {
                            (true, Some(pdf)) => Some(Self::render_pades_options(&page, pdf)),
                            _ => None,
                        }
                    }
                }
            })
            .child(Self::render_triphase_options(this))
            .child(html!("button", {
                .attr("type", "button")
                .attr("id", "sign_button")
                .text("Firmar")
                .attr_signal("disabled", map_ref! {
                    let key = this.keys.selected.signal(),
                    let busy = this.busy.signal(),
                    let format = options.format.signal(),
                    let pdf = this.pdf.signal_ref(Option::is_some) => {
                        let missing_pdf = *format == SignatureFormat::Pades && !pdf;
                        (key.is_none() || busy.is_some() || missing_pdf).then_some("")
                    }
                })
                .event(clone!(this => move |_: events::Click| Self::sign(&this)))
            }))
        })
    }

    fn render_cades_options(this: &Rc<Self>) -> Dom {
        html!("div", {
            .style("display", "contents")
            .children(&mut [
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
            ])
        })
    }

    fn render_pades_options(this: &Rc<Self>, pdf: &Rc<PdfDocument>) -> Dom {
        let options = &this.options;
        let info = &pdf.info;
        let mut notes = Vec::new();
        if info.signatures > 0 {
            notes.push(format!(
                "El PDF ya tiene {} firma(s); se añadirá otra sin invalidarlas.",
                info.signatures
            ));
        }
        if info.certification == CertificationLevel::NoChanges {
            notes.push("El PDF está certificado y no admite más firmas.".to_string());
        }

        html!("fieldset", {
            .attr("id", "pades_options")
            .style("margin", "1rem 0")
            .child(html!("legend", { .text("Opciones de la firma PDF") }))
            .children(notes.iter().map(|note| html!("p", { .text(note) })))
            .child(html!("div", {
                .class(&*OPTIONS_CLASS)
                .children(&mut [
                    html!("label", { .attr("for", "sign_reason").text("Motivo") }),
                    text_input("sign_reason", &options.reason),
                    html!("label", { .attr("for", "sign_location").text("Lugar") }),
                    text_input("sign_location", &options.location),
                    html!("label", { .attr("for", "sign_certification").text("Certificación") }),
                    select(
                        "sign_certification",
                        &[
                            ("0", "Firma ordinaria (sin certificar)"),
                            ("1", "Certificar: no se permiten cambios"),
                            ("2", "Certificar: se permite rellenar formularios y firmar"),
                            ("3", "Certificar: formularios, firmas y anotaciones"),
                        ],
                        match options.certification.get() {
                            CertificationLevel::NotCertified => "0",
                            CertificationLevel::NoChanges => "1",
                            CertificationLevel::FormFilling => "2",
                            CertificationLevel::FormFillingAndAnnotations => "3",
                        },
                        clone!(this => move |value| this.options.certification.set(match value.as_str() {
                            "1" => CertificationLevel::NoChanges,
                            "2" => CertificationLevel::FormFilling,
                            "3" => CertificationLevel::FormFillingAndAnnotations,
                            _ => CertificationLevel::NotCertified,
                        })),
                    ),
                    html!("span", { .text("Firma visible") }),
                    checkbox("sign_visible", "Mostrar la firma en una página", &options.visible),
                ])
            }))
            .child_signal(options.visible.signal().map(clone!(this, pdf => move |visible| {
                visible.then(|| Self::render_visible_options(&this, &pdf))
            })))
        })
    }

    fn render_visible_options(this: &Rc<Self>, pdf: &Rc<PdfDocument>) -> Dom {
        let options = &this.options;
        let rubric_picker = FilePicker::new(
            "sign_rubric",
            "Imagen de rúbrica (JPEG o PNG)",
            "image/jpeg,image/png",
            clone!(this => move |result| match result {
                Ok(file) => this.options.rubric.set(Some(Rc::new(file))),
                Err(err) => this.error.set(Some(err)),
            }),
        );

        html!("div", {
            .attr("id", "visible_options")
            .children(&mut [
                PagePlacement::render(&pdf.placement),
                html!("div", {
                    .class(&*OPTIONS_CLASS)
                    .children(&mut [
                        html!("label", { .attr("for", "sign_text").text("Texto") }),
                        html!("textarea" => web_sys::HtmlTextAreaElement, {
                            .attr("id", "sign_text")
                            .attr("rows", "3")
                            .attr("placeholder", "Firmado por $$SUBJECTCN$$\nFecha: $$SIGNDATE=dd/MM/yyyy HH:mm:ss z$$")
                            .prop("value", options.text.get_cloned())
                            .with_node!(element => {
                                .event(clone!(this => move |_: events::Input| this.options.text.set(element.value())))
                            })
                        }),
                        html!("span", {}),
                        html!("small", {
                            .style("color", "var(--muted)")
                            .text("Vacío para el texto de AutoFirma. Admite $$SUBJECTCN$$, $$ISSUERCN$$, $$GIVENNAME$$, \
                                   $$SURNAME$$, $$REASON$$, $$LOCATION$$ y $$SIGNDATE=dd/MM/yyyy$$.")
                        }),
                        html!("label", { .attr("for", "sign_font").text("Letra") }),
                        select(
                            "sign_font",
                            &[("courier", "Courier"), ("helvetica", "Helvetica"), ("times", "Times")],
                            match options.font_family.get() {
                                FontFamily::Courier => "courier",
                                FontFamily::Helvetica => "helvetica",
                                FontFamily::Times => "times",
                            },
                            clone!(this => move |value| this.options.font_family.set(match value.as_str() {
                                "helvetica" => FontFamily::Helvetica,
                                "times" => FontFamily::Times,
                                _ => FontFamily::Courier,
                            })),
                        ),
                        html!("label", { .attr("for", "sign_font_size").text("Tamaño de letra") }),
                        html!("input" => HtmlInputElement, {
                            .attr("type", "number")
                            .attr("id", "sign_font_size")
                            .attr("min", "4")
                            .attr("max", "72")
                            .style("width", "6rem")
                            .prop("value", options.font_size.get().to_string())
                            .with_node!(element => {
                                .event(clone!(this => move |_: events::Change| {
                                    if let Ok(size) = element.value().parse::<f32>() {
                                        this.options.font_size.set(size.clamp(4.0, 72.0));
                                    }
                                }))
                            })
                        }),
                        html!("span", { .text("Rúbrica") }),
                        html!("div", {
                            .style("display", "flex")
                            .style("gap", "0.5rem")
                            .style("align-items", "center")
                            .child(FilePicker::render(&rubric_picker))
                            .child_signal(options.rubric.signal_cloned().map(clone!(this => move |rubric| {
                                rubric.map(|file| html!("span", {
                                    .children(&mut [
                                        html!("span", { .text(&file.name) }),
                                        html!("button", {
                                            .attr("type", "button")
                                            .text("Quitar")
                                            .event(clone!(this => move |_: events::Click| this.options.rubric.set(None)))
                                        }),
                                    ])
                                }))
                            })))
                        }),
                    ])
                }),
            ])
        })
    }

    fn render_triphase_options(this: &Rc<Self>) -> Dom {
        let options = &this.options;
        html!("details", {
            .style("margin", "1rem 0")
            .children(&mut [
                html!("summary", { .text("Firma trifásica (servidor)") }),
                html!("p", {
                    .style("color", "var(--muted)")
                    .text("La firma se compone en un servidor de firma trifásica de AutoFirma; el documento se envía al \
                           servidor y la clave privada no sale de este navegador.")
                }),
                checkbox("sign_triphase", "Firmar a través del servidor", &options.triphase),
                html!("div", {
                    .class(&*OPTIONS_CLASS)
                    .children(&mut [
                        html!("label", { .attr("for", "sign_server").text("Servidor") }),
                        html!("input" => HtmlInputElement, {
                            .attr("type", "url")
                            .attr("id", "sign_server")
                            .attr("placeholder", "https://servidor/afirma-server-triphase-signer/SignatureService")
                            .prop("value", options.server_url.get_cloned())
                            .with_node!(element => {
                                .event(clone!(this => move |_: events::Input| this.options.server_url.set(element.value())))
                            })
                        }),
                    ])
                }),
            ])
        })
    }

    fn render_signature(signature: &Rc<SignatureResult>) -> Dom {
        html!("div", {
            .attr("id", "signature_result")
            .attr("role", "status")
            .style("margin-top", "1rem")
            .children(&mut [
                html!("p", { .text(&signature.description) }),
                html!("button", {
                    .attr("type", "button")
                    .attr("id", "download_signature")
                    .text(&format!("Descargar {}", signature.file_name))
                    .event(clone!(signature => move |_: events::Click| {
                        if let Err(err) = web::download(&signature.data, &signature.file_name, signature.mime_type) {
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

/// `documento.pdf` → `documento_signed.pdf`, as AutoFirma names signed PDFs.
fn signed_pdf_name(name: &str) -> String {
    let stem = name.len().checked_sub(4).filter(|&i| {
        name.get(i..)
            .is_some_and(|extension| extension.eq_ignore_ascii_case(".pdf"))
    });
    match stem {
        Some(stem) => format!("{}_signed.pdf", &name[..stem]),
        None => format!("{name}_signed.pdf"),
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

fn text_input(id: &str, value: &Mutable<String>) -> Dom {
    html!("input" => HtmlInputElement, {
        .attr("type", "text")
        .attr("id", id)
        .prop("value", value.get_cloned())
        .with_node!(element => {
            .event(clone!(value => move |_: events::Input| value.set(element.value())))
        })
    })
}

fn checkbox(id: &str, label: &str, value: &Mutable<bool>) -> Dom {
    html!("label", {
        .style("display", "flex")
        .style("gap", "0.4rem")
        .style("align-items", "center")
        .children(&mut [
            html!("input" => HtmlInputElement, {
                .attr("type", "checkbox")
                .attr("id", id)
                .prop("checked", value.get())
                .with_node!(element => {
                    .event(clone!(value => move |_: events::Change| value.set(element.checked())))
                })
            }),
            html!("span", { .text(label) }),
        ])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_pdf_names() {
        assert_eq!(signed_pdf_name("contrato.PDF"), "contrato_signed.pdf");
        assert_eq!(signed_pdf_name("informe"), "informe_signed.pdf");
        assert_eq!(signed_pdf_name("ñ.pdf"), "ñ_signed.pdf");
    }
}
