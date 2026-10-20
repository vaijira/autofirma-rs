use std::rc::Rc;

use afirma_core::{
    algorithm::KeyType,
    cades::{CadesParams, SignatureMode},
    digest::DigestAlgorithm,
    facturae::{FacturaeParams, FacturaeRole},
    format::{DataKind, SignatureFormat},
    job::{AsicSignature, FileAnalysis, Job, JobOutput, KeyEntry},
    multisign::{
        CounterSignTarget, MultiSignOperation, MultiSignParams, SignedKind, multisigned_file_name,
    },
    odf::OdfParams,
    ooxml::OoxmlParams,
    pades::{CertificationLevel, Font, FontFamily, PadesParams, SignaturePages, VisibleSignature},
    params::ExtraParams,
    policy::PolicyPreset,
    triphase::{self, CryptoOperation, TriphaseFormat, TriphaseRequest},
    xades::{ProductionPlace, XadesFormat, XadesParams},
};
use anyhow::anyhow;
use dominator::{Dom, clone, events, html, with_node};
use futures_signals::{
    map_ref,
    signal::{Mutable, SignalExt, always},
};
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlInputElement;

use super::document::{Document, PdfDocument};
use crate::{
    app::App,
    components::{
        file_picker::{FilePicker, LoadedFile},
        form::{
            checkbox, choice, differs, field, group, hint, row, text_area, text_input, unmarked,
            url_input,
        },
        page_placement::PagePlacement,
    },
    css::{
        ACTIONS_CLASS, CARD_CLASS, CARD_TITLE_CLASS, CHIP_CLASS, CHIP_MODIFIED_CLASS, CHIPS_CLASS,
        DISCLOSURE_CLASS, ERROR_CLASS, MUTED_CLASS, STATUS_CLASS, VERDICT_CLASS,
    },
    prefs::{PdfTimestamp, Preferences},
    state::{now, utc_offset_minutes},
    utils::{format_size, http, web},
};

/// A signature ready to download.
#[derive(Debug)]
struct SignatureResult {
    data: Vec<u8>,
    file_name: String,
    mime_type: &'static str,
    description: String,
}

/// Options that depend on this file. The ones shared by every signature are
/// [`Preferences`].
#[derive(Debug)]
struct Options {
    format: Mutable<SignatureFormat>,
    /// Co-signature or counter-signature of a signature; `None` signs the file.
    operation: Mutable<Option<MultiSignOperation>>,
    /// CAdES or XAdES signature inside an ASiC-S container.
    asic: Mutable<bool>,
    /// Role of the signer of a FacturaE invoice.
    role: Mutable<FacturaeRole>,
    reason: Mutable<String>,
    certification: Mutable<CertificationLevel>,
    rubric: Mutable<Option<Rc<LoadedFile>>>,
    /// Signed data of an explicit CAdES signature to co-sign.
    cosign_data: Mutable<Option<Rc<LoadedFile>>>,
}

/// Signs one file. Every option starts at AutoFirma's default for the file,
/// and the summary says what will be done before the user changes anything.
#[derive(Debug)]
pub struct SignPanel {
    app: Rc<App>,
    file: Rc<LoadedFile>,
    analysis: FileAnalysis,
    pdf: Mutable<Option<Rc<PdfDocument>>>,
    /// Format AutoFirma would use: the detected one, or CAdES for a PDF that
    /// cannot be read.
    default_format: Mutable<SignatureFormat>,
    /// A signature is co-signed (counter-signed, for invoices) by default.
    default_operation: Option<MultiSignOperation>,
    options: Options,
    /// Why the default format changed.
    fallback_note: Mutable<Option<String>>,
    signature: Mutable<Option<Rc<SignatureResult>>>,
    busy: Mutable<Option<&'static str>>,
    error: Mutable<Option<String>>,
}

impl SignPanel {
    pub fn new(
        app: &Rc<App>,
        file: Rc<LoadedFile>,
        analysis: FileAnalysis,
        pdf: Mutable<Option<Rc<PdfDocument>>>,
    ) -> Rc<Self> {
        let default_operation = match analysis.signed {
            Some(SignedKind::Cades | SignedKind::Xades | SignedKind::Asic) => {
                Some(MultiSignOperation::Cosign)
            }
            Some(SignedKind::Facturae) => {
                Some(MultiSignOperation::Countersign(CounterSignTarget::Leafs))
            }
            _ => None,
        };
        Rc::new(Self {
            app: app.clone(),
            file,
            default_format: Mutable::new(analysis.default_format),
            options: Options {
                format: Mutable::new(analysis.default_format),
                operation: Mutable::new(default_operation),
                asic: Mutable::new(false),
                role: Mutable::new(FacturaeRole::Issuer),
                reason: Mutable::new(String::new()),
                certification: Mutable::new(CertificationLevel::NotCertified),
                rubric: Mutable::new(None),
                cosign_data: Mutable::new(None),
            },
            analysis,
            pdf,
            default_operation,
            fallback_note: Mutable::new(None),
            signature: Mutable::new(None),
            busy: Mutable::new(None),
            error: Mutable::new(None),
        })
    }

    /// The default format cannot be used (`reason`): `format` becomes the default.
    pub fn fall_back(&self, format: SignatureFormat, reason: String) {
        self.default_format.set(format);
        self.options.format.set(format);
        self.fallback_note.set(Some(format!(
            "{reason}. Se firmará en {} en su lugar.",
            format.name()
        )));
    }

    fn prefs(&self) -> &Preferences {
        &self.app.prefs
    }

    fn is_xml(&self) -> bool {
        self.analysis.kind == DataKind::Xml
    }

    /// Back to the defaults: this file's and the shared ones.
    fn reset(&self) {
        self.prefs().reset();
        let options = &self.options;
        options.format.set_neq(self.default_format.get());
        options.operation.set_neq(self.default_operation);
        options.asic.set_neq(false);
        options.role.set_neq(FacturaeRole::Issuer);
        options.reason.set_neq(String::new());
        options
            .certification
            .set_neq(CertificationLevel::NotCertified);
        options.rubric.set(None);
        options.cosign_data.set(None);
    }

    /// The XAdES layout to use: enveloped only exists for XML.
    fn xades_format(&self) -> XadesFormat {
        match self.prefs().xades_format.get() {
            XadesFormat::Enveloped if !self.is_xml() => XadesFormat::Enveloping,
            format => format,
        }
    }

    fn pades_params(&self, pdf: &PdfDocument) -> PadesParams {
        let prefs = self.prefs();
        let options = &self.options;
        let text = |value: &Mutable<String>| {
            let value = value.get_cloned();
            (!value.trim().is_empty()).then_some(value)
        };
        let visible = prefs.visible.get().then(|| VisibleSignature {
            pages: SignaturePages::Pages(vec![pdf.placement.page.get() as i32]),
            rect: pdf.placement.rect.get(),
            text: text(&prefs.visible_text),
            font: Font {
                family: prefs.font_family.get(),
                size: prefs.font_size.get(),
                ..Font::default()
            },
            image: options.rubric.get_cloned().map(|file| file.data.clone()),
            obfuscate: None,
            mask: None,
        });
        PadesParams {
            digest: prefs.digest.get(),
            policy: prefs
                .policy
                .get()
                .map(|preset| preset.policy(SignatureFormat::Pades)),
            signing_time: now(),
            utc_offset_minutes: utc_offset_minutes(),
            reason: text(&options.reason),
            location: text(&prefs.location),
            contact: None,
            certification: options.certification.get(),
            visible,
            password: pdf.password.clone(),
            allow_signing_certified: false,
            // Room for the signature timestamp, added to the CMS afterwards.
            reserved_size: (prefs.timestamp.get()
                && prefs.pdf_timestamp.get() != PdfTimestamp::Document)
                .then_some(32 * 1024),
        }
    }

    fn production_place(&self) -> ProductionPlace {
        let city = self.prefs().location.get_cloned();
        ProductionPlace {
            city: (!city.trim().is_empty()).then(|| city.trim().to_string()),
            ..ProductionPlace::default()
        }
    }

    fn xades_params(&self) -> XadesParams {
        XadesParams {
            digest: self.prefs().digest.get(),
            format: self.xades_format(),
            policy: self
                .prefs()
                .policy
                .get()
                .map(|preset| preset.policy(SignatureFormat::Xades)),
            signing_time: now(),
            utc_offset_minutes: utc_offset_minutes(),
            production_place: self.production_place(),
            claimed_roles: Vec::new(),
        }
    }

    fn facturae_params(&self) -> FacturaeParams {
        FacturaeParams {
            digest: self.prefs().digest.get(),
            signing_time: now(),
            utc_offset_minutes: utc_offset_minutes(),
            role: self.options.role.get(),
            production_place: self.production_place(),
        }
    }

    fn multisign_params(&self) -> MultiSignParams {
        MultiSignParams {
            digest: self.prefs().digest.get(),
            mode: self.prefs().cades_mode.get(),
            policy: self.prefs().policy.get(),
            signing_time: now(),
            utc_offset_minutes: utc_offset_minutes(),
            production_place: self.production_place(),
            claimed_roles: Vec::new(),
        }
    }

    fn cades_params(&self) -> CadesParams {
        CadesParams {
            digest: self.prefs().digest.get(),
            mode: self.prefs().cades_mode.get(),
            policy: self
                .prefs()
                .policy
                .get()
                .map(|preset| preset.policy(SignatureFormat::Cades)),
            signing_time: now(),
            content_description: content_description(self.analysis.kind),
        }
    }

    fn sign(this: &Rc<Self>) {
        let Some(entry) = this.app.keys.selected_entry() else {
            this.app.certificates.show();
            return;
        };
        let format = this.options.format.get();
        let operation = this.options.operation.get();
        let pdf = this.pdf.get_cloned();
        let triphase = this.prefs().triphase.get();
        let file = this.file.clone();

        this.error.set(None);
        this.signature.set(None);
        this.busy.set(Some("Firmando…"));
        spawn_local(clone!(this => async move {
            let result = if let Some(operation) = operation {
                Self::multisign(&this, &entry, operation).await
            } else { match (format, &pdf) {
                (SignatureFormat::Pades, Some(pdf)) => {
                    let params = this.pades_params(pdf);
                    if triphase {
                        let extra = ExtraParams::from(&params);
                        Self::sign_triphase(&this, &entry, CryptoOperation::Sign, TriphaseFormat::Pades, &file.data, params.digest, extra).await
                    } else {
                        let job = Job::SignPades { data: file.data.clone(), key_id: entry.id, params: Box::new(params) };
                        Self::run_signature_job(&this, job).await
                    }
                    .map(|data| SignatureResult {
                        description: format!("PDF firmado en PAdES ({}).", format_size(data.len())),
                        data,
                        file_name: SignatureFormat::Pades.signed_file_name(&file.name),
                        mime_type: "application/pdf",
                    })
                }
                (SignatureFormat::Pades, None) => Err(anyhow!("Abra antes el PDF")),
                (format @ (SignatureFormat::Odf | SignatureFormat::Ooxml), _) => {
                    if triphase {
                        Err(anyhow!("Los documentos ODF y OOXML no se pueden firmar en un servidor trifásico"))
                    } else {
                        let digest = this.prefs().digest.get();
                        let job = if format == SignatureFormat::Odf {
                            Job::SignOdf {
                                data: file.data.clone(),
                                key_id: entry.id,
                                params: OdfParams {
                                    digest,
                                    signing_time: now(),
                                    utc_offset_minutes: utc_offset_minutes(),
                                },
                            }
                        } else {
                            Job::SignOoxml {
                                data: file.data.clone(),
                                key_id: entry.id,
                                params: Box::new(OoxmlParams {
                                    digest,
                                    utc_offset_minutes: utc_offset_minutes(),
                                    production_place: this.production_place(),
                                    ..OoxmlParams::new(now())
                                }),
                            }
                        };
                        Self::run_signature_job(&this, job).await
                    }
                    .map(|data| SignatureResult {
                        description: format!("Documento firmado en {} ({}).", format.name(), format_size(data.len())),
                        file_name: format.signed_file_name(&file.name),
                        mime_type: if format == SignatureFormat::Odf { "application/vnd.oasis.opendocument" } else { "application/zip" },
                        data,
                    })
                }
                (SignatureFormat::Facturae, _) => {
                    let params = this.facturae_params();
                    if triphase {
                        let extra = ExtraParams::from(&params);
                        Self::sign_triphase(&this, &entry, CryptoOperation::Sign, TriphaseFormat::Facturae, &file.data, params.digest, extra).await
                    } else {
                        let job = Job::SignFacturae { data: file.data.clone(), key_id: entry.id, params };
                        Self::run_signature_job(&this, job).await
                    }
                    .map(|data| SignatureResult {
                        description: format!("Factura electrónica firmada ({}).", format_size(data.len())),
                        data,
                        file_name: SignatureFormat::Facturae.signed_file_name(&file.name),
                        mime_type: "text/xml",
                    })
                }
                (format, _) if this.options.asic.get() => {
                    let signature = if format == SignatureFormat::Xades {
                        AsicSignature::Xades(this.xades_params())
                    } else {
                        AsicSignature::Cades(this.cades_params())
                    };
                    if triphase {
                        Err(anyhow!("Los contenedores ASiC-S no se pueden firmar en un servidor trifásico"))
                    } else {
                        let job = Job::SignAsic {
                            data: file.data.clone(),
                            file_name: Some(file.name.clone()),
                            key_id: entry.id,
                            params: Box::new(signature),
                        };
                        Self::run_signature_job(&this, job).await
                    }
                    .map(|data| SignatureResult {
                        description: format!(
                            "Contenedor ASiC-S con firma {} generado ({}).",
                            format.name(),
                            format_size(data.len())
                        ),
                        data,
                        file_name: format!("{}.asics", file.name),
                        mime_type: "application/vnd.etsi.asic-s+zip",
                    })
                }
                (SignatureFormat::Xades, _) => {
                    let params = this.xades_params();
                    if triphase {
                        let extra = ExtraParams::from(&params);
                        Self::sign_triphase(&this, &entry, CryptoOperation::Sign, TriphaseFormat::Xades, &file.data, params.digest, extra).await
                    } else {
                        let job = Job::SignXades { data: file.data.clone(), key_id: entry.id, params: Box::new(params) };
                        Self::run_signature_job(&this, job).await
                    }
                    .map(|data| SignatureResult {
                        description: format!("Firma XAdES generada ({}).", format_size(data.len())),
                        data,
                        file_name: SignatureFormat::Xades.signed_file_name(&file.name),
                        mime_type: "text/xml",
                    })
                }
                _ => {
                    let params = this.cades_params();
                    if triphase {
                        let extra = ExtraParams::from(&params);
                        Self::sign_triphase(&this, &entry, CryptoOperation::Sign, TriphaseFormat::Cades, &file.data, params.digest, extra).await
                    } else {
                        let job = Job::SignCades { data: file.data.clone(), key_id: entry.id, params };
                        Self::run_signature_job(&this, job).await
                    }
                    .map(|data| SignatureResult {
                        description: format!("Firma CAdES generada ({}).", format_size(data.len())),
                        data,
                        file_name: SignatureFormat::Cades.signed_file_name(&file.name),
                        mime_type: "application/pkcs7-signature",
                    })
                }
            } };
            let stamp = this.prefs().timestamp.get() && stamps(format, operation);
            let result = match result {
                Ok(signature) if stamp => {
                    Self::add_timestamps(&this, signature, format, pdf.as_deref()).await
                }
                other => other,
            };
            match result {
                Ok(signature) => this.signature.set(Some(Rc::new(signature))),
                Err(err) => this.error.set(Some(err.to_string())),
            }
            this.busy.set(None);
        }));
    }

    /// Adds timestamps from the TSA to a new signature: signature timestamps
    /// and, for PDFs, a document timestamp if requested.
    async fn add_timestamps(
        this: &Rc<Self>,
        mut signature: SignatureResult,
        format: SignatureFormat,
        pdf: Option<&PdfDocument>,
    ) -> anyhow::Result<SignatureResult> {
        let prefs = this.prefs();
        let url = prefs.tsa_url.get_cloned().trim().to_string();
        if url.is_empty() {
            return Err(anyhow!(
                "Indique la dirección del servidor de sellado de tiempo (TSA) en «Personalizar»"
            ));
        }
        let policy = Some(prefs.tsa_policy.get_cloned().trim().to_string())
            .filter(|policy| !policy.is_empty());
        let digest = prefs.digest.get();
        let kind = if format == SignatureFormat::Pades {
            prefs.pdf_timestamp.get()
        } else {
            PdfTimestamp::Signature
        };

        this.busy.set(Some("Obteniendo el sello de tiempo…"));
        if kind != PdfTimestamp::Document {
            let requests = match this
                .app
                .worker
                .run(Job::TimestampRequests {
                    signed: signature.data.clone(),
                    digest,
                    policy: policy.clone(),
                })
                .await?
            {
                JobOutput::TimestampRequests(requests) => requests,
                other => return Err(anyhow!("Respuesta inesperada del worker: {other:?}")),
            };
            let mut responses = Vec::with_capacity(requests.len());
            for request in &requests {
                responses.push(serde_bytes::ByteBuf::from(
                    http::post_timestamp_query(&url, request).await?,
                ));
            }
            signature.data = Self::run_signature_job(
                this,
                Job::AddTimestamps {
                    signed: signature.data,
                    digest,
                    responses,
                },
            )
            .await?;
        }
        if kind != PdfTimestamp::Signature {
            let (prepared, request) = match this
                .app
                .worker
                .run(Job::PrepareDocumentTimestamp {
                    pdf: signature.data,
                    password: pdf.and_then(|pdf| pdf.password.clone()),
                    digest,
                    policy,
                })
                .await?
            {
                JobOutput::DocumentTimestamp { prepared, request } => (prepared, request),
                other => return Err(anyhow!("Respuesta inesperada del worker: {other:?}")),
            };
            let response = http::post_timestamp_query(&url, &request).await?;
            signature.data = Self::run_signature_job(
                this,
                Job::AddDocumentTimestamp {
                    prepared,
                    digest,
                    response,
                },
            )
            .await?;
        }
        // "Firma XAdES generada (5 KB)." → "Firma XAdES generada con sello de tiempo (9 KB)."
        let what = signature
            .description
            .split(" (")
            .next()
            .unwrap_or_default()
            .to_string();
        signature.description = format!(
            "{what} con sello de tiempo ({}).",
            format_size(signature.data.len())
        );
        Ok(signature)
    }

    async fn run_signature_job(this: &Rc<Self>, job: Job) -> anyhow::Result<Vec<u8>> {
        match this.app.worker.run(job).await? {
            JobOutput::Signature(data) => Ok(data),
            other => Err(anyhow!("Respuesta inesperada del worker: {other:?}")),
        }
    }

    /// Co-signature or counter-signature of the file, a signature.
    async fn multisign(
        this: &Rc<Self>,
        entry: &KeyEntry,
        operation: MultiSignOperation,
    ) -> anyhow::Result<SignatureResult> {
        let kind = this
            .analysis
            .signed
            .ok_or_else(|| anyhow!("El fichero no es una firma"))?;
        let params = this.multisign_params();
        let data = if this.prefs().triphase.get() {
            let (format, policy_format) = match kind {
                SignedKind::Cades => (TriphaseFormat::Cades, SignatureFormat::Cades),
                SignedKind::Xades | SignedKind::Facturae => {
                    (TriphaseFormat::Xades, SignatureFormat::Xades)
                }
                _ => {
                    return Err(anyhow!(
                        "Esta firma no se puede ampliar en un servidor trifásico"
                    ));
                }
            };
            let crypto_operation = match operation {
                MultiSignOperation::Cosign => CryptoOperation::Cosign,
                MultiSignOperation::Countersign(_) => CryptoOperation::Countersign,
            };
            let extra = ExtraParams::multisign(&params, operation, policy_format);
            Self::sign_triphase(
                this,
                entry,
                crypto_operation,
                format,
                &this.file.data,
                params.digest,
                extra,
            )
            .await?
        } else {
            let job = Job::MultiSign {
                signature: this.file.data.clone(),
                data: this
                    .options
                    .cosign_data
                    .get_cloned()
                    .map(|file| file.data.clone()),
                operation,
                key_id: entry.id,
                params: Box::new(params),
            };
            Self::run_signature_job(this, job).await?
        };
        let (what, format) = match kind {
            SignedKind::Cades => ("CAdES", "application/pkcs7-signature"),
            SignedKind::Xades => ("XAdES", "text/xml"),
            SignedKind::Facturae => ("de la factura", "text/xml"),
            SignedKind::Asic => ("ASiC-S", "application/vnd.etsi.asic-s+zip"),
            _ => ("", "application/octet-stream"),
        };
        Ok(SignatureResult {
            description: format!(
                "{} {what} generada ({}).",
                match operation {
                    MultiSignOperation::Cosign => "Cofirma",
                    MultiSignOperation::Countersign(_) => "Contrafirma",
                },
                format_size(data.len())
            ),
            file_name: multisigned_file_name(&this.file.name, operation),
            mime_type: format,
            data,
        })
    }

    /// Triphase signature: the server builds the signature, the key (in the
    /// worker) only signs the pre-signatures.
    async fn sign_triphase(
        this: &Rc<Self>,
        entry: &KeyEntry,
        operation: CryptoOperation,
        format: TriphaseFormat,
        document: &[u8],
        digest: DigestAlgorithm,
        params: ExtraParams,
    ) -> anyhow::Result<Vec<u8>> {
        let url = this.prefs().server_url.get_cloned().trim().to_string();
        if url.is_empty() {
            return Err(anyhow!(
                "Indique la dirección del servidor de firma trifásica en «Personalizar»"
            ));
        }
        let key_type: KeyType = entry
            .certificate
            .key_type
            .ok_or_else(|| anyhow!("Tipo de clave no soportado"))?;
        let request = TriphaseRequest {
            format,
            operation,
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
            .app
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
        html!("section", {
            .class(&*CARD_CLASS)
            .attr("id", "sign_card")
            .attr("aria-labelledby", "sign_title")
            .child_signal(this.signature.signal_cloned().map(clone!(this => move |signature| Some(match signature {
                Some(signature) => Self::render_done(&this, &signature),
                None => Self::render_form(&this),
            }))))
        })
    }

    fn title(&self) -> &'static str {
        match self.analysis.signed {
            Some(_) => "Añadir su firma",
            None => "Firmar",
        }
    }

    fn render_form(this: &Rc<Self>) -> Dom {
        let note = match this.analysis.signed {
            Some(SignedKind::Pdf | SignedKind::Odf | SignedKind::Ooxml) => Some(
                "El documento ya está firmado: su firma se añadirá sin invalidar las anteriores.",
            ),
            Some(SignedKind::Cades | SignedKind::Xades | SignedKind::Asic) => Some(
                "El fichero es una firma. Por defecto se cofirma: usted firma los mismos datos que los \
                 demás firmantes.",
            ),
            Some(SignedKind::Facturae) => Some(
                "La factura ya está firmada. Por defecto se contrafirma: usted firma la última firma.",
            ),
            None => None,
        };

        html!("div", {
            .child(html!("h2", { .attr("id", "sign_title").class(&*CARD_TITLE_CLASS).text(this.title()) }))
            .apply_if(note.is_some(), |dom| dom.child(html!("p", {
                .attr("id", "sign_note")
                .style("margin-top", "0")
                .text(note.unwrap_or_default())
            })))
            .child_signal(this.fallback_note.signal_cloned().map(|note| note.map(|note| html!("p", {
                .attr("id", "sign_fallback")
                .class(&*ERROR_CLASS)
                .style("margin", "0 0 0.75rem")
                .text(&note)
            }))))
            .children(&mut [
                html!("p", { .class(&*MUTED_CLASS).style("margin-bottom", "0.4rem").text("Se firmará así:") }),
                Self::render_summary(this),
                Self::render_certificate(this),
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
                    .attr("id", "sign_button")
                    .class("primary")
                    .style("min-width", "10rem")
                    .text_signal(map_ref! {
                        let key = this.app.keys.selected.signal(),
                        let operation = this.options.operation.signal() => {
                            match (key, operation) {
                                (None, _) => "Elegir certificado y firmar",
                                (_, Some(MultiSignOperation::Cosign)) => "Cofirmar",
                                (_, Some(MultiSignOperation::Countersign(_))) => "Contrafirmar",
                                (_, None) => "Firmar",
                            }
                        }
                    })
                    .attr_signal("disabled", map_ref! {
                        let busy = this.busy.signal(),
                        let format = this.options.format.signal(),
                        let operation = this.options.operation.signal(),
                        let pdf = this.pdf.signal_ref(Option::is_some) => {
                            let missing_pdf = operation.is_none() && *format == SignatureFormat::Pades && !pdf;
                            (busy.is_some() || missing_pdf).then_some("")
                        }
                    })
                    .event(clone!(this => move |_: events::Click| Self::sign(&this)))
                }))
            }))
        })
    }

    /// One chip per setting, in plain words; changed ones stand out.
    fn render_summary(this: &Rc<Self>) -> Dom {
        let options = &this.options;
        let prefs = this.prefs();
        let signed = this.analysis.signed;
        let is_xml = this.is_xml();
        let default_operation = this.default_operation;

        html!("ul", {
            .attr("id", "sign_summary")
            .attr("aria-label", "Opciones de la firma")
            .class(&*CHIPS_CLASS)
            .child_signal(map_ref! {
                let format = options.format.signal(),
                let default_format = this.default_format.signal(),
                let operation = options.operation.signal(),
                let asic = options.asic.signal(),
                let role = options.role.signal(),
                let mode = prefs.cades_mode.signal(),
                let xades = prefs.xades_format.signal() => {
                    let xades = match xades {
                        XadesFormat::Enveloped if !is_xml => XadesFormat::Enveloping,
                        xades => *xades,
                    };
                    let text = kind_text(*format, *operation, signed, *asic, *role, *mode, xades);
                    let modified = format != default_format
                        || *operation != default_operation
                        || *asic
                        || (*format == SignatureFormat::Cades && *mode != SignatureMode::Explicit)
                        || (*format == SignatureFormat::Xades && xades != XadesFormat::Enveloping);
                    Some(chip("summary_format", &text, modified))
                }
            })
            .child_signal(prefs.digest.signal().map(|digest| {
                Some(chip("summary_digest", digest.name(), digest != DigestAlgorithm::Sha512))
            }))
            .child_signal(map_ref! {
                let format = options.format.signal(),
                let operation = options.operation.signal(),
                let policy = prefs.policy.signal() => {
                    has_policy(*format, *operation).then(|| match policy {
                        None => chip("summary_policy", "Sin política de firma", false),
                        Some(PolicyPreset::Age19) => chip("summary_policy", "Política AGE v1.9", true),
                        Some(PolicyPreset::Age18) => chip("summary_policy", "Política AGE v1.8", true),
                    })
                }
            })
            .child_signal(map_ref! {
                let pades = map_ref! {
                    let format = options.format.signal(),
                    let operation = options.operation.signal() => {
                        *format == SignatureFormat::Pades && operation.is_none()
                    }
                },
                let visible = prefs.visible.signal(),
                let page = this.pdf.signal_cloned().switch(|pdf| {
                    pdf.map(|pdf| pdf.placement.page.clone()).unwrap_or_else(|| Mutable::new(0)).signal()
                }) => {
                    pades.then(|| if *visible {
                        chip("summary_visible", &format!("Visible en la página {page}"), true)
                    } else {
                        chip("summary_visible", "Firma invisible", false)
                    })
                }
            })
            .child_signal(map_ref! {
                let format = options.format.signal(),
                let operation = options.operation.signal(),
                let certification = options.certification.signal() => {
                    (*format == SignatureFormat::Pades
                        && operation.is_none()
                        && *certification != CertificationLevel::NotCertified)
                        .then(|| chip("summary_certification", "Certifica el documento", true))
                }
            })
            .child_signal(map_ref! {
                let format = options.format.signal(),
                let operation = options.operation.signal(),
                let timestamp = prefs.timestamp.signal() => {
                    stamps(*format, *operation).then(|| if *timestamp {
                        chip("summary_timestamp", "Con sello de tiempo", true)
                    } else {
                        chip("summary_timestamp", "Sin sello de tiempo", false)
                    })
                }
            })
            .child_signal(prefs.triphase.signal().map(|triphase| {
                triphase.then(|| chip("summary_triphase", "En el servidor trifásico", true))
            }))
        })
    }

    fn render_certificate(this: &Rc<Self>) -> Dom {
        html!("p", {
            .attr("id", "sign_certificate")
            .class(&*MUTED_CLASS)
            .style("margin-top", "0.75rem")
            .children_signal_vec(this.app.keys.selected_signal().map(clone!(this => move |entry: Option<KeyEntry>| {
                let change = html!("button", {
                    .attr("type", "button")
                    .class("link")
                    .text(if entry.is_some() { "Cambiar" } else { "Importar certificado" })
                    .event(clone!(this => move |_: events::Click| this.app.certificates.show()))
                });
                match entry {
                    Some(entry) => vec![
                        html!("span", { .text("Con el certificado de ") }),
                        html!("strong", { .text(&entry.certificate.subject_cn) }),
                        html!("span", { .text(" · ") }),
                        change,
                    ],
                    None => vec![html!("span", { .text("Aún no ha importado ningún certificado. ") }), change],
                }
            })).to_signal_vec())
        })
    }

    /// Every option, grouped, behind "Personalizar".
    fn render_customize(this: &Rc<Self>) -> Dom {
        let options = &this.options;
        html!("details", {
            .attr("id", "sign_customize")
            .class(&*DISCLOSURE_CLASS)
            .child(html!("summary", { .style("font-weight", "600").text("Personalizar") }))
            .child_signal(map_ref! {
                let format = options.format.signal(),
                let operation = options.operation.signal() => (*format, *operation)
            }.map(clone!(this => move |(format, operation)| Some(html!("div", {
                .child(Self::render_kind_options(&this, format, operation))
                .child(Self::render_general_options(&this, format, operation))
                .apply_if(format == SignatureFormat::Pades && operation.is_none(), |dom| {
                    dom.child_signal(this.pdf.signal_cloned().map(clone!(this => move |pdf| {
                        pdf.map(|pdf| Self::render_pades_options(&this, &pdf))
                    })))
                })
                .apply_if(stamps(format, operation), |dom| {
                    dom.child(Self::render_timestamp_options(&this, format == SignatureFormat::Pades && operation.is_none()))
                })
                .child(Self::render_triphase_options(&this))
            })))))
            .child(html!("div", {
                .class(&*ACTIONS_CLASS)
                .style("justify-content", "flex-start")
                .child(html!("button", {
                    .attr("type", "button")
                    .attr("id", "sign_reset")
                    .class("link")
                    .text("Restablecer los valores predeterminados")
                    .event(clone!(this => move |_: events::Click| this.reset()))
                }))
            }))
        })
    }

    /// What to sign and how: operation, format and its layout.
    fn render_kind_options(
        this: &Rc<Self>,
        format: SignatureFormat,
        operation: Option<MultiSignOperation>,
    ) -> Dom {
        let options = &this.options;
        let prefs = this.prefs();
        let signed = this.analysis.signed;
        let multisign = matches!(
            signed,
            Some(SignedKind::Cades | SignedKind::Xades | SignedKind::Facturae | SignedKind::Asic)
        );
        let mut rows: Vec<Dom> = Vec::new();

        if multisign {
            let mut operations = Vec::new();
            if signed != Some(SignedKind::Facturae) {
                operations.push((
                    Some(MultiSignOperation::Cosign),
                    "cosign",
                    "Cofirmar (firmar los mismos datos)",
                ));
            }
            operations.extend([
                (
                    Some(MultiSignOperation::Countersign(CounterSignTarget::Leafs)),
                    "leafs",
                    "Contrafirmar las últimas firmas",
                ),
                (
                    Some(MultiSignOperation::Countersign(CounterSignTarget::Tree)),
                    "tree",
                    "Contrafirmar todas las firmas",
                ),
                (None, "sign", "Firmar el fichero como datos (firma nueva)"),
            ]);
            rows.extend(field(
                "sign_operation",
                "Operación",
                differs(&options.operation, this.default_operation),
                choice("sign_operation", &options.operation, &operations),
            ));
        }

        if operation.is_none() {
            let formats = formats_for(this.analysis.default_format);
            rows.extend(field(
                "sign_format",
                "Formato",
                differs(&options.format, this.default_format.get()),
                choice("sign_format", &options.format, formats),
            ));
            match format {
                SignatureFormat::Cades => {
                    rows.extend(field(
                        "sign_mode",
                        "Datos",
                        prefs.cades_mode.modified_signal(),
                        choice(
                            "sign_mode",
                            &prefs.cades_mode,
                            &[
                                (
                                    SignatureMode::Explicit,
                                    "explicit",
                                    "Fuera de la firma (explícita)",
                                ),
                                (
                                    SignatureMode::Implicit,
                                    "implicit",
                                    "Dentro de la firma (implícita)",
                                ),
                            ],
                        ),
                    ));
                    rows.push(hint(
                        "Explícita: guarde el fichero original junto a la firma .csig.",
                    ));
                }
                SignatureFormat::Xades => {
                    let mut layouts = vec![(
                        XadesFormat::Enveloping,
                        "enveloping",
                        "Envolvente (los datos dentro de la firma)",
                    )];
                    if this.is_xml() {
                        layouts.push((
                            XadesFormat::Enveloped,
                            "enveloped",
                            "Envuelta (la firma dentro del XML)",
                        ));
                    }
                    layouts.push((
                        XadesFormat::Detached,
                        "detached",
                        "Separada (datos y firma en un XML nuevo)",
                    ));
                    rows.extend(field(
                        "sign_xades_format",
                        "Tipo",
                        prefs.xades_format.modified_signal(),
                        choice("sign_xades_format", &prefs.xades_format, &layouts),
                    ));
                }
                SignatureFormat::Facturae => rows.extend(field(
                    "sign_role",
                    "Firma como",
                    differs(&options.role, FacturaeRole::Issuer),
                    choice(
                        "sign_role",
                        &options.role,
                        &[
                            (FacturaeRole::Issuer, "emisor", "Emisor"),
                            (FacturaeRole::Receiver, "receptor", "Receptor"),
                            (FacturaeRole::ThirdParty, "tercero", "Tercero"),
                        ],
                    ),
                )),
                _ => {}
            }
            if matches!(format, SignatureFormat::Cades | SignatureFormat::Xades) {
                rows.extend(row(
                    "Contenedor",
                    options.asic.signal(),
                    checkbox(
                        "sign_asic",
                        "ASiC-S (fichero y firma en un ZIP)",
                        &options.asic,
                    ),
                ));
            }
        }

        if signed == Some(SignedKind::Cades) && operation == Some(MultiSignOperation::Cosign) {
            let data_picker = FilePicker::new(
                "sign_cosign_data",
                "Seleccionar los datos firmados",
                "*/*",
                clone!(this => move |result| match result {
                    Ok(file) => this.options.cosign_data.set(Some(Rc::new(file))),
                    Err(err) => this.error.set(Some(err)),
                }),
            );
            rows.extend(row(
                "Datos firmados",
                unmarked(),
                html!("div", {
                    .style("display", "flex")
                    .style("flex-wrap", "wrap")
                    .style("gap", "0.5rem")
                    .style("align-items", "center")
                    .child(FilePicker::render(&data_picker))
                    .child_signal(options.cosign_data.signal_cloned().map(clone!(this => move |data| {
                        data.map(|file| html!("span", {
                            .children(&mut [
                                html!("span", { .attr("id", "sign_cosign_data_name").text(&file.name) }),
                                html!("button", {
                                    .attr("type", "button")
                                    .class("link")
                                    .text("Quitar")
                                    .event(clone!(this => move |_: events::Click| this.options.cosign_data.set(None)))
                                }),
                            ])
                        }))
                    })))
                }),
            ));
            rows.push(hint(
                "Solo hacen falta si la firma no incluye los datos y se usa otro algoritmo.",
            ));
        }

        group("Tipo de firma", &mut rows)
    }

    /// Algorithm, policy and place.
    fn render_general_options(
        this: &Rc<Self>,
        format: SignatureFormat,
        operation: Option<MultiSignOperation>,
    ) -> Dom {
        let prefs = this.prefs();
        let mut rows: Vec<Dom> = Vec::new();
        rows.extend(field(
            "sign_digest",
            "Algoritmo",
            prefs.digest.modified_signal(),
            choice(
                "sign_digest",
                &prefs.digest,
                &[
                    (DigestAlgorithm::Sha512, "sha512", "SHA-512 (recomendado)"),
                    (DigestAlgorithm::Sha384, "sha384", "SHA-384"),
                    (DigestAlgorithm::Sha256, "sha256", "SHA-256"),
                ],
            ),
        ));
        if has_policy(format, operation) {
            rows.extend(field(
                "sign_policy",
                "Política de firma",
                prefs.policy.modified_signal(),
                choice(
                    "sign_policy",
                    &prefs.policy,
                    &[
                        (None, "none", "Ninguna (firma básica, BES)"),
                        (
                            Some(PolicyPreset::Age19),
                            "age19",
                            PolicyPreset::Age19.name(),
                        ),
                        (
                            Some(PolicyPreset::Age18),
                            "age18",
                            PolicyPreset::Age18.name(),
                        ),
                    ],
                ),
            ));
            rows.push(hint(
                "Algunas administraciones exigen la política de la AGE.",
            ));
        }
        if has_location(format, operation, this.analysis.signed) {
            rows.extend(field(
                "sign_location",
                "Lugar",
                prefs.location.modified_signal(),
                text_input("sign_location", &prefs.location, "Opcional, p. ej. Madrid"),
            ));
        }
        group("General", &mut rows)
    }

    fn render_pades_options(this: &Rc<Self>, pdf: &Rc<PdfDocument>) -> Dom {
        let options = &this.options;
        let prefs = this.prefs();
        let mut notes = Vec::new();
        if pdf.info.certification == CertificationLevel::NoChanges {
            notes.push("El PDF está certificado y no admite más firmas.".to_string());
        }

        let mut rows: Vec<Dom> = Vec::new();
        rows.extend(notes.iter().map(|note| {
            html!("p", { .style("grid-column", "1 / -1").style("margin", "0").class(&*ERROR_CLASS).text(note) })
        }));
        rows.extend(field(
            "sign_reason",
            "Motivo",
            options.reason.signal_ref(|reason| !reason.is_empty()),
            text_input(
                "sign_reason",
                &options.reason,
                "Opcional, p. ej. Conformidad",
            ),
        ));
        rows.extend(field(
            "sign_certification",
            "Certificación",
            differs(&options.certification, CertificationLevel::NotCertified),
            choice(
                "sign_certification",
                &options.certification,
                &[
                    (
                        CertificationLevel::NotCertified,
                        "0",
                        "Firma ordinaria (sin certificar)",
                    ),
                    (
                        CertificationLevel::NoChanges,
                        "1",
                        "Certificar: no se permiten cambios",
                    ),
                    (
                        CertificationLevel::FormFilling,
                        "2",
                        "Certificar: se permite rellenar formularios y firmar",
                    ),
                    (
                        CertificationLevel::FormFillingAndAnnotations,
                        "3",
                        "Certificar: formularios, firmas y anotaciones",
                    ),
                ],
            ),
        ));
        rows.extend(row(
            "Firma visible",
            prefs.visible.modified_signal(),
            checkbox(
                "sign_visible",
                "Mostrar la firma en una página",
                &prefs.visible,
            ),
        ));

        html!("div", {
            .attr("id", "pades_options")
            .child(group("Firma en el PDF", &mut rows))
            .child_signal(prefs.visible.signal().map(clone!(this, pdf => move |visible| {
                visible.then(|| Self::render_visible_options(&this, &pdf))
            })))
        })
    }

    fn render_visible_options(this: &Rc<Self>, pdf: &Rc<PdfDocument>) -> Dom {
        let options = &this.options;
        let prefs = this.prefs();
        let rubric_picker = FilePicker::new(
            "sign_rubric",
            "Elegir imagen (JPEG o PNG)",
            "image/jpeg,image/png",
            clone!(this => move |result| match result {
                Ok(file) => this.options.rubric.set(Some(Rc::new(file))),
                Err(err) => this.error.set(Some(err)),
            }),
        );

        let mut rows: Vec<Dom> = Vec::new();
        rows.extend(field(
            "sign_text",
            "Texto",
            prefs.visible_text.modified_signal(),
            text_area(
                "sign_text",
                &prefs.visible_text,
                "Firmado por $$SUBJECTCN$$\nFecha: $$SIGNDATE=dd/MM/yyyy HH:mm:ss z$$",
            ),
        ));
        rows.push(hint(
            "Vacío para el texto de AutoFirma. Admite $$SUBJECTCN$$, $$ISSUERCN$$, $$GIVENNAME$$, \
             $$SURNAME$$, $$REASON$$, $$LOCATION$$ y $$SIGNDATE=dd/MM/yyyy$$.",
        ));
        rows.extend(field(
            "sign_font",
            "Letra",
            prefs.font_family.modified_signal(),
            choice(
                "sign_font",
                &prefs.font_family,
                &[
                    (FontFamily::Courier, "courier", "Courier"),
                    (FontFamily::Helvetica, "helvetica", "Helvetica"),
                    (FontFamily::Times, "times", "Times"),
                ],
            ),
        ));
        rows.extend(field(
            "sign_font_size",
            "Tamaño de letra",
            prefs.font_size.modified_signal(),
            html!("input" => HtmlInputElement, {
                .attr("type", "number")
                .attr("id", "sign_font_size")
                .attr("min", "4")
                .attr("max", "72")
                .style("width", "6rem")
                .prop_signal("value", prefs.font_size.signal().map(|size| size.to_string()))
                .with_node!(element => {
                    .event(clone!(this => move |_: events::Change| {
                        if let Ok(size) = element.value().parse::<f32>() {
                            this.prefs().font_size.set_neq(size.clamp(4.0, 72.0));
                        }
                    }))
                })
            }),
        ));
        rows.extend(row(
            "Rúbrica",
            options.rubric.signal_ref(Option::is_some),
            html!("div", {
                .style("display", "flex")
                .style("flex-wrap", "wrap")
                .style("gap", "0.5rem")
                .style("align-items", "center")
                .child(FilePicker::render(&rubric_picker))
                .child_signal(options.rubric.signal_cloned().map(clone!(this => move |rubric| {
                    rubric.map(|file| html!("span", {
                        .children(&mut [
                            html!("span", { .text(&file.name) }),
                            html!("button", {
                                .attr("type", "button")
                                .class("link")
                                .text("Quitar")
                                .event(clone!(this => move |_: events::Click| this.options.rubric.set(None)))
                            }),
                        ])
                    }))
                })))
            }),
        ));

        html!("div", {
            .attr("id", "visible_options")
            .style("margin-top", "1rem")
            .children(&mut [
                PagePlacement::render(&pdf.placement),
                html!("div", {
                    .class(&*crate::css::OPTIONS_CLASS)
                    .style("margin-top", "1rem")
                    .children(&mut rows)
                }),
            ])
        })
    }

    fn render_timestamp_options(this: &Rc<Self>, is_pdf: bool) -> Dom {
        let prefs = this.prefs();
        let mut rows: Vec<Dom> = Vec::new();
        rows.extend(row(
            "Sello",
            prefs.timestamp.modified_signal(),
            checkbox(
                "sign_timestamp",
                "Añadir un sello de tiempo",
                &prefs.timestamp,
            ),
        ));
        rows.push(hint(
            "Una autoridad de sellado de tiempo (TSA) certifica la fecha. Solo recibe una huella de la \
             firma, nunca el documento, y debe admitir peticiones desde esta página (CORS).",
        ));
        html!("div", {
            .attr("id", "timestamp_options")
            .child(group("Sello de tiempo", &mut rows))
            .child_signal(prefs.timestamp.signal().map(clone!(this => move |timestamp| timestamp.then(|| {
                let prefs = this.prefs();
                let mut rows: Vec<Dom> = Vec::new();
                rows.extend(field(
                    "sign_tsa",
                    "Dirección de la TSA",
                    always(false),
                    url_input("sign_tsa", &prefs.tsa_url, "https://tsa.ejemplo.es/tsa"),
                ));
                rows.extend(field(
                    "sign_tsa_policy",
                    "Política de la TSA",
                    prefs.tsa_policy.modified_signal(),
                    text_input("sign_tsa_policy", &prefs.tsa_policy, "Opcional, p. ej. 0.4.0.2023.1.1"),
                ));
                if is_pdf {
                    rows.extend(field(
                        "sign_pdf_timestamp",
                        "Qué se sella",
                        prefs.pdf_timestamp.modified_signal(),
                        choice(
                            "sign_pdf_timestamp",
                            &prefs.pdf_timestamp,
                            &[
                                (PdfTimestamp::Signature, "signature", "La firma"),
                                (PdfTimestamp::Document, "document", "El documento (nueva revisión)"),
                                (PdfTimestamp::Both, "both", "Ambos"),
                            ],
                        ),
                    ));
                }
                html!("div", {
                    .class(&*crate::css::OPTIONS_CLASS)
                    .style("margin-top", "0.6rem")
                    .children(&mut rows)
                })
            }))))
        })
    }

    fn render_triphase_options(this: &Rc<Self>) -> Dom {
        let prefs = this.prefs();
        let mut rows: Vec<Dom> = Vec::new();
        rows.extend(row(
            "Servidor",
            prefs.triphase.modified_signal(),
            checkbox(
                "sign_triphase",
                "Firmar a través de un servidor trifásico",
                &prefs.triphase,
            ),
        ));
        rows.push(hint(
            "La firma se compone en un servidor de firma trifásica de AutoFirma: el documento se envía \
             al servidor y la clave privada no sale de este navegador.",
        ));
        html!("div", {
            .attr("id", "triphase_options")
            .child(group("Firma trifásica", &mut rows))
            .child_signal(prefs.triphase.signal().map(clone!(this => move |triphase| triphase.then(|| {
                let mut rows: Vec<Dom> = Vec::new();
                rows.extend(field(
                    "sign_server",
                    "Dirección",
                    always(false),
                    url_input(
                        "sign_server",
                        &this.prefs().server_url,
                        "https://servidor/afirma-server-triphase-signer/SignatureService",
                    ),
                ));
                html!("div", {
                    .class(&*crate::css::OPTIONS_CLASS)
                    .style("margin-top", "0.6rem")
                    .children(&mut rows)
                })
            }))))
        })
    }

    fn render_done(this: &Rc<Self>, signature: &Rc<SignatureResult>) -> Dom {
        let result = Rc::new(LoadedFile {
            name: signature.file_name.clone(),
            data: signature.data.clone(),
        });
        html!("div", {
            .children(&mut [
                html!("h2", { .attr("id", "sign_title").class(&*CARD_TITLE_CLASS).text("Firma lista") }),
                html!("div", {
                    .attr("id", "signature_result")
                    .attr("role", "status")
                    .children(&mut [
                        html!("p", {
                            .class(&*VERDICT_CLASS)
                            .style("color", "var(--ok)")
                            .style("background", "var(--ok-soft)")
                            .children(&mut [
                                html!("span", { .attr("aria-hidden", "true").text("✔") }),
                                html!("span", { .text(&signature.description) }),
                            ])
                        }),
                        html!("div", {
                            .class(&*ACTIONS_CLASS)
                            .style("justify-content", "flex-start")
                            .child(html!("button", {
                                .attr("type", "button")
                                .attr("id", "download_signature")
                                .class("primary")
                                .text(&format!("Descargar {}", signature.file_name))
                                .event(clone!(signature => move |_: events::Click| {
                                    if let Err(err) = web::download(&signature.data, &signature.file_name, signature.mime_type) {
                                        log::error!("{err}");
                                    }
                                }))
                            }))
                        }),
                    ])
                }),
                Document::render_next_steps(&this.app, result, this.file.clone()),
                html!("button", {
                    .attr("type", "button")
                    .attr("id", "sign_again")
                    .class("link")
                    .style("margin-top", "0.5rem")
                    .text("Volver a las opciones de firma")
                    .event(clone!(this => move |_: events::Click| this.signature.set(None)))
                }),
            ])
        })
    }
}

fn chip(id: &str, text: &str, modified: bool) -> Dom {
    html!("li", {
        .attr("id", id)
        .class(&*CHIP_CLASS)
        .apply_if(modified, |dom| dom.class(&*CHIP_MODIFIED_CLASS).attr("title", "Cambiado"))
        .text(text)
    })
}

/// The formats offered for a file whose default is `default`, the default first.
fn formats_for(
    default: SignatureFormat,
) -> &'static [(SignatureFormat, &'static str, &'static str)] {
    use SignatureFormat::*;
    match default {
        Odf => &[
            (Odf, "odf", "ODF (firma dentro del documento)"),
            (Cades, "cades", "CAdES"),
            (Xades, "xades", "XAdES"),
        ],
        Ooxml => &[
            (Ooxml, "ooxml", "OOXML (firma dentro del documento)"),
            (Cades, "cades", "CAdES"),
            (Xades, "xades", "XAdES"),
        ],
        Pades => &[
            (Pades, "pades", "PAdES (firma dentro del PDF)"),
            (Cades, "cades", "CAdES"),
            (Xades, "xades", "XAdES"),
        ],
        Facturae => &[
            (Facturae, "facturae", "FacturaE (factura electrónica)"),
            (Xades, "xades", "XAdES"),
            (Cades, "cades", "CAdES"),
        ],
        Xades => &[(Xades, "xades", "XAdES"), (Cades, "cades", "CAdES")],
        Cades => &[(Cades, "cades", "CAdES"), (Xades, "xades", "XAdES")],
    }
}

/// The kind of signature, in plain words: `PAdES, dentro del PDF`.
fn kind_text(
    format: SignatureFormat,
    operation: Option<MultiSignOperation>,
    signed: Option<SignedKind>,
    asic: bool,
    role: FacturaeRole,
    mode: SignatureMode,
    xades: XadesFormat,
) -> String {
    let signed_name = match signed {
        Some(SignedKind::Cades) => " CAdES",
        Some(SignedKind::Xades | SignedKind::Facturae) => " XAdES",
        Some(SignedKind::Asic) => " ASiC-S",
        _ => "",
    };
    match operation {
        Some(MultiSignOperation::Cosign) => return format!("Cofirma{signed_name}"),
        Some(MultiSignOperation::Countersign(CounterSignTarget::Leafs)) => {
            return "Contrafirma de las últimas firmas".to_string();
        }
        Some(MultiSignOperation::Countersign(CounterSignTarget::Tree)) => {
            return "Contrafirma de todas las firmas".to_string();
        }
        None => {}
    }
    let text = match format {
        SignatureFormat::Pades => "PAdES, dentro del PDF".to_string(),
        SignatureFormat::Odf | SignatureFormat::Ooxml => {
            format!("{}, dentro del documento", format.name())
        }
        SignatureFormat::Facturae => format!("FacturaE, como {}", role.name()),
        SignatureFormat::Xades => match xades {
            XadesFormat::Enveloping => "XAdES envolvente".to_string(),
            XadesFormat::Enveloped => "XAdES dentro del XML".to_string(),
            XadesFormat::Detached => "XAdES separada".to_string(),
        },
        SignatureFormat::Cades => match mode {
            SignatureMode::Explicit => "CAdES, firma aparte (.csig)".to_string(),
            SignatureMode::Implicit => "CAdES con los datos dentro".to_string(),
        },
    };
    if asic && matches!(format, SignatureFormat::Cades | SignatureFormat::Xades) {
        format!("{text}, en ASiC-S")
    } else {
        text
    }
}

/// FacturaE has its own policy; ODF and OOXML none.
fn has_policy(format: SignatureFormat, operation: Option<MultiSignOperation>) -> bool {
    operation.is_some()
        || !matches!(
            format,
            SignatureFormat::Facturae | SignatureFormat::Odf | SignatureFormat::Ooxml
        )
}

/// Formats that record where the signature was made.
fn has_location(
    format: SignatureFormat,
    operation: Option<MultiSignOperation>,
    signed: Option<SignedKind>,
) -> bool {
    match operation {
        Some(_) => matches!(
            signed,
            Some(SignedKind::Xades | SignedKind::Facturae | SignedKind::Asic)
        ),
        None => matches!(
            format,
            SignatureFormat::Pades
                | SignatureFormat::Xades
                | SignatureFormat::Facturae
                | SignatureFormat::Ooxml
        ),
    }
}

/// Counter-signatures are not timestamped; ODF and OOXML have no timestamps.
fn stamps(format: SignatureFormat, operation: Option<MultiSignOperation>) -> bool {
    match operation {
        Some(MultiSignOperation::Countersign(_)) => false,
        Some(MultiSignOperation::Cosign) => true,
        None => !matches!(format, SignatureFormat::Odf | SignatureFormat::Ooxml),
    }
}

/// `contentHint` description, as AutoFirma writes it.
fn content_description(kind: DataKind) -> Option<String> {
    match kind {
        DataKind::Binary => None,
        kind => Some(kind.description().to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_words() {
        let text = |format, operation, asic| {
            kind_text(
                format,
                operation,
                None,
                asic,
                FacturaeRole::Issuer,
                SignatureMode::Explicit,
                XadesFormat::Enveloping,
            )
        };
        assert_eq!(
            text(SignatureFormat::Pades, None, false),
            "PAdES, dentro del PDF"
        );
        assert_eq!(
            text(SignatureFormat::Cades, None, true),
            "CAdES, firma aparte (.csig), en ASiC-S"
        );
        assert_eq!(
            text(SignatureFormat::Facturae, None, false),
            "FacturaE, como emisor"
        );
        assert_eq!(
            text(
                SignatureFormat::Cades,
                Some(MultiSignOperation::Cosign),
                false
            ),
            "Cofirma"
        );
    }

    #[test]
    fn default_format_comes_first() {
        for format in [
            SignatureFormat::Cades,
            SignatureFormat::Pades,
            SignatureFormat::Xades,
            SignatureFormat::Facturae,
            SignatureFormat::Odf,
            SignatureFormat::Ooxml,
        ] {
            assert_eq!(formats_for(format)[0].0, format);
        }
    }
}
