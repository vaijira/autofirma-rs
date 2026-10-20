use std::rc::Rc;

use afirma_core::{
    Error as CoreError,
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
    pades::{
        CertificationLevel, Font, FontFamily, PadesParams, PdfInfo, SignaturePages,
        VisibleSignature,
    },
    params::ExtraParams,
    policy::PolicyPreset,
    triphase::{self, CryptoOperation, TriphaseFormat, TriphaseRequest},
    xades::{ProductionPlace, XadesFormat, XadesParams},
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

/// Timestamps of a PDF (AutoFirma's `tsType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PdfTimestamp {
    /// On the signature (`1`).
    Signature,
    /// On the whole document, as a new revision (`2`).
    Document,
    /// Both (`3`).
    Both,
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
    /// XAdES enveloping, enveloped or detached.
    xades_format: Mutable<XadesFormat>,
    /// CAdES or XAdES signature inside an ASiC-S container.
    asic: Mutable<bool>,
    /// Role of the signer of a FacturaE invoice.
    role: Mutable<FacturaeRole>,
    timestamp: Mutable<bool>,
    tsa_url: Mutable<String>,
    tsa_policy: Mutable<String>,
    pdf_timestamp: Mutable<PdfTimestamp>,
    /// Co-signature or counter-signature of a signature; `None` signs the file.
    operation: Mutable<Option<MultiSignOperation>>,
    /// Signed data of an explicit CAdES signature to co-sign.
    cosign_data: Mutable<Option<Rc<LoadedFile>>>,
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
                xades_format: Mutable::new(XadesFormat::Enveloping),
                asic: Mutable::new(false),
                role: Mutable::new(FacturaeRole::Issuer),
                timestamp: Mutable::new(false),
                tsa_url: Mutable::new(String::new()),
                tsa_policy: Mutable::new(String::new()),
                pdf_timestamp: Mutable::new(PdfTimestamp::Signature),
                operation: Mutable::new(None),
                cosign_data: Mutable::new(None),
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
                    this.options.format.set(analysis.default_format);
                    // A signature is co-signed (counter-signed, for invoices) by default.
                    this.options.operation.set(match analysis.signed {
                        Some(SignedKind::Cades | SignedKind::Xades | SignedKind::Asic) => Some(MultiSignOperation::Cosign),
                        Some(SignedKind::Facturae) => Some(MultiSignOperation::Countersign(CounterSignTarget::Leafs)),
                        _ => None,
                    });
                    this.options.cosign_data.set(None);
                    if analysis.kind != DataKind::Xml && this.options.xades_format.get() == XadesFormat::Enveloped {
                        this.options.xades_format.set(XadesFormat::Enveloping);
                    }
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
            // Room for the signature timestamp, added to the CMS afterwards.
            reserved_size: (options.timestamp.get()
                && options.pdf_timestamp.get() != PdfTimestamp::Document)
                .then_some(32 * 1024),
        }
    }

    fn production_place(&self) -> ProductionPlace {
        let city = self.options.location.get_cloned();
        ProductionPlace {
            city: (!city.trim().is_empty()).then(|| city.trim().to_string()),
            ..ProductionPlace::default()
        }
    }

    fn xades_params(&self) -> XadesParams {
        XadesParams {
            digest: self.options.digest.get(),
            format: self.options.xades_format.get(),
            policy: self
                .options
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
            digest: self.options.digest.get(),
            signing_time: now(),
            utc_offset_minutes: utc_offset_minutes(),
            role: self.options.role.get(),
            production_place: self.production_place(),
        }
    }

    fn multisign_params(&self) -> MultiSignParams {
        MultiSignParams {
            digest: self.options.digest.get(),
            mode: self.options.mode.get(),
            policy: self.options.policy.get(),
            signing_time: now(),
            utc_offset_minutes: utc_offset_minutes(),
            production_place: self.production_place(),
            claimed_roles: Vec::new(),
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
        let operation = this.options.operation.get();
        let pdf = this.pdf.get_cloned();

        this.error.set(None);
        this.signature.set(None);
        this.busy.set(Some("Firmando…"));
        spawn_local(clone!(this => async move {
            let result = if let Some(operation) = operation {
                Self::multisign(&this, &entry, &selected, operation).await
            } else { match (format, &pdf) {
                (SignatureFormat::Pades, Some(pdf)) => {
                    let params = this.pades_params(pdf);
                    if this.options.triphase.get() {
                        let extra = ExtraParams::from(&params);
                        Self::sign_triphase(&this, &entry, CryptoOperation::Sign, TriphaseFormat::Pades, &selected.file.data, params.digest, extra).await
                    } else {
                        let job = Job::SignPades { data: selected.file.data.clone(), key_id: entry.id, params: Box::new(params) };
                        Self::run_signature_job(&this, job).await
                    }
                    .map(|data| SignatureResult {
                        description: format!("PDF firmado en PAdES ({}).", format_size(data.len())),
                        data,
                        file_name: SignatureFormat::Pades.signed_file_name(&selected.file.name),
                        mime_type: "application/pdf",
                    })
                }
                (SignatureFormat::Pades, None) => Err(anyhow!("Abra antes el PDF")),
                (format @ (SignatureFormat::Odf | SignatureFormat::Ooxml), _) => {
                    let options = &this.options;
                    if options.triphase.get() {
                        Err(anyhow!("Los documentos ODF y OOXML no se pueden firmar en un servidor trifásico"))
                    } else {
                        let job = if format == SignatureFormat::Odf {
                            Job::SignOdf {
                                data: selected.file.data.clone(),
                                key_id: entry.id,
                                params: OdfParams {
                                    digest: options.digest.get(),
                                    signing_time: now(),
                                    utc_offset_minutes: utc_offset_minutes(),
                                },
                            }
                        } else {
                            Job::SignOoxml {
                                data: selected.file.data.clone(),
                                key_id: entry.id,
                                params: Box::new(OoxmlParams {
                                    digest: options.digest.get(),
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
                        file_name: format.signed_file_name(&selected.file.name),
                        mime_type: if format == SignatureFormat::Odf { "application/vnd.oasis.opendocument" } else { "application/zip" },
                        data,
                    })
                }
                (SignatureFormat::Facturae, _) => {
                    let params = this.facturae_params();
                    if this.options.triphase.get() {
                        let extra = ExtraParams::from(&params);
                        Self::sign_triphase(&this, &entry, CryptoOperation::Sign, TriphaseFormat::Facturae, &selected.file.data, params.digest, extra).await
                    } else {
                        let job = Job::SignFacturae { data: selected.file.data.clone(), key_id: entry.id, params };
                        Self::run_signature_job(&this, job).await
                    }
                    .map(|data| SignatureResult {
                        description: format!("Factura electrónica firmada ({}).", format_size(data.len())),
                        data,
                        file_name: SignatureFormat::Facturae.signed_file_name(&selected.file.name),
                        mime_type: "text/xml",
                    })
                }
                (format, _) if this.options.asic.get() => {
                    let signature = if format == SignatureFormat::Xades {
                        AsicSignature::Xades(this.xades_params())
                    } else {
                        AsicSignature::Cades(this.cades_params(selected.analysis.kind))
                    };
                    if this.options.triphase.get() {
                        Err(anyhow!("Los contenedores ASiC-S no se pueden firmar en un servidor trifásico"))
                    } else {
                        let job = Job::SignAsic {
                            data: selected.file.data.clone(),
                            file_name: Some(selected.file.name.clone()),
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
                        file_name: format!("{}.asics", selected.file.name),
                        mime_type: "application/vnd.etsi.asic-s+zip",
                    })
                }
                (SignatureFormat::Xades, _) => {
                    let params = this.xades_params();
                    if this.options.triphase.get() {
                        let extra = ExtraParams::from(&params);
                        Self::sign_triphase(&this, &entry, CryptoOperation::Sign, TriphaseFormat::Xades, &selected.file.data, params.digest, extra).await
                    } else {
                        let job = Job::SignXades { data: selected.file.data.clone(), key_id: entry.id, params: Box::new(params) };
                        Self::run_signature_job(&this, job).await
                    }
                    .map(|data| SignatureResult {
                        description: format!("Firma XAdES generada ({}).", format_size(data.len())),
                        data,
                        file_name: SignatureFormat::Xades.signed_file_name(&selected.file.name),
                        mime_type: "text/xml",
                    })
                }
                _ => {
                    let params = this.cades_params(selected.analysis.kind);
                    if this.options.triphase.get() {
                        let extra = ExtraParams::from(&params);
                        Self::sign_triphase(&this, &entry, CryptoOperation::Sign, TriphaseFormat::Cades, &selected.file.data, params.digest, extra).await
                    } else {
                        let job = Job::SignCades { data: selected.file.data.clone(), key_id: entry.id, params };
                        Self::run_signature_job(&this, job).await
                    }
                    .map(|data| SignatureResult {
                        description: format!("Firma CAdES generada ({}).", format_size(data.len())),
                        data,
                        file_name: SignatureFormat::Cades.signed_file_name(&selected.file.name),
                        mime_type: "application/pkcs7-signature",
                    })
                }
            } };
            // Counter-signatures are not timestamped.
            let stamp = this.options.timestamp.get()
                && !matches!(operation, Some(MultiSignOperation::Countersign(_)));
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
        let url = this.options.tsa_url.get_cloned().trim().to_string();
        if url.is_empty() {
            return Err(anyhow!(
                "Indique la dirección del servidor de sellado de tiempo (TSA)"
            ));
        }
        let policy = Some(this.options.tsa_policy.get_cloned().trim().to_string())
            .filter(|policy| !policy.is_empty());
        let digest = this.options.digest.get();
        let kind = if format == SignatureFormat::Pades {
            this.options.pdf_timestamp.get()
        } else {
            PdfTimestamp::Signature
        };

        this.busy.set(Some("Obteniendo el sello de tiempo…"));
        if kind != PdfTimestamp::Document {
            let requests = match this
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
        match this.worker.run(job).await? {
            JobOutput::Signature(data) => Ok(data),
            other => Err(anyhow!("Respuesta inesperada del worker: {other:?}")),
        }
    }

    /// Co-signature or counter-signature of the selected signature.
    async fn multisign(
        this: &Rc<Self>,
        entry: &KeyEntry,
        selected: &Selected,
        operation: MultiSignOperation,
    ) -> anyhow::Result<SignatureResult> {
        let kind = selected
            .analysis
            .signed
            .ok_or_else(|| anyhow!("El fichero no es una firma"))?;
        let params = this.multisign_params();
        let data = if this.options.triphase.get() {
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
                &selected.file.data,
                params.digest,
                extra,
            )
            .await?
        } else {
            let job = Job::MultiSign {
                signature: selected.file.data.clone(),
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
            file_name: multisigned_file_name(&selected.file.name, operation),
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
        let is_xml = selected.analysis.kind == DataKind::Xml;
        let signed = selected.analysis.signed;
        let formats: &[(&str, &str)] = match selected.analysis.default_format {
            SignatureFormat::Odf => &[
                ("odf", "ODF (firma dentro del documento)"),
                ("cades", "CAdES"),
                ("xades", "XAdES"),
            ],
            SignatureFormat::Ooxml => &[
                ("ooxml", "OOXML (firma dentro del documento)"),
                ("cades", "CAdES"),
                ("xades", "XAdES"),
            ],
            SignatureFormat::Pades => &[
                ("pades", "PAdES (firma dentro del PDF)"),
                ("cades", "CAdES"),
                ("xades", "XAdES"),
            ],
            SignatureFormat::Facturae => &[
                ("facturae", "FacturaE (factura electrónica)"),
                ("xades", "XAdES"),
                ("cades", "CAdES"),
            ],
            SignatureFormat::Xades => &[("xades", "XAdES"), ("cades", "CAdES")],
            _ => &[("cades", "CAdES"), ("xades", "XAdES")],
        };
        let options = &this.options;

        let note = match signed {
            Some(SignedKind::Odf | SignedKind::Ooxml) => Some(
                "El documento ya está firmado; se añadirá otra firma sin invalidar las anteriores.",
            ),
            Some(SignedKind::Cades | SignedKind::Xades | SignedKind::Asic) => Some(
                "El fichero es una firma: puede cofirmarla (otro firmante firma los mismos datos), \
                 contrafirmarla (firmar las firmas existentes) o firmarlo como un fichero cualquiera.",
            ),
            Some(SignedKind::Facturae) => Some(
                "La factura ya está firmada: puede contrafirmarla o firmarla como un fichero cualquiera.",
            ),
            _ => None,
        };
        let multisign = matches!(
            signed,
            Some(SignedKind::Cades | SignedKind::Xades | SignedKind::Facturae | SignedKind::Asic)
        );

        html!("div", {
            .apply_if(note.is_some(), |dom| dom.child(html!("p", {
                .attr("id", "sign_note")
                .text(note.unwrap_or_default())
            })))
            .child(html!("div", {
                .class(&*OPTIONS_CLASS)
                .apply_if(multisign, |dom| dom.child(Self::render_operation(this, signed)))
                .child_signal(options.operation.signal().map(clone!(this => move |operation| {
                    operation.is_none().then(|| html!("div", {
                        .style("display", "contents")
                        .children(&mut [
                            html!("label", { .attr("for", "sign_format").text("Formato") }),
                            select(
                                "sign_format",
                                formats,
                                match this.options.format.get() {
                                    SignatureFormat::Pades => "pades",
                                    SignatureFormat::Xades => "xades",
                                    SignatureFormat::Facturae => "facturae",
                                    SignatureFormat::Odf => "odf",
                                    SignatureFormat::Ooxml => "ooxml",
                                    SignatureFormat::Cades => "cades",
                                },
                                clone!(this => move |value| this.options.format.set(match value.as_str() {
                                    "pades" => SignatureFormat::Pades,
                                    "xades" => SignatureFormat::Xades,
                                    "facturae" => SignatureFormat::Facturae,
                                    "odf" => SignatureFormat::Odf,
                                    "ooxml" => SignatureFormat::Ooxml,
                                    _ => SignatureFormat::Cades,
                                })),
                            ),
                        ])
                    }))
                })))
                .children(&mut [
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
                ])
                // FacturaE has its own policy; ODF and OOXML none.
                .child_signal(map_ref! {
                    let format = options.format.signal(),
                    let operation = options.operation.signal() => move {
                        operation.is_some()
                            || !matches!(format, SignatureFormat::Facturae | SignatureFormat::Odf | SignatureFormat::Ooxml)
                    }
                }.map(clone!(this => move |policy| policy.then(|| Self::render_policy(&this)))))
                .child_signal(map_ref! {
                    let format = options.format.signal(),
                    let operation = options.operation.signal() => (*format, *operation)
                }.map(clone!(this => move |(format, operation)| match (operation, format) {
                    (Some(operation), _) => Some(Self::render_multisign_options(&this, signed, operation)),
                    (None, SignatureFormat::Cades) => Some(Self::render_cades_options(&this)),
                    (None, SignatureFormat::Xades) => Some(Self::render_xades_options(&this, is_xml)),
                    (None, SignatureFormat::Facturae) => Some(Self::render_facturae_options(&this)),
                    _ => None,
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
            .child_signal({
                let page = this.clone();
                map_ref! {
                    let pades = options.format.signal().map(|f| f == SignatureFormat::Pades),
                    let operation = options.operation.signal(),
                    let pdf = this.pdf.signal_cloned() => move {
                        match (pades, operation, pdf) {
                            (true, None, Some(pdf)) => Some(Self::render_pades_options(&page, pdf)),
                            _ => None,
                        }
                    }
                }
            })
            // Counter-signatures are not timestamped; ODF and OOXML have no timestamps.
            .child_signal(map_ref! {
                let format = options.format.signal(),
                let operation = options.operation.signal() => {
                    match operation {
                        Some(MultiSignOperation::Countersign(_)) => false,
                        Some(MultiSignOperation::Cosign) => true,
                        None => !matches!(format, SignatureFormat::Odf | SignatureFormat::Ooxml),
                    }
                }
            }.map(clone!(this => move |stamp| stamp.then(|| Self::render_timestamp_options(&this, is_pdf)))))
            .child(Self::render_triphase_options(this))
            .child(html!("button", {
                .attr("type", "button")
                .attr("id", "sign_button")
                .text("Firmar")
                .attr_signal("disabled", map_ref! {
                    let key = this.keys.selected.signal(),
                    let busy = this.busy.signal(),
                    let format = options.format.signal(),
                    let operation = options.operation.signal(),
                    let pdf = this.pdf.signal_ref(Option::is_some) => {
                        let missing_pdf = operation.is_none() && *format == SignatureFormat::Pades && !pdf;
                        (key.is_none() || busy.is_some() || missing_pdf).then_some("")
                    }
                })
                .event(clone!(this => move |_: events::Click| Self::sign(&this)))
            }))
        })
    }

    /// What to do with a signature: co-sign, counter-sign or sign it as data.
    fn render_operation(this: &Rc<Self>, signed: Option<SignedKind>) -> Dom {
        let mut operations = Vec::new();
        if signed != Some(SignedKind::Facturae) {
            operations.push(("cosign", "Cofirmar (otro firmante firma los mismos datos)"));
        }
        operations.extend([
            ("leafs", "Contrafirmar las últimas firmas"),
            ("tree", "Contrafirmar todas las firmas"),
            ("sign", "Firmar el fichero como datos (nueva firma)"),
        ]);
        html!("div", {
            .style("display", "contents")
            .children(&mut [
                html!("label", { .attr("for", "sign_operation").text("Operación") }),
                select(
                    "sign_operation",
                    &operations,
                    match this.options.operation.get() {
                        Some(MultiSignOperation::Cosign) => "cosign",
                        Some(MultiSignOperation::Countersign(CounterSignTarget::Leafs)) => "leafs",
                        Some(MultiSignOperation::Countersign(CounterSignTarget::Tree)) => "tree",
                        None => "sign",
                    },
                    clone!(this => move |value| this.options.operation.set(match value.as_str() {
                        "cosign" => Some(MultiSignOperation::Cosign),
                        "leafs" => Some(MultiSignOperation::Countersign(CounterSignTarget::Leafs)),
                        "tree" => Some(MultiSignOperation::Countersign(CounterSignTarget::Tree)),
                        _ => None,
                    })),
                ),
            ])
        })
    }

    /// Options of a co-signature or counter-signature.
    fn render_multisign_options(
        this: &Rc<Self>,
        signed: Option<SignedKind>,
        operation: MultiSignOperation,
    ) -> Dom {
        let xml = matches!(
            signed,
            Some(SignedKind::Xades | SignedKind::Facturae | SignedKind::Asic)
        );
        let cades_cosign =
            signed == Some(SignedKind::Cades) && operation == MultiSignOperation::Cosign;
        let data_picker = FilePicker::new(
            "sign_cosign_data",
            "Seleccionar los datos firmados",
            "*/*",
            clone!(this => move |result| match result {
                Ok(file) => this.options.cosign_data.set(Some(Rc::new(file))),
                Err(err) => this.error.set(Some(err)),
            }),
        );
        html!("div", {
            .style("display", "contents")
            .apply_if(xml, |dom| dom.children(&mut [
                html!("label", { .attr("for", "sign_city").text("Lugar") }),
                text_input("sign_city", &this.options.location),
            ]))
            .apply_if(cades_cosign, |dom| dom.children(&mut [
                html!("span", { .text("Datos firmados") }),
                html!("div", {
                    .children(&mut [
                        html!("small", {
                            .style("color", "var(--muted)")
                            .text("Solo hacen falta si la firma no incluye los datos y se usa otro algoritmo.")
                        }),
                    ])
                    .child(html!("div", {
                        .style("display", "flex")
                        .style("gap", "0.5rem")
                        .style("align-items", "center")
                        .child(FilePicker::render(&data_picker))
                        .child_signal(this.options.cosign_data.signal_cloned().map(clone!(this => move |data| {
                            data.map(|file| html!("span", {
                                .children(&mut [
                                    html!("span", { .attr("id", "sign_cosign_data_name").text(&file.name) }),
                                    html!("button", {
                                        .attr("type", "button")
                                        .text("Quitar")
                                        .event(clone!(this => move |_: events::Click| this.options.cosign_data.set(None)))
                                    }),
                                ])
                            }))
                        })))
                    }))
                }),
            ]))
        })
    }

    fn render_policy(this: &Rc<Self>) -> Dom {
        let options = &this.options;
        html!("div", {
            .style("display", "contents")
            .children(&mut [
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
        })
    }

    fn render_xades_options(this: &Rc<Self>, is_xml: bool) -> Dom {
        let mut formats = vec![("enveloping", "Envolvente (los datos dentro de la firma)")];
        if is_xml {
            formats.push(("enveloped", "Envuelta (la firma dentro del XML)"));
        }
        formats.push(("detached", "Separada (datos y firma en un XML nuevo)"));
        html!("div", {
            .style("display", "contents")
            .children(&mut [
                html!("label", { .attr("for", "sign_xades_format").text("Tipo") }),
                select(
                    "sign_xades_format",
                    &formats,
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
                html!("label", { .attr("for", "sign_city").text("Lugar") }),
                text_input("sign_city", &this.options.location),
                html!("span", { .text("Contenedor") }),
                checkbox("sign_asic", "ASiC-S (fichero y firma en un ZIP)", &this.options.asic),
            ])
        })
    }

    fn render_facturae_options(this: &Rc<Self>) -> Dom {
        html!("div", {
            .style("display", "contents")
            .children(&mut [
                html!("label", { .attr("for", "sign_role").text("Firma como") }),
                select(
                    "sign_role",
                    &[("emisor", "Emisor"), ("receptor", "Receptor"), ("tercero", "Tercero")],
                    this.options.role.get().name(),
                    clone!(this => move |value| this.options.role.set(match value.as_str() {
                        "receptor" => FacturaeRole::Receiver,
                        "tercero" => FacturaeRole::ThirdParty,
                        _ => FacturaeRole::Issuer,
                    })),
                ),
                html!("label", { .attr("for", "sign_city").text("Lugar") }),
                text_input("sign_city", &this.options.location),
            ])
        })
    }

    fn render_timestamp_options(this: &Rc<Self>, is_pdf: bool) -> Dom {
        let options = &this.options;
        html!("details", {
            .style("margin", "1rem 0")
            .children(&mut [
                html!("summary", { .attr("id", "timestamp_summary").text("Sello de tiempo") }),
                html!("p", {
                    .style("color", "var(--muted)")
                    .text("Una autoridad de sellado de tiempo (TSA) certifica la fecha de la firma. Solo se le envía \
                           una huella de la firma, nunca el documento. La TSA debe admitir peticiones desde esta \
                           página (CORS).")
                }),
                checkbox("sign_timestamp", "Añadir sello de tiempo", &options.timestamp),
                html!("div", {
                    .class(&*OPTIONS_CLASS)
                    .children(&mut [
                        html!("label", { .attr("for", "sign_tsa").text("TSA") }),
                        html!("input" => HtmlInputElement, {
                            .attr("type", "url")
                            .attr("id", "sign_tsa")
                            .attr("placeholder", "https://tsa.ejemplo.es/tsa")
                            .prop("value", options.tsa_url.get_cloned())
                            .with_node!(element => {
                                .event(clone!(this => move |_: events::Input| this.options.tsa_url.set(element.value())))
                            })
                        }),
                        html!("label", { .attr("for", "sign_tsa_policy").text("Política de la TSA") }),
                        html!("input" => HtmlInputElement, {
                            .attr("type", "text")
                            .attr("id", "sign_tsa_policy")
                            .attr("placeholder", "Opcional, p. ej. 0.4.0.2023.1.1")
                            .prop("value", options.tsa_policy.get_cloned())
                            .with_node!(element => {
                                .event(clone!(this => move |_: events::Input| this.options.tsa_policy.set(element.value())))
                            })
                        }),
                    ])
                    .apply_if(is_pdf, |dom| dom.children(&mut [
                        html!("label", { .attr("for", "sign_pdf_timestamp").text("En el PDF") }),
                        select(
                            "sign_pdf_timestamp",
                            &[
                                ("signature", "Sellar la firma"),
                                ("document", "Sellar el documento (nueva revisión)"),
                                ("both", "Ambos"),
                            ],
                            match options.pdf_timestamp.get() {
                                PdfTimestamp::Signature => "signature",
                                PdfTimestamp::Document => "document",
                                PdfTimestamp::Both => "both",
                            },
                            clone!(this => move |value| this.options.pdf_timestamp.set(match value.as_str() {
                                "document" => PdfTimestamp::Document,
                                "both" => PdfTimestamp::Both,
                                _ => PdfTimestamp::Signature,
                            })),
                        ),
                    ]))
                }),
            ])
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
                html!("span", { .text("Contenedor") }),
                checkbox("sign_asic", "ASiC-S (fichero y firma en un ZIP)", &this.options.asic),
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
                html!("summary", { .attr("id", "triphase_summary").text("Firma trifásica (servidor)") }),
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

pub(crate) fn select(
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

pub(crate) fn text_input(id: &str, value: &Mutable<String>) -> Dom {
    html!("input" => HtmlInputElement, {
        .attr("type", "text")
        .attr("id", id)
        .prop("value", value.get_cloned())
        .with_node!(element => {
            .event(clone!(value => move |_: events::Input| value.set(element.value())))
        })
    })
}

pub(crate) fn checkbox(id: &str, label: &str, value: &Mutable<bool>) -> Dom {
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
