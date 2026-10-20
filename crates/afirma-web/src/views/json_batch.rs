use std::rc::Rc;

use afirma_core::{
    batch::{BatchResult, BatchStep},
    job::{Job, JobOutput, KeyEntry},
};
use anyhow::anyhow;
use dominator::{Dom, clone, events, html, with_node};
use futures_signals::{
    map_ref,
    signal::{Mutable, SignalExt},
};
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlTextAreaElement;

use crate::{
    components::{
        dialog::modal,
        file_picker::FilePicker,
        form::{field, unmarked, url_input},
    },
    css::{ACTIONS_CLASS, ERROR_CLASS, MUTED_CLASS, OPTIONS_CLASS, STATUS_CLASS, VERDICT_CLASS},
    state::Keys,
    utils::http,
    views::certs::Certificates,
    worker::WorkerClient,
};

/// A JSON batch of an AutoFirma batch signature service: the documents stay on
/// the server, only their pre-signatures are signed here.
#[derive(Debug)]
pub struct JsonBatch {
    worker: Rc<WorkerClient>,
    keys: Rc<Keys>,
    certificates: Rc<Certificates>,
    pub open: Mutable<bool>,
    /// The batch, as given (JSON or Base64).
    batch: Mutable<String>,
    presign_url: Mutable<String>,
    postsign_url: Mutable<String>,
    busy: Mutable<Option<&'static str>>,
    error: Mutable<Option<String>>,
    results: Mutable<Option<Rc<Vec<BatchResult>>>>,
}

impl JsonBatch {
    pub fn new(
        worker: Rc<WorkerClient>,
        keys: Rc<Keys>,
        certificates: Rc<Certificates>,
    ) -> Rc<Self> {
        Rc::new(Self {
            worker,
            keys,
            certificates,
            open: Mutable::new(false),
            batch: Mutable::new(String::new()),
            presign_url: Mutable::new(String::new()),
            postsign_url: Mutable::new(String::new()),
            busy: Mutable::new(None),
            error: Mutable::new(None),
            results: Mutable::new(None),
        })
    }

    fn sign(this: &Rc<Self>) {
        let Some(entry) = this.keys.selected_entry() else {
            this.open.set(false);
            this.certificates.show();
            return;
        };
        this.results.set(None);
        this.error.set(None);
        spawn_local(clone!(this => async move {
            match Self::run(&this, &entry).await {
                Ok(results) => this.results.set(Some(Rc::new(results))),
                Err(err) => this.error.set(Some(err.to_string())),
            }
            this.busy.set(None);
        }));
    }

    /// The JSON batch protocol: presign on the server, sign the pre-signatures
    /// here (in the worker), postsign on the server.
    async fn run(this: &Rc<Self>, entry: &KeyEntry) -> anyhow::Result<Vec<BatchResult>> {
        let presign_url = this.presign_url.get_cloned().trim().to_string();
        let postsign_url = this.postsign_url.get_cloned().trim().to_string();
        if presign_url.is_empty() || postsign_url.is_empty() {
            return Err(anyhow!(
                "Indique las direcciones de los servicios de prefirma y postfirma del lote"
            ));
        }
        this.busy.set(Some("Preparando el lote…"));
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
        this.busy.set(Some("Prefirma en el servidor…"));
        let presign_response = http::post_form(&presign_url, &body).await?;
        this.busy.set(Some("Firmando…"));
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
        this.busy.set(Some("Postfirma en el servidor…"));
        let response = http::post_form(&postsign_url, &body).await?;
        match this.worker.run(Job::BatchResults { response }).await? {
            JobOutput::BatchResults(results) => Ok(results),
            other => Err(anyhow!("Respuesta inesperada del worker: {other:?}")),
        }
    }

    pub fn render_dialog(this: &Rc<Self>) -> Dom {
        modal(
            "batch_json",
            "Lote de un servicio de firma",
            &this.open,
            clone!(this => move || {
                Self::render_body(&this)
            }),
        )
    }

    fn render_body(this: &Rc<Self>) -> Dom {
        let picker = FilePicker::new(
            "batch_json_file",
            "Cargar el lote desde un fichero",
            "application/json,.json,.txt",
            clone!(this => move |result| match result {
                Ok(file) => {
                    this.error.set(None);
                    this.results.set(None);
                    this.batch.set(String::from_utf8_lossy(&file.data).into_owned());
                }
                Err(err) => this.error.set(Some(err)),
            }),
        );

        let mut rows: Vec<Dom> = Vec::new();
        rows.extend(field(
            "batch_json_text",
            "Lote (JSON o Base64)",
            unmarked(),
            html!("textarea" => HtmlTextAreaElement, {
                .attr("id", "batch_json_text")
                .attr("rows", "5")
                .attr("spellcheck", "false")
                .style("width", "100%")
                .style("font-family", "monospace")
                .style("font-size", "0.8rem")
                .attr("placeholder", r#"{"algorithm":"SHA512withRSA","format":"CAdES","suboperation":"sign","singlesigns":[...]}"#)
                .prop_signal("value", this.batch.signal_cloned())
                .with_node!(element => {
                    .event(clone!(this => move |_: events::Input| this.batch.set(element.value())))
                })
            }),
        ));
        rows.extend(field(
            "batch_presign_url",
            "Prefirma",
            unmarked(),
            url_input(
                "batch_presign_url",
                &this.presign_url,
                "https://servidor/afirma-server-triphase-signer/presign",
            ),
        ));
        rows.extend(field(
            "batch_postsign_url",
            "Postfirma",
            unmarked(),
            url_input(
                "batch_postsign_url",
                &this.postsign_url,
                "https://servidor/afirma-server-triphase-signer/postsign",
            ),
        ));

        html!("div", {
            .children(&mut [
                html!("p", {
                    .class(&*MUTED_CLASS)
                    .text("Firme un lote JSON de un servicio de firma por lotes de AutoFirma. Los documentos \
                           están en el servidor: aquí solo se firman sus huellas, y la clave privada no sale de \
                           este navegador. El servidor debe admitir peticiones desde esta página (CORS).")
                }),
                html!("div", { .style("margin", "1rem 0").child(FilePicker::render(&picker)) }),
                html!("div", { .class(&*OPTIONS_CLASS).children(&mut rows) }),
            ])
            .child_signal(this.busy.signal().map(|busy| {
                busy.map(|text| html!("p", { .class(&*STATUS_CLASS).attr("role", "status").text(text) }))
            }))
            .child_signal(this.error.signal_cloned().map(|error| {
                error.map(|error| html!("p", { .class(&*ERROR_CLASS).attr("role", "alert").text(&error) }))
            }))
            .child_signal(this.results.signal_cloned().map(|results| results.map(|results| render_results(&results))))
            .child(html!("div", {
                .class(&*ACTIONS_CLASS)
                .child(html!("button", {
                    .attr("type", "button")
                    .attr("id", "batch_json_button")
                    .class("primary")
                    .text("Firmar el lote")
                    .attr_signal("disabled", map_ref! {
                        let busy = this.busy.signal(),
                        let empty = this.batch.signal_ref(|batch| batch.trim().is_empty()) => {
                            (busy.is_some() || *empty).then_some("")
                        }
                    })
                    .event(clone!(this => move |_: events::Click| Self::sign(&this)))
                }))
            }))
        })
    }
}

fn render_results(results: &[BatchResult]) -> Dom {
    let done = results.iter().filter(|r| r.is_ok()).count();
    let all = done == results.len();
    html!("div", {
        .attr("id", "batch_json_result")
        .attr("role", "status")
        .style("margin-top", "1rem")
        .children(&mut [
            html!("p", {
                .attr("id", "batch_json_summary")
                .class(&*VERDICT_CLASS)
                .style("color", if all { "var(--ok)" } else { "var(--danger)" })
                .style("background", if all { "var(--ok-soft)" } else { "var(--danger-soft)" })
                .text(&format!("{done} de {} firma(s) del lote realizadas.", results.len()))
            }),
            html!("ul", {
                .style("padding-left", "1.25rem")
                .children(results.iter().map(|result| html!("li", {
                    .attr("data-status", if result.is_ok() { "ok" } else { "error" })
                    .text(&match &result.description {
                        Some(description) => format!("{}: {} — {description}", result.id, result.text()),
                        None => format!("{}: {}", result.id, result.text()),
                    })
                })))
            }),
        ])
    })
}
