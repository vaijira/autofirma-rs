use std::rc::Rc;

use afirma_core::job::{FileAnalysis, Job, JobOutput};
use dominator::{Dom, clone, events, html};
use futures_signals::signal::{Mutable, SignalExt};
use wasm_bindgen_futures::spawn_local;

use crate::{
    components::file_picker::{FilePicker, LoadedFile},
    css::{ERROR_CLASS, INFO_TABLE_CLASS},
    utils::{format_size, web},
    worker::WorkerClient,
};

/// File selected for signing together with its analysis.
#[derive(Debug)]
struct Selected {
    file: LoadedFile,
    analysis: FileAnalysis,
}

/// "Firmar" view: pick a file, inspect it and (from P1 on) sign it.
#[derive(Debug)]
pub struct SignPage {
    worker: Rc<WorkerClient>,
    selected: Mutable<Option<Rc<Selected>>>,
    busy: Mutable<bool>,
    error: Mutable<Option<String>>,
}

impl SignPage {
    pub fn new(worker: Rc<WorkerClient>) -> Rc<Self> {
        Rc::new(Self {
            worker,
            selected: Mutable::new(None),
            busy: Mutable::new(false),
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
        this.busy.set(true);
        spawn_local(clone!(this => async move {
            // The worker gets its own copy; the UI keeps the original for signing.
            match this.worker.run(Job::Analyze { data: file.data.clone() }).await {
                Ok(JobOutput::Analysis(analysis)) => {
                    this.selected.set(Some(Rc::new(Selected { file, analysis })));
                }
                Err(err) => this.error.set(Some(err.to_string())),
            }
            this.busy.set(false);
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
            .child_signal(this.busy.signal().map(|busy| busy.then(|| html!("p", { .text("Analizando…") }))))
            .child_signal(this.error.signal_cloned().map(|error| {
                error.map(|error| html!("p", {
                    .class(&*ERROR_CLASS)
                    .attr("role", "alert")
                    .text(&error)
                }))
            }))
            .child_signal(this.selected.signal_cloned().map(|selected| {
                selected.map(|selected| Self::render_selected(&selected))
            }))
        })
    }

    fn render_selected(selected: &Rc<Selected>) -> Dom {
        let analysis = &selected.analysis;
        let row = |name: &str, value: &str| {
            html!("tr", {
                .children(&mut [
                    html!("th", { .attr("scope", "row").style("text-align", "left").style("padding-right", "1rem").text(name) }),
                    html!("td", { .text(value) }),
                ])
            })
        };

        html!("div", {
            .attr("id", "file_info")
            .children(&mut [
                html!("table", {
                    .class(&*INFO_TABLE_CLASS)
                    .children(&mut [
                        row("Nombre", &selected.file.name),
                        row("Tamaño", &format_size(analysis.size)),
                        row("Tipo", analysis.kind.description()),
                        row("Formato de firma", analysis.default_format.name()),
                        html!("tr", {
                            .attr("id", "file_sha256")
                            .children(&mut [
                                html!("th", { .attr("scope", "row").style("text-align", "left").style("padding-right", "1rem").text("SHA-256") }),
                                html!("td", { .style("font-family", "monospace").text(&analysis.sha256) }),
                            ])
                        }),
                    ])
                }),
                html!("button", {
                    .attr("type", "button")
                    .attr("disabled", "")
                    .attr("title", "Disponible en la fase P1")
                    .text("Firmar")
                }),
                html!("button", {
                    .attr("type", "button")
                    .attr("id", "download_copy")
                    .style("margin-left", "0.5rem")
                    .text("Descargar copia")
                    .event(clone!(selected => move |_: events::Click| {
                        if let Err(err) = web::download(&selected.file.data, &selected.file.name, "application/octet-stream") {
                            log::error!("{err}");
                        }
                    }))
                }),
            ])
        })
    }
}
