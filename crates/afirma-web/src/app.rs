use std::{cell::Cell, rc::Rc};

use afirma_core::job::{Job, JobOutput};
use dominator::{Dom, EventOptions, clone, events, html, svg};
use futures_signals::{
    map_ref,
    signal::{Mutable, Signal, SignalExt},
};
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::spawn_local;

use crate::{
    components::file_picker::{LoadedFile, file_input, files_of, open_file_input, read_files},
    css::{
        BRAND_CLASS, CARD_CLASS, DROP_ZONE_ACTIVE_CLASS, DROP_ZONE_CLASS, ERROR_CLASS,
        FOOTER_CLASS, HEADER_CLASS, MAIN_CLASS, MUTED_CLASS, STATUS_CLASS,
    },
    prefs::Preferences,
    state::Keys,
    views::{bulk::Bulk, certs::Certificates, document::Document, json_batch::JsonBatch},
    worker::WorkerClient,
};

/// Id of the main file input, also used by the drop zone and the e2e tests.
const FILE_INPUT: &str = "file_input";

/// What the page shows: one screen whose content follows the files.
#[derive(Debug, Clone)]
enum Stage {
    /// Nothing open: the drop zone.
    Empty,
    /// Reading and analyzing a file.
    Analyzing(String),
    /// One file: verified if signed, ready to sign.
    Single(Rc<Document>),
    /// Several files: signed together into a ZIP file.
    Many(Rc<Bulk>),
}

#[derive(Debug)]
pub struct App {
    pub worker: Rc<WorkerClient>,
    pub keys: Rc<Keys>,
    pub prefs: Preferences,
    pub certificates: Rc<Certificates>,
    json_batch: Rc<JsonBatch>,
    stage: Mutable<Stage>,
    /// Files are being dragged over the page.
    dragging: Mutable<bool>,
    /// `dragenter` minus `dragleave` events: zero once the drag left the page.
    drag_depth: Cell<i32>,
    error: Mutable<Option<String>>,
    /// Increased on every open, so a slow analysis does not replace a newer file.
    generation: Cell<u32>,
}

impl App {
    pub fn new() -> Result<Rc<Self>, JsValue> {
        let worker = WorkerClient::new()?;
        let keys = Rc::new(Keys::default());
        let certificates = Certificates::new(worker.clone(), keys.clone());
        Ok(Rc::new(Self {
            json_batch: JsonBatch::new(worker.clone(), keys.clone(), certificates.clone()),
            worker,
            keys,
            prefs: Preferences::load(),
            certificates,
            stage: Mutable::new(Stage::Empty),
            dragging: Mutable::new(false),
            drag_depth: Cell::new(0),
            error: Mutable::new(None),
            generation: Cell::new(0),
        }))
    }

    /// Back to the drop zone.
    pub fn reset(this: &Rc<Self>) {
        this.generation.set(this.generation.get().wrapping_add(1));
        this.error.set(None);
        this.stage.set(Stage::Empty);
    }

    /// Opens what the user chose: one file is analyzed (and verified if it is
    /// signed), several are signed together.
    pub fn open(this: &Rc<Self>, mut files: Vec<LoadedFile>) {
        match files.len() {
            0 => {}
            1 => Self::open_signature(this, files.remove(0), None),
            _ => {
                Self::reset(this);
                this.stage.set(Stage::Many(Bulk::new(this, files)));
            }
        }
    }

    /// Opens one file; `data` is the signed data when the file is a detached
    /// signature of a known file.
    pub fn open_signature(this: &Rc<Self>, file: LoadedFile, data: Option<Rc<LoadedFile>>) {
        Self::reset(this);
        let generation = this.generation.get();
        this.stage.set(Stage::Analyzing(file.name.clone()));
        spawn_local(clone!(this => async move {
            // The worker gets its own copy; the UI keeps the original for signing.
            let result = this.worker.run(Job::Analyze { data: file.data.clone() }).await;
            if this.generation.get() != generation {
                return;
            }
            match result {
                Ok(JobOutput::Analysis(analysis)) => {
                    let document = Document::new(&this, file, analysis, data);
                    this.stage.set(Stage::Single(document));
                }
                Ok(other) => log::error!("Unexpected worker output: {other:?}"),
                Err(err) => {
                    this.stage.set(Stage::Empty);
                    this.error.set(Some(err.to_string()));
                }
            }
        }));
    }

    fn open_result(this: &Rc<Self>, result: Result<Vec<LoadedFile>, String>) {
        match result {
            Ok(files) => Self::open(this, files),
            Err(err) => this.error.set(Some(err)),
        }
    }

    pub fn render(this: Rc<Self>) -> Dom {
        html!("div", {
            // Files can be dropped anywhere on the page.
            .global_event_with_options(&EventOptions::preventable(), clone!(this => move |event: events::DragOver| {
                event.prevent_default();
                this.dragging.set_neq(true);
            }))
            .global_event(clone!(this => move |_: events::DragEnter| {
                this.drag_depth.set(this.drag_depth.get() + 1);
            }))
            .global_event(clone!(this => move |_: events::DragLeave| {
                // Every element entered is left again; zero means the page was left.
                this.drag_depth.set(this.drag_depth.get() - 1);
                if this.drag_depth.get() <= 0 {
                    this.drag_depth.set(0);
                    this.dragging.set_neq(false);
                }
            }))
            .global_event_with_options(&EventOptions::preventable(), clone!(this => move |event: events::Drop| {
                event.prevent_default();
                this.drag_depth.set(0);
                this.dragging.set_neq(false);
                let Some(list) = event.data_transfer().and_then(|transfer| transfer.files()) else {
                    return;
                };
                let files = files_of(&list);
                spawn_local(clone!(this => async move {
                    let result = read_files(files).await;
                    Self::open_result(&this, result);
                }));
            }))
            .children(&mut [
                Self::render_header(&this),
                html!("main", {
                    .class(&*MAIN_CLASS)
                    .child(file_input(FILE_INPUT, "*/*", true, clone!(this => move |result| Self::open_result(&this, result))))
                    .child_signal(this.error.signal_cloned().map(|error| {
                        error.map(|error| html!("p", { .class(&*ERROR_CLASS).attr("role", "alert").text(&error) }))
                    }))
                    .child_signal(this.stage.signal_cloned().map(clone!(this => move |stage| Some(match stage {
                        Stage::Empty => Self::render_home(&this),
                        Stage::Analyzing(name) => html!("p", {
                            .class(&*CARD_CLASS)
                            .class(&*STATUS_CLASS)
                            .attr("role", "status")
                            .text(&format!("Analizando «{name}»…"))
                        }),
                        Stage::Single(document) => Document::render(&document),
                        Stage::Many(bulk) => Bulk::render(&bulk),
                    }))))
                }),
                Self::render_footer(&this),
                Certificates::render_dialog(&this.certificates),
                JsonBatch::render_dialog(&this.json_batch),
                Self::render_drop_overlay(&this),
            ])
        })
    }

    fn render_header(this: &Rc<Self>) -> Dom {
        html!("header", {
            .class(&*HEADER_CLASS)
            .children(&mut [
                html!("h1", {
                    .style("margin", "0")
                    .child(html!("button", {
                        .attr("type", "button")
                        .attr("title", "Inicio")
                        .class(&*BRAND_CLASS)
                        .children(&mut [logo(), html!("span", { .text("autofirma-rs") })])
                        .event(clone!(this => move |_: events::Click| Self::reset(&this)))
                    }))
                }),
                Certificates::render_button(&this.certificates),
            ])
        })
    }

    fn render_home(this: &Rc<Self>) -> Dom {
        html!("section", {
            .attr("id", "drop_zone")
            .attr("aria-labelledby", "drop_title")
            .class(&*DROP_ZONE_CLASS)
            .class_signal(&*DROP_ZONE_ACTIVE_CLASS, this.dragging.signal())
            .children(&mut [
                upload_icon(),
                html!("h2", {
                    .attr("id", "drop_title")
                    .style("margin", "0")
                    .style("font-size", "1.35rem")
                    .text("Arrastre aquí lo que quiera firmar o verificar")
                }),
                html!("button", {
                    .attr("type", "button")
                    .attr("id", "choose_files")
                    .class("primary")
                    .style("padding", "0.65rem 1.4rem")
                    .text("Seleccionar ficheros")
                    .event(|_: events::Click| open_file_input(FILE_INPUT))
                }),
                html!("ul", {
                    .class(&*MUTED_CLASS)
                    .style("list-style", "none")
                    .style("padding", "0")
                    .style("display", "grid")
                    .style("gap", "0.2rem")
                    .children(&mut [
                        html!("li", { .text("Un documento: se firma (PAdES para PDF, XAdES para XML, CAdES para el resto).") }),
                        html!("li", { .text("Una firma o un documento firmado: se verifica y puede añadir su firma.") }),
                        html!("li", { .text("Varios ficheros: se firman todos de una vez en un ZIP.") }),
                    ])
                }),
                html!("p", {
                    .style("margin", "0")
                    .style("font-weight", "500")
                    .text("🔒 Los ficheros no salen de su equipo.")
                }),
            ])
        })
    }

    fn render_footer(this: &Rc<Self>) -> Dom {
        html!("footer", {
            .class(&*FOOTER_CLASS)
            .children(&mut [
                html!("span", { .text("autofirma-rs · software libre (GPL-2.0)") }),
                html!("button", {
                    .attr("type", "button")
                    .attr("id", "open_batch_json")
                    .class("link")
                    .style("font-size", "inherit")
                    .text("Lote de un servicio de firma")
                    .event(clone!(this => move |_: events::Click| this.json_batch.open.set(true)))
                }),
                html!("button", {
                    .attr("type", "button")
                    .attr("id", "reset_preferences")
                    .class("link")
                    .style("font-size", "inherit")
                    .attr("title", "Algoritmo, política, sello de tiempo… vuelven a los de AutoFirma")
                    .text("Restablecer las opciones")
                    .event(clone!(this => move |_: events::Click| this.prefs.reset()))
                }),
            ])
        })
    }

    /// Shown while files are dragged over a page that is not the drop zone.
    fn render_drop_overlay(this: &Rc<Self>) -> Dom {
        html!("div", {
            .attr("aria-hidden", "true")
            .style("position", "fixed")
            .style("inset", "0.5rem")
            .style("z-index", "20")
            .style("pointer-events", "none")
            .style("display", "grid")
            .style("place-items", "center")
            .style("border", "3px dashed var(--accent)")
            .style("border-radius", "var(--radius)")
            .style("background", "color-mix(in srgb, var(--accent-soft) 85%, transparent)")
            .style("font-size", "1.25rem")
            .style("font-weight", "600")
            .style("color", "var(--accent)")
            .visible_signal(overlay_signal(this))
            .text("Suelte los ficheros para abrirlos")
        })
    }
}

/// Dragging over a page with an open file (the drop zone has its own style).
fn overlay_signal(this: &Rc<App>) -> impl Signal<Item = bool> + use<> {
    map_ref! {
        let dragging = this.dragging.signal(),
        let empty = this.stage.signal_ref(|stage| matches!(stage, Stage::Empty)) => {
            *dragging && !*empty
        }
    }
}

fn logo() -> Dom {
    svg!("svg", {
        .attr("viewBox", "0 0 24 24")
        .attr("width", "26")
        .attr("height", "26")
        .attr("aria-hidden", "true")
        .children(&mut [
            svg!("rect", {
                .attr("width", "24")
                .attr("height", "24")
                .attr("rx", "6")
                .attr("fill", "var(--accent)")
            }),
            svg!("path", {
                .attr("d", "M6 15.5c2-3 3.5-6.5 5-6.5s-1 6 1 6 2.5-3 4-3 0 2.5 2 2.5")
                .attr("fill", "none")
                .attr("stroke", "var(--on-accent)")
                .attr("stroke-width", "1.8")
                .attr("stroke-linecap", "round")
                .attr("stroke-linejoin", "round")
            }),
        ])
    })
}

fn upload_icon() -> Dom {
    svg!("svg", {
        .attr("viewBox", "0 0 24 24")
        .attr("width", "48")
        .attr("height", "48")
        .attr("aria-hidden", "true")
        .attr("fill", "none")
        .attr("stroke", "var(--accent)")
        .attr("stroke-width", "1.5")
        .attr("stroke-linecap", "round")
        .attr("stroke-linejoin", "round")
        .children(&mut [
            svg!("path", { .attr("d", "M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z") }),
            svg!("path", { .attr("d", "M14 3v5h5") }),
            svg!("path", { .attr("d", "M12 17v-6m-2.5 2.5L12 11l2.5 2.5") }),
        ])
    })
}
