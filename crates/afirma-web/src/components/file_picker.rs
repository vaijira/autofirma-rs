use std::rc::Rc;

use dominator::{Dom, clone, events, html, with_node};
use gloo_file::{Blob, futures::read_as_bytes};
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlInputElement;

use crate::css::HIDDEN_INPUT_CLASS;

/// A file read into memory.
#[derive(Debug)]
pub struct LoadedFile {
    pub name: String,
    pub data: Vec<u8>,
}

/// Button that lets the user pick a local file and reads it into memory.
pub struct FilePicker {
    id: &'static str,
    label: &'static str,
    accept: &'static str,
    on_load: Box<dyn Fn(Result<LoadedFile, String>)>,
}

impl std::fmt::Debug for FilePicker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilePicker").field("id", &self.id).finish()
    }
}

impl FilePicker {
    pub fn new(
        id: &'static str,
        label: &'static str,
        accept: &'static str,
        on_load: impl Fn(Result<LoadedFile, String>) + 'static,
    ) -> Rc<Self> {
        Rc::new(Self {
            id,
            label,
            accept,
            on_load: Box::new(on_load),
        })
    }

    pub fn render(this: &Rc<Self>) -> Dom {
        html!("div", {
            .children(&mut [
                html!("button", {
                    .attr("type", "button")
                    .child(html!("label", {
                        .attr("for", this.id)
                        .text(this.label)
                    }))
                }),
                html!("input" => HtmlInputElement, {
                    .class(&*HIDDEN_INPUT_CLASS)
                    .attr("id", this.id)
                    .attr("type", "file")
                    .attr("accept", this.accept)
                    .with_node!(element => {
                        .event(clone!(this => move |_: events::Change| {
                            let Some(file) = element.files().and_then(|files| files.get(0)) else {
                                return;
                            };
                            let name = file.name();
                            let blob = Blob::from(file);
                            spawn_local(clone!(this => async move {
                                let result = read_as_bytes(&blob)
                                    .await
                                    .map(|data| LoadedFile { name, data })
                                    .map_err(|e| format!("No se pudo leer el fichero: {e}"));
                                (this.on_load)(result);
                            }));
                            // Allow picking the same file again.
                            element.set_value("");
                        }))
                    })
                }),
            ])
        })
    }
}
