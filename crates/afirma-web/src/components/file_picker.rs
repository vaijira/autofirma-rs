use std::rc::Rc;

use dominator::{Dom, clone, events, html, with_node};
use gloo_file::{Blob, futures::read_as_bytes};
use wasm_bindgen_futures::spawn_local;
use web_sys::{FileList, HtmlInputElement};

use crate::css::HIDDEN_INPUT_CLASS;

/// A file read into memory.
#[derive(Debug)]
pub struct LoadedFile {
    pub name: String,
    pub data: Vec<u8>,
}

/// The files of `list`. Take them in the event handler: Chrome empties the
/// list when the input is cleared or the drop event ends.
pub fn files_of(list: &FileList) -> Vec<web_sys::File> {
    (0..list.length()).filter_map(|i| list.get(i)).collect()
}

/// Reads `files` into memory.
pub async fn read_files(files: Vec<web_sys::File>) -> Result<Vec<LoadedFile>, String> {
    let mut loaded = Vec::with_capacity(files.len());
    for file in files {
        let name = file.name();
        match read_as_bytes(&Blob::from(file)).await {
            Ok(data) => loaded.push(LoadedFile { name, data }),
            Err(e) => return Err(format!("No se pudo leer «{name}»: {e}")),
        }
    }
    Ok(loaded)
}

/// A hidden `<input type=file>` that reads the chosen files into memory. Buttons
/// open it with [`open_file_input`].
pub fn file_input(
    id: &str,
    accept: &str,
    multiple: bool,
    on_load: impl Fn(Result<Vec<LoadedFile>, String>) + 'static,
) -> Dom {
    let on_load = Rc::new(on_load);
    html!("input" => HtmlInputElement, {
        .class(&*HIDDEN_INPUT_CLASS)
        .attr("id", id)
        .attr("type", "file")
        .attr("accept", accept)
        .apply_if(multiple, |dom| dom.attr("multiple", ""))
        .with_node!(element => {
            .event(move |_: events::Change| {
                let Some(list) = element.files() else {
                    return;
                };
                let files = files_of(&list);
                spawn_local(clone!(on_load => async move {
                    on_load(read_files(files).await);
                }));
                // Allow picking the same file again.
                element.set_value("");
            })
        })
    })
}

/// Opens the file chooser of the input made by [`file_input`].
pub fn open_file_input(id: &str) {
    if let Some(input) = gloo_utils::document().get_element_by_id(id)
        && let Ok(input) = wasm_bindgen::JsCast::dyn_into::<HtmlInputElement>(input)
    {
        input.click();
    }
}

/// Button that lets the user pick one local file and reads it into memory.
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
        Self::render_button(this, false)
    }

    /// Rendered as the main action of its context.
    pub fn render_primary(this: &Rc<Self>) -> Dom {
        Self::render_button(this, true)
    }

    fn render_button(this: &Rc<Self>, primary: bool) -> Dom {
        html!("span", {
            .children(&mut [
                html!("button", {
                    .attr("type", "button")
                    .apply_if(primary, |dom| dom.class("primary"))
                    .text(this.label)
                    .event(clone!(this => move |_: events::Click| open_file_input(this.id)))
                }),
                file_input(this.id, this.accept, false, clone!(this => move |result| {
                    (this.on_load)(result.and_then(|files| {
                        files.into_iter().next().ok_or_else(|| "No se seleccionó ningún fichero".to_string())
                    }));
                })),
            ])
        })
    }
}
