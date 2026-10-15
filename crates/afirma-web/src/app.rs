use std::rc::Rc;

use dominator::{Dom, html, link};
use futures_signals::signal::SignalExt;
use wasm_bindgen::JsValue;

use crate::{
    css::{HEADER_CLASS, MAIN_CLASS, NAV_LINK_ACTIVE_CLASS, NAV_LINK_CLASS},
    pages::{self, sign::SignPage},
    router::Route,
    worker::WorkerClient,
};

#[derive(Debug)]
pub struct App {
    sign_page: Rc<SignPage>,
}

impl App {
    pub fn new() -> Result<Rc<Self>, JsValue> {
        let worker = WorkerClient::new()?;
        Ok(Rc::new(Self {
            sign_page: SignPage::new(worker),
        }))
    }

    pub fn render(this: Rc<Self>) -> Dom {
        html!("div", {
            .children(&mut [
                Self::render_header(),
                html!("main", {
                    .class(&*MAIN_CLASS)
                    .child_signal(Route::signal().map(move |route| Some(match route {
                        Route::Sign => SignPage::render(&this.sign_page),
                        Route::Verify => pages::coming_soon(route.title(), "P2"),
                        Route::Certs => pages::coming_soon(route.title(), "P1"),
                        Route::Batch => pages::coming_soon(route.title(), "P4"),
                    })))
                }),
            ])
        })
    }

    fn render_header() -> Dom {
        html!("header", {
            .class(&*HEADER_CLASS)
            .children(&mut [
                html!("h1", {
                    .style("font-size", "1.25rem")
                    .style("margin", "0 1rem 0 0")
                    .text("autofirma-rs")
                }),
                html!("nav", {
                    .attr("aria-label", "Secciones")
                    .style("display", "flex")
                    .style("flex-wrap", "wrap")
                    .style("gap", "0.25rem")
                    .children(Route::ALL.iter().map(|&route| {
                        link!(route.hash(), {
                            .class(&*NAV_LINK_CLASS)
                            .class_signal(&*NAV_LINK_ACTIVE_CLASS, Route::signal().map(move |current| current == route))
                            .text(route.title())
                        })
                    }))
                }),
            ])
        })
    }
}
