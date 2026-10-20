use dominator::{Dom, clone, events, html, traits::StaticEvent};
use futures_signals::signal::{Mutable, SignalExt};
use web_sys::HtmlDialogElement;

use crate::css::DIALOG_BODY_CLASS;

/// `close` of a `<dialog>`: Escape, or [`HtmlDialogElement::close`].
struct DialogClose;

impl StaticEvent for DialogClose {
    const EVENT_TYPE: &'static str = "close";

    fn unchecked_from_event(_: web_sys::Event) -> Self {
        Self
    }
}

/// A modal `<dialog>`, in the document while `open` is true. The browser
/// keeps the focus inside and closes it with Escape.
pub fn modal(
    id: &'static str,
    title: &'static str,
    open: &Mutable<bool>,
    body: impl Fn() -> Dom + 'static,
) -> Dom {
    html!("div", {
        .style("display", "contents")
        .child_signal(open.signal().map(clone!(open => move |is_open| is_open.then(|| {
            html!("dialog" => HtmlDialogElement, {
                .attr("id", id)
                .attr("aria-labelledby", &format!("{id}_title"))
                .after_inserted(|element| {
                    if let Err(err) = element.show_modal() {
                        log::error!("Unable to open the dialog: {err:?}");
                    }
                })
                .event(clone!(open => move |_: DialogClose| open.set_neq(false)))
                .child(html!("div", {
                    .class(&*DIALOG_BODY_CLASS)
                    .children(&mut [
                        html!("div", {
                            .style("display", "flex")
                            .style("justify-content", "space-between")
                            .style("align-items", "center")
                            .style("gap", "1rem")
                            .style("margin-bottom", "0.75rem")
                            .children(&mut [
                                html!("h2", {
                                    .attr("id", &format!("{id}_title"))
                                    .style("margin", "0")
                                    .style("font-size", "1.15rem")
                                    .text(title)
                                }),
                                html!("button", {
                                    .attr("type", "button")
                                    .attr("aria-label", "Cerrar")
                                    .class("link")
                                    .style("font-size", "1.4rem")
                                    .style("line-height", "1")
                                    .style("text-decoration-line", "none")
                                    .text("×")
                                    .event(clone!(open => move |_: events::Click| open.set_neq(false)))
                                }),
                            ])
                        }),
                        body(),
                    ])
                }))
            })
        }))))
    })
}
