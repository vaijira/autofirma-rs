use std::rc::Rc;

use afirma_core::pades::Rect;
use dominator::{Dom, clone, events, html, svg, with_node};
use futures_signals::{
    map_ref,
    signal::{Mutable, SignalExt},
};
use web_sys::{HtmlElement, HtmlInputElement, HtmlSelectElement};

/// Width of the page preview, in CSS pixels.
const PREVIEW_WIDTH: f64 = 240.0;

/// Default signature box, as in AutoFirma's dialog: lower left area of the page.
pub const DEFAULT_RECT: Rect = Rect {
    llx: 72.0,
    lly: 72.0,
    urx: 272.0,
    ury: 142.0,
};

/// Chooses the page and the area of a visible signature: drag on the page outline,
/// or type the coordinates (points, origin at the lower left corner).
#[derive(Debug)]
pub struct PagePlacement {
    /// Displayed size of every page, in points.
    pages: Vec<(f32, f32)>,
    /// Selected page, 1-based.
    pub page: Mutable<usize>,
    pub rect: Mutable<Rect>,
    /// Point where the current drag started, in page coordinates.
    drag_start: Mutable<Option<(f32, f32)>>,
}

impl PagePlacement {
    pub fn new(pages: Vec<(f32, f32)>) -> Rc<Self> {
        let page = pages.len().max(1);
        Rc::new(Self {
            pages,
            page: Mutable::new(page),
            rect: Mutable::new(DEFAULT_RECT),
            drag_start: Mutable::new(None),
        })
    }

    fn page_size(&self, page: usize) -> (f32, f32) {
        self.pages
            .get(page.saturating_sub(1))
            .copied()
            .unwrap_or((595.0, 842.0))
    }

    /// Page coordinates of a pointer event on the preview.
    fn to_page(&self, element: &HtmlElement, client_x: i32, client_y: i32) -> (f32, f32) {
        let (width, height) = self.page_size(self.page.get());
        let bounds = element.get_bounding_client_rect();
        let scale = bounds.width() / f64::from(width);
        let x = ((f64::from(client_x) - bounds.left()) / scale).clamp(0.0, f64::from(width));
        let y = ((f64::from(client_y) - bounds.top()) / scale).clamp(0.0, f64::from(height));
        (x as f32, height - y as f32)
    }

    fn drag_to(&self, (x, y): (f32, f32)) {
        if let Some((x0, y0)) = self.drag_start.get() {
            self.rect.set(Rect {
                llx: x0.min(x).round(),
                lly: y0.min(y).round(),
                urx: x0.max(x).round(),
                ury: y0.max(y).round(),
            });
        }
    }

    pub fn render(this: &Rc<Self>) -> Dom {
        html!("div", {
            .attr("id", "placement")
            .style("display", "flex")
            .style("flex-wrap", "wrap")
            .style("gap", "1rem")
            .style("align-items", "flex-start")
            .children(&mut [
                Self::render_preview(this),
                Self::render_fields(this),
            ])
        })
    }

    fn render_preview(this: &Rc<Self>) -> Dom {
        let size = this
            .page
            .signal()
            .map(clone!(this => move |page| this.page_size(page)));
        html!("div" => HtmlElement, {
            .attr("aria-hidden", "true")
            .style("position", "relative")
            .style("width", &format!("{PREVIEW_WIDTH}px"))
            .style("background", "#fff")
            .style("border", "1px solid var(--border)")
            .style("box-shadow", "0 1px 4px rgba(0, 0, 0, 0.2)")
            .style("touch-action", "none")
            .style("cursor", "crosshair")
            .style_signal("aspect-ratio", size.map(|(w, h)| format!("{w} / {h}")))
            .with_node!(element => {
                .event(clone!(this, element => move |event: events::PointerDown| {
                    let _ = element.set_pointer_capture(event.pointer_id());
                    let point = this.to_page(&element, event.mouse_x(), event.mouse_y());
                    this.drag_start.set(Some(point));
                    this.drag_to(point);
                }))
                .event(clone!(this, element => move |event: events::PointerMove| {
                    this.drag_to(this.to_page(&element, event.mouse_x(), event.mouse_y()));
                }))
                .event(clone!(this, element => move |event: events::PointerUp| {
                    this.drag_to(this.to_page(&element, event.mouse_x(), event.mouse_y()));
                    this.drag_start.set(None);
                    // A click without dragging keeps a usable box.
                    let rect = this.rect.get();
                    if rect.urx - rect.llx < 20.0 || rect.ury - rect.lly < 10.0 {
                        let (w, h) = this.page_size(this.page.get());
                        let llx = rect.llx.min(w - (DEFAULT_RECT.urx - DEFAULT_RECT.llx)).max(0.0);
                        let lly = rect.lly.min(h - (DEFAULT_RECT.ury - DEFAULT_RECT.lly)).max(0.0);
                        this.rect.set(Rect {
                            llx,
                            lly,
                            urx: llx + DEFAULT_RECT.urx - DEFAULT_RECT.llx,
                            ury: lly + DEFAULT_RECT.ury - DEFAULT_RECT.lly,
                        });
                    }
                }))
            })
            .child(svg!("svg", {
                .attr("width", "100%")
                .attr("height", "100%")
                .attr("style", "display: block")
                .attr_signal("viewBox", this.page.signal().map(clone!(this => move |page| {
                    let (w, h) = this.page_size(page);
                    format!("0 0 {w} {h}")
                })))
                .child(svg!("rect", {
                    .attr("fill", "rgba(0, 90, 160, 0.15)")
                    .attr("stroke", "var(--accent)")
                    .attr("stroke-width", "2")
                    .attr("vector-effect", "non-scaling-stroke")
                    .attr_signal("x", this.rect.signal().map(|r| r.llx.to_string()))
                    .attr_signal("width", this.rect.signal().map(|r| (r.urx - r.llx).max(0.0).to_string()))
                    .attr_signal("height", this.rect.signal().map(|r| (r.ury - r.lly).max(0.0).to_string()))
                    .attr_signal("y", {
                        let placement = this.clone();
                        map_ref! {
                            let page = this.page.signal(),
                            let rect = this.rect.signal() => move {
                                (placement.page_size(*page).1 - rect.ury).to_string()
                            }
                        }
                    })
                }))
            }))
        })
    }

    fn render_fields(this: &Rc<Self>) -> Dom {
        let number = |id: &'static str,
                      label: &'static str,
                      get: fn(&Rect) -> f32,
                      set: fn(&mut Rect, f32)| {
            [
                html!("label", { .attr("for", id).text(label) }),
                html!("input" => HtmlInputElement, {
                    .attr("type", "number")
                    .attr("id", id)
                    .attr("min", "0")
                    .attr("step", "1")
                    .style("width", "6rem")
                    .prop_signal("value", this.rect.signal().map(move |rect| get(&rect).to_string()))
                    .with_node!(element => {
                        .event(clone!(this => move |_: events::Change| {
                            if let Ok(value) = element.value().trim().parse::<f32>() {
                                let mut rect = this.rect.get();
                                set(&mut rect, value);
                                this.rect.set(rect);
                            }
                        }))
                    })
                }),
            ]
        };

        html!("div", {
            .style("display", "grid")
            .style("grid-template-columns", "max-content max-content")
            .style("gap", "0.4rem 0.75rem")
            .style("align-items", "center")
            .children(&mut [
                html!("label", { .attr("for", "sign_page").text("Página") }),
                html!("select" => HtmlSelectElement, {
                    .attr("id", "sign_page")
                    .children((1..=this.pages.len()).map(clone!(this => move |page| {
                        html!("option", {
                            .attr("value", &page.to_string())
                            .prop("selected", page == this.page.get())
                            .text(&page.to_string())
                        })
                    })))
                    .with_node!(element => {
                        .event(clone!(this => move |_: events::Change| {
                            if let Ok(page) = element.value().parse() {
                                this.page.set(page);
                            }
                        }))
                    })
                }),
            ])
            .children(number("sign_llx", "X inferior izquierda", |r| r.llx, |r, v| {
                let width = r.urx - r.llx;
                r.llx = v;
                r.urx = v + width;
            }))
            .children(number("sign_lly", "Y inferior izquierda", |r| r.lly, |r, v| {
                let height = r.ury - r.lly;
                r.lly = v;
                r.ury = v + height;
            }))
            .children(number("sign_width", "Ancho", |r| r.urx - r.llx, |r, v| r.urx = r.llx + v.max(1.0)))
            .children(number("sign_height", "Alto", |r| r.ury - r.lly, |r, v| r.ury = r.lly + v.max(1.0)))
            .child(html!("p", {
                .style("grid-column", "1 / -1")
                .style("margin", "0")
                .style("color", "var(--muted)")
                .style("max-width", "18rem")
                .text("Arrastre sobre la página para dibujar el área de la firma. Las medidas están en puntos (1/72 de pulgada).")
            }))
        })
    }
}
