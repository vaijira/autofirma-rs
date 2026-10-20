//! Form controls bound to a [`Mutable`]: they follow it when it changes
//! elsewhere (for instance when the options are reset).

use dominator::{Dom, clone, events, html, with_node};
use futures_signals::signal::{Mutable, Signal, always};
use web_sys::{HtmlInputElement, HtmlSelectElement, HtmlTextAreaElement};

use crate::css::{FIELDSET_CLASS, LEGEND_CLASS, MODIFIED_CLASS, MUTED_CLASS, OPTIONS_CLASS};

/// A `<select>` over `options`: (value, `value` attribute, label).
pub fn choice<T>(id: &str, value: &Mutable<T>, options: &[(T, &str, &str)]) -> Dom
where
    T: Copy + PartialEq + 'static,
{
    let values: Vec<T> = options.iter().map(|(v, _, _)| *v).collect();
    html!("select" => HtmlSelectElement, {
        .attr("id", id)
        .children(options.iter().map(|&(option, name, label)| {
            html!("option", {
                .attr("value", name)
                .prop_signal("selected", value.signal_ref(move |current| *current == option))
                .text(label)
            })
        }))
        .with_node!(element => {
            .event(clone!(value => move |_: events::Change| {
                if let Some(selected) = usize::try_from(element.selected_index()).ok().and_then(|i| values.get(i)) {
                    value.set_neq(*selected);
                }
            }))
        })
    })
}

pub fn text_input(id: &str, value: &Mutable<String>, placeholder: &str) -> Dom {
    typed_input(id, "text", value, placeholder)
}

pub fn url_input(id: &str, value: &Mutable<String>, placeholder: &str) -> Dom {
    typed_input(id, "url", value, placeholder)
}

fn typed_input(id: &str, kind: &str, value: &Mutable<String>, placeholder: &str) -> Dom {
    html!("input" => HtmlInputElement, {
        .attr("type", kind)
        .attr("id", id)
        .attr("placeholder", placeholder)
        .style("width", "100%")
        .prop_signal("value", value.signal_cloned())
        .with_node!(element => {
            .event(clone!(value => move |_: events::Input| value.set_neq(element.value())))
        })
    })
}

pub fn text_area(id: &str, value: &Mutable<String>, placeholder: &str) -> Dom {
    html!("textarea" => HtmlTextAreaElement, {
        .attr("id", id)
        .attr("rows", "3")
        .attr("placeholder", placeholder)
        .style("width", "100%")
        .prop_signal("value", value.signal_cloned())
        .with_node!(element => {
            .event(clone!(value => move |_: events::Input| value.set_neq(element.value())))
        })
    })
}

pub fn checkbox(id: &str, label: &str, value: &Mutable<bool>) -> Dom {
    html!("label", {
        .style("display", "inline-flex")
        .style("gap", "0.5rem")
        .style("align-items", "center")
        .children(&mut [
            html!("input" => HtmlInputElement, {
                .attr("type", "checkbox")
                .attr("id", id)
                .prop_signal("checked", value.signal())
                .with_node!(element => {
                    .event(clone!(value => move |_: events::Change| value.set_neq(element.checked())))
                })
            }),
            html!("span", { .text(label) }),
        ])
    })
}

/// A group of options with a title.
pub fn group(legend: &str, children: &mut [Dom]) -> Dom {
    html!("fieldset", {
        .class(&*FIELDSET_CLASS)
        .children(&mut [
            html!("legend", { .class(&*LEGEND_CLASS).text(legend) }),
            html!("div", { .class(&*OPTIONS_CLASS).children(children) }),
        ])
    })
}

/// Label and control of a grid row; the label is marked while the option
/// differs from its default.
pub fn field(
    id: &str,
    label: &str,
    modified: impl Signal<Item = bool> + 'static,
    control: Dom,
) -> [Dom; 2] {
    [
        html!("label", {
            .attr("for", id)
            .class_signal(&*MODIFIED_CLASS, modified)
            .text(label)
        }),
        control,
    ]
}

/// A row whose control is not a single element (no `for`).
pub fn row(label: &str, modified: impl Signal<Item = bool> + 'static, control: Dom) -> [Dom; 2] {
    [
        html!("span", {
            .class_signal(&*MODIFIED_CLASS, modified)
            .text(label)
        }),
        control,
    ]
}

/// Explanation under the control of the previous row.
pub fn hint(text: &str) -> Dom {
    html!("p", {
        .class(&*MUTED_CLASS)
        .style("grid-column", "2")
        .style("margin-top", "-0.35rem")
        .text(text)
    })
}

/// A signal for options that have no default to compare with.
pub fn unmarked() -> impl Signal<Item = bool> {
    always(false)
}

/// `true` while `value` differs from `default`.
pub fn differs<T>(value: &Mutable<T>, default: T) -> impl Signal<Item = bool> + use<T>
where
    T: PartialEq + 'static,
{
    value.signal_ref(move |value| *value != default)
}
