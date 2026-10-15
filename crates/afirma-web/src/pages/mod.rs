use dominator::{Dom, html};

pub mod sign;

/// Placeholder for views planned in later phases of PLAN.md.
pub fn coming_soon(title: &str, phase: &str) -> Dom {
    html!("section", {
        .children(&mut [
            html!("h2", { .text(title) }),
            html!("p", { .text(&format!("Disponible en la fase {phase} del plan.")) }),
        ])
    })
}
