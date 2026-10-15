use std::sync::LazyLock;

use dominator::{class, pseudo};

pub static HEADER_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("display", "flex")
        .style("flex-wrap", "wrap")
        .style("align-items", "center")
        .style("gap", "1rem")
        .style("padding", "0.75rem 1rem")
        .style("background", "var(--accent)")
        .style("color", "#fff")
    }
});

pub static NAV_LINK_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("color", "#fff")
        .style("text-decoration", "none")
        .style("padding", "0.35rem 0.75rem")
        .style("border-radius", "4px")
        .pseudo!(":hover", {
            .style("background", "rgba(255, 255, 255, 0.15)")
        })
    }
});

pub static NAV_LINK_ACTIVE_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("background", "rgba(255, 255, 255, 0.25)")
        .style("font-weight", "600")
    }
});

pub static MAIN_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("max-width", "60rem")
        .style("margin", "0 auto")
        .style("padding", "1rem")
    }
});

pub static INFO_TABLE_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("border-collapse", "collapse")
        .style("margin", "1rem 0")
        .style("word-break", "break-all")
    }
});

pub static ERROR_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("color", "#ba3939")
        .style("background", "#ffe0e0")
        .style("border", "1px solid #a33a3a")
        .style("padding", "0.5rem 1rem")
        .style("border-radius", "4px")
    }
});

pub static HIDDEN_INPUT_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("display", "none")
    }
});

pub static OPTIONS_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("display", "grid")
        .style("grid-template-columns", "max-content minmax(0, 1fr)")
        .style("gap", "0.5rem 1rem")
        .style("align-items", "center")
        .style("margin", "1rem 0")
    }
});

pub static CARD_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("border", "1px solid var(--border)")
        .style("border-radius", "6px")
        .style("padding", "0.75rem 1rem")
        .style("margin", "0.75rem 0")
    }
});

pub static CARD_SELECTED_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("border-color", "var(--accent)")
        .style("box-shadow", "0 0 0 1px var(--accent)")
    }
});

pub static DIALOG_BACKDROP_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("position", "fixed")
        .style("inset", "0")
        .style("background", "rgba(0, 0, 0, 0.45)")
        .style("display", "flex")
        .style("align-items", "center")
        .style("justify-content", "center")
        .style("padding", "1rem")
        .style("z-index", "10")
    }
});

pub static DIALOG_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("background", "var(--bg)")
        .style("color", "var(--fg)")
        .style("border-radius", "8px")
        .style("padding", "1.25rem")
        .style("width", "min(26rem, 100%)")
        .style("box-shadow", "0 10px 30px rgba(0, 0, 0, 0.3)")
    }
});
