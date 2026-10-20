use std::sync::LazyLock;

use dominator::{class, pseudo};

pub static HEADER_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("position", "sticky")
        .style("top", "0")
        .style("z-index", "5")
        .style("display", "flex")
        .style("align-items", "center")
        .style("justify-content", "space-between")
        .style("gap", "1rem")
        .style("padding", "0.6rem max(1rem, calc((100% - 46rem) / 2))")
        .style("background", "color-mix(in srgb, var(--bg) 85%, transparent)")
        .style("backdrop-filter", "blur(8px)")
        .style("border-bottom", "1px solid var(--border)")
    }
});

pub static BRAND_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("display", "flex")
        .style("align-items", "center")
        .style("gap", "0.5rem")
        .style("margin", "0")
        .style("font-size", "1.1rem")
        .style("font-weight", "700")
        .style("border-style", "none")
        .style("background-color", "transparent")
        .style("padding", "0.25rem")
    }
});

pub static MAIN_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("max-width", "46rem")
        .style("margin", "0 auto")
        .style("padding", "1.5rem 1rem 4rem")
        .style("display", "flex")
        .style("flex-direction", "column")
        .style("gap", "1rem")
    }
});

pub static FOOTER_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("max-width", "46rem")
        .style("margin", "0 auto")
        .style("padding", "0 1rem 2rem")
        .style("display", "flex")
        .style("flex-wrap", "wrap")
        .style("align-items", "center")
        .style("gap", "0.25rem 1rem")
        .style("color", "var(--muted)")
        .style("font-size", "0.875rem")
    }
});

pub static CARD_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("background", "var(--surface)")
        .style("border", "1px solid var(--border)")
        .style("border-radius", "var(--radius)")
        .style("box-shadow", "var(--shadow)")
        .style("padding", "1.25rem")
    }
});

pub static CARD_TITLE_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("margin", "0 0 0.75rem")
        .style("font-size", "1.1rem")
    }
});

/// Inner card: one signer, one certificate.
pub static TILE_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("border", "1px solid var(--border)")
        .style("border-radius", "var(--radius-sm)")
        .style("padding", "0.75rem 1rem")
        .style("margin", "0.75rem 0 0")
    }
});

pub static TILE_SELECTED_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("border-color", "var(--accent)")
        .style("box-shadow", "0 0 0 1px var(--accent)")
    }
});

pub static DROP_ZONE_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("display", "flex")
        .style("flex-direction", "column")
        .style("align-items", "center")
        .style("gap", "0.75rem")
        .style("text-align", "center")
        .style("padding", "3rem 1.5rem")
        .style("border", "2px dashed var(--border)")
        .style("border-radius", "var(--radius)")
        .style("background", "var(--surface)")
        .style("transition", "border-color 0.15s, background 0.15s")
    }
});

pub static DROP_ZONE_ACTIVE_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("border-color", "var(--accent)")
        .style("background", "var(--accent-soft)")
    }
});

pub static MUTED_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("color", "var(--muted)")
        .style("font-size", "0.875rem")
        .style("margin", "0")
    }
});

pub static ERROR_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("color", "var(--danger)")
        .style("background", "var(--danger-soft)")
        .style("border-radius", "var(--radius-sm)")
        .style("padding", "0.6rem 0.9rem")
        .style("margin", "0.75rem 0 0")
    }
});

pub static STATUS_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("color", "var(--muted)")
        .style("margin", "0.75rem 0 0")
    }
});

/// Banner at the top of a result: valid (green) or not (red).
pub static VERDICT_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("display", "flex")
        .style("gap", "0.75rem")
        .style("align-items", "flex-start")
        .style("border-radius", "var(--radius-sm)")
        .style("padding", "0.75rem 1rem")
        .style("margin", "0")
        .style("font-weight", "600")
    }
});

pub static HIDDEN_INPUT_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("display", "none")
    }
});

/// The current settings, one chip each.
pub static CHIPS_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("display", "flex")
        .style("flex-wrap", "wrap")
        .style("gap", "0.4rem")
        .style("list-style", "none")
        .style("padding", "0")
        .style("margin", "0")
    }
});

pub static CHIP_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("padding", "0.2rem 0.65rem")
        .style("border-radius", "999px")
        .style("background", "var(--surface-2)")
        .style("font-size", "0.875rem")
    }
});

/// A setting the user changed from its default.
pub static CHIP_MODIFIED_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("background", "var(--accent-soft)")
        .style("color", "var(--accent)")
        .style("font-weight", "600")
    }
});

pub static ACTIONS_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("display", "flex")
        .style("flex-wrap", "wrap")
        .style("gap", "0.5rem")
        .style("align-items", "center")
        .style("justify-content", "flex-end")
        .style("margin-top", "1rem")
    }
});

/// "Personalizar": every option, grouped.
pub static DISCLOSURE_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("margin-top", "1rem")
        .style("border-top", "1px solid var(--border)")
        .style("padding-top", "0.75rem")
    }
});

pub static FIELDSET_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("border-style", "none")
        .style("padding", "0")
        .style("margin", "1rem 0 0")
        .style("min-width", "0")
    }
});

pub static LEGEND_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("font-weight", "600")
        .style("padding", "0")
        .style("margin-bottom", "0.5rem")
    }
});

pub static OPTIONS_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("display", "grid")
        .style("grid-template-columns", "minmax(8rem, max-content) minmax(0, 1fr)")
        .style("gap", "0.6rem 1rem")
        .style("align-items", "center")
    }
});

/// Label of an option that differs from its default.
pub static MODIFIED_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .pseudo!("::after", {
            .style("content", "\" •\"")
            .style("color", "var(--accent)")
        })
    }
});

pub static DETAILS_LIST_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("display", "grid")
        .style("grid-template-columns", "max-content minmax(0, 1fr)")
        .style("gap", "0.15rem 1rem")
        .style("margin", "0")
        .style("word-break", "break-word")
    }
});

pub static DIALOG_BODY_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("padding", "1.25rem")
    }
});

pub static FILE_ROW_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("display", "flex")
        .style("align-items", "center")
        .style("gap", "0.75rem")
    }
});

pub static FILE_ICON_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("flex", "none")
        .style("display", "grid")
        .style("place-items", "center")
        .style("width", "2.75rem")
        .style("height", "2.75rem")
        .style("border-radius", "var(--radius-sm)")
        .style("background", "var(--accent-soft)")
        .style("color", "var(--accent)")
        .style("font-size", "0.75rem")
        .style("font-weight", "700")
    }
});

pub static ELLIPSIS_CLASS: LazyLock<String> = LazyLock::new(|| {
    class! {
        .style("overflow", "hidden")
        .style("text-overflow", "ellipsis")
        .style("white-space", "nowrap")
        .style("margin", "0")
    }
});
