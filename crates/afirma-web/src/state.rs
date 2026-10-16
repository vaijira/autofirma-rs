use afirma_core::job::KeyEntry;
use futures_signals::{
    signal::{Mutable, Signal, SignalExt},
    signal_vec::MutableVec,
};

/// Private keys loaded in the worker (only their certificates live here) and the
/// one selected for signing. Shared by the "Certificados" and "Firmar" pages.
#[derive(Debug, Default)]
pub struct Keys {
    pub entries: MutableVec<KeyEntry>,
    pub selected: Mutable<Option<u32>>,
}

impl Keys {
    pub fn add(&self, entries: Vec<KeyEntry>) {
        if self.selected.get().is_none() {
            self.selected.set(entries.first().map(|entry| entry.id));
        }
        self.entries.lock_mut().extend(entries);
    }

    pub fn remove(&self, key_id: u32) {
        self.entries.lock_mut().retain(|entry| entry.id != key_id);
        if self.selected.get() == Some(key_id) {
            self.selected
                .set(self.entries.lock_ref().first().map(|entry| entry.id));
        }
    }

    /// The selected key.
    pub fn selected_entry(&self) -> Option<KeyEntry> {
        let selected = self.selected.get()?;
        self.entries
            .lock_ref()
            .iter()
            .find(|entry| entry.id == selected)
            .cloned()
    }

    /// The selected key, updated when the selection changes.
    pub fn selected_signal(&self) -> impl Signal<Item = Option<KeyEntry>> + use<> {
        let entries = self.entries.clone();
        self.selected.signal().map(move |selected| {
            selected.and_then(|id| {
                entries
                    .lock_ref()
                    .iter()
                    .find(|entry| entry.id == id)
                    .cloned()
            })
        })
    }
}

/// Current time, seconds since the Unix epoch.
pub fn now() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}

/// Offset of the local time zone from UTC, in minutes (`120` in CEST).
pub fn utc_offset_minutes() -> i32 {
    -(js_sys::Date::new_0().get_timezone_offset() as i32)
}

/// Formats a Unix time as a Spanish date and time (`15/10/2026, 14:05:00`).
pub fn format_date_time(unix_seconds: i64) -> String {
    let date = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(
        unix_seconds as f64 * 1000.0,
    ));
    String::from(date.to_locale_string("es-ES", &wasm_bindgen::JsValue::UNDEFINED))
}

/// Formats a Unix time as a Spanish date (`15/10/2026`).
pub fn format_date(unix_seconds: i64) -> String {
    let date = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(
        unix_seconds as f64 * 1000.0,
    ));
    String::from(date.to_locale_date_string("es-ES", &wasm_bindgen::JsValue::UNDEFINED))
}
