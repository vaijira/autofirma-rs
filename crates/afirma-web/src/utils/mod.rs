pub mod http;
pub mod web;

/// Formats a byte count for display (`1,5 MB`).
pub fn format_size(bytes: usize) -> String {
    const UNITS: [&str; 4] = ["bytes", "KB", "MB", "GB"];

    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{size:.1} {}", UNITS[unit]).replace('.', ",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(format_size(0), "0 bytes");
        assert_eq!(format_size(1023), "1023 bytes");
        assert_eq!(format_size(1536), "1,5 KB");
        assert_eq!(format_size(5 * 1024 * 1024), "5,0 MB");
    }
}
