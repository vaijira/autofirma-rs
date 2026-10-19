//! Random values: identifiers of XAdES elements and nonces of timestamp
//! requests. In the browser they come from `crypto.getRandomValues`.

use crate::error::{Error, Result};

/// `N` random bytes.
pub(crate) fn bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0; N];
    getrandom::fill(&mut out).map_err(|e| Error::Random(e.to_string()))?;
    Ok(out)
}

/// Random (version 4) UUID, as Java's `UUID.randomUUID()` writes it.
pub(crate) fn uuid() -> Result<String> {
    let mut b = bytes::<16>()?;
    b[6] = b[6] & 0x0f | 0x40;
    b[8] = b[8] & 0x3f | 0x80;
    let hex = crate::digest::to_hex(&b);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_v4() {
        let id = uuid().unwrap();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"), "{id}");
        assert_ne!(id, uuid().unwrap());
    }
}
