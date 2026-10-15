use dominator::routing;
use futures_signals::signal::Signal;
use web_sys::Url;

/// Views of the application, addressed by the URL hash (`#/sign`, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Sign,
    Verify,
    Certs,
    Batch,
}

impl Route {
    pub const ALL: [Route; 4] = [Route::Sign, Route::Verify, Route::Certs, Route::Batch];

    pub fn signal() -> impl Signal<Item = Route> {
        routing::url().signal_ref(|url| Route::from_url(url))
    }

    fn from_url(url: &str) -> Route {
        let hash = Url::new(url).map(|url| url.hash()).unwrap_or_default();
        Route::from_hash(&hash)
    }

    fn from_hash(hash: &str) -> Route {
        match hash {
            "#/verify" => Route::Verify,
            "#/certs" => Route::Certs,
            "#/batch" => Route::Batch,
            _ => Route::Sign,
        }
    }

    pub fn hash(self) -> &'static str {
        match self {
            Route::Sign => "#/sign",
            Route::Verify => "#/verify",
            Route::Certs => "#/certs",
            Route::Batch => "#/batch",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Route::Sign => "Firmar",
            Route::Verify => "Verificar",
            Route::Certs => "Certificados",
            Route::Batch => "Firma por lotes",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_round_trip() {
        for route in Route::ALL {
            assert_eq!(Route::from_hash(route.hash()), route);
        }
        assert_eq!(Route::from_hash(""), Route::Sign);
        assert_eq!(Route::from_hash("#/unknown"), Route::Sign);
    }
}
