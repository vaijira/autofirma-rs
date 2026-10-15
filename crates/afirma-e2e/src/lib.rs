//! End-to-end tests live in `tests/`. They need the services from
//! `docker-compose.yml` and a built `dist/`, so they are `#[ignore]`d:
//!
//! ```sh
//! yarnpkg run build && docker compose up -d
//! cargo test -p afirma-e2e -- --ignored --test-threads=1
//! ```
