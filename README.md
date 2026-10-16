# autofirma-rs

Electronic signatures (CAdES, PAdES, XAdES…) in the browser, written in Rust and compiled to
WebAssembly with [dominator](https://github.com/Pauan/rust-dominator). It is a port of the
current features of the Spanish government's [AutoFirma](https://github.com/ctt-gob-es/clienteafirma)
client. Files never leave the user's machine.

## Layout

| Path | Contents |
|---|---|
| `crates/afirma-core` | Signature formats, keystores and signing logic. No browser dependencies |
| `crates/afirma-web` | dominator UI (`dist/js/index.js`) |
| `crates/afirma-worker` | Web Worker that runs heavy jobs off the UI thread (`dist/js/worker.js`) |
| `crates/afirma-e2e` | Browser end-to-end tests (thirtyfour) |
| `static/` | CSS and images copied into `dist/` |
| `dist/index.html` | Page that loads the app |

## Development

Requirements: Rust (stable, with the `wasm32-unknown-unknown` target), `wasm-bindgen-cli`, Node.js
and yarn 4. On Debian/Ubuntu, yarn is called `yarnpkg`.

```sh
rustup target add wasm32-unknown-unknown
yarnpkg install
yarnpkg start            # dev build + server with live reload on http://localhost:10001
yarnpkg run build        # optimized build into dist/ (or: cargo make yarn)
```

### Tests

```sh
cargo test --workspace                     # unit tests (native)
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --target wasm32-unknown-unknown -p afirma-core -p afirma-web -p afirma-worker -- -D warnings
```

Cross-validation with AutoFirma itself: this signs CAdES with every key, digest, mode and
policy combination and PAdES with every PDF variant (xref streams, encryption, visible,
certified, co-signed), then checks the results with AutoFirma's validators
([tools/AfirmaValidate.java](tools/AfirmaValidate.java)), `openssl cms -verify`, poppler's
`pdfsig` and `qpdf --check`. It needs Java, OpenSSL, poppler-utils, qpdf and AutoFirma installed:

```sh
cargo test -p afirma-core --test autofirma_interop -- --ignored
```

Triphase signing is tested against the pre/post processors of clienteafirma's
`afirma-server-triphase-signer`. [tools/triphase-server/run.sh](tools/triphase-server/run.sh)
downloads them (pinned to AutoFirma 1.9), compiles them against `autofirma.jar` with a small
HTTP wrapper and serves them on port 8090. It needs a JDK:

```sh
tools/triphase-server/run.sh &
cargo test -p afirma-core --test triphase_interop -- --ignored
```

Test keystores live in `tests/data/certs` (password `1234`; regenerate them with `generate.sh`).
Test PDFs live in `tests/data/pades` (regenerate them with `generate.sh`; the encrypted ones use
the passwords `user` and `owner`). Reference signatures made by AutoFirma live in `tests/data/cades`
and `tests/data/pades/autofirma-*.pdf`.

The end-to-end tests need a built `dist/`. To run them with Selenium in Docker:

```sh
docker compose up -d
cargo test -p afirma-e2e -- --ignored --test-threads=1
```

To run them with a local Firefox and geckodriver instead:

```sh
python3 -m http.server 8080 --directory dist &
geckodriver --port 4444 &
E2E_BROWSER=firefox E2E_TEST_DATA=$PWD/tests/data cargo test -p afirma-e2e -- --ignored --test-threads=1
```

Set `TRIPHASE_URL=http://127.0.0.1:8090/afirma-server-triphase-signer/SignatureService` with the
triphase test server running to also test triphase signing from the browser.

## License

GPL-2.0-only. See [LICENSE](LICENSE).
