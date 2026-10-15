# autofirma-rs

Electronic signatures (CAdES, PAdES, XAdES…) in the browser, written in Rust and compiled to
WebAssembly with [dominator](https://github.com/Pauan/rust-dominator). It is a port of the
current features of the Spanish government's [AutoFirma](https://github.com/ctt-gob-es/clienteafirma)
client. Files never leave the user's machine.

See [PLAN.md](PLAN.md) for the migration plan and roadmap.

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

## License

GPL-2.0-only. See [LICENSE](LICENSE).
