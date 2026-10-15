import rust from "@wasm-tool/rollup-plugin-rust";
import serve from "rollup-plugin-serve";
import livereload from "rollup-plugin-livereload";
import { terser } from "rollup-plugin-terser";
import copy from "rollup-plugin-copy";

const is_watch = !!process.env.ROLLUP_WATCH;

export default {
    input: {
        // UI, loaded by dist/index.html.
        index: "./crates/afirma-web/Cargo.toml",
        // Web Worker, loaded by the UI as a module worker from js/worker.js.
        worker: "./crates/afirma-worker/Cargo.toml",
    },
    output: {
        dir: "dist/js",
        format: "es",
        sourcemap: true,
    },
    plugins: [
        rust({
            extraArgs: {
                wasmOpt: ["-Oz", "--enable-bulk-memory-opt", "--enable-nontrapping-float-to-int"],
            },
            watchPatterns: ["src/**", "../afirma-core/src/**"],
        }),

        copy({
            targets: [
                { src: "static/css/main.css", dest: "dist/css/" },
                { src: "static/img/favicon.svg", dest: "dist/img/" },
            ],
        }),

        is_watch && serve({
            contentBase: "dist",
            port: 10001,
            open: true,
        }),

        is_watch && livereload("dist"),

        !is_watch && terser(),
    ],
};
