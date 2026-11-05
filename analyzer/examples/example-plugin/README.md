# Native decoder plugin example

This crate demonstrates the Requin plugin ABI v1. Build a platform library with:

```sh
cargo build --release --manifest-path analyzer/examples/example-plugin/Cargo.toml
```

Then load the resulting `librequin_example_plugin.so` (or `.dylib`/`.dll`) with
`cli --plugin <library> <capture>` or `gui <capture> --plugin <library>`.
`--plugins-dir <directory>` loads every native library in that directory.

Plugins export `requin_plugin_init_v1`, verify `PluginHostV1::abi_version`, and
register application decoders. Decoder callbacks inspect a borrowed payload and
emit owned text fields via the host callback. The host keeps the library loaded
for as long as its registered function pointers are in use. Native plugins run
inside the application process with its permissions; only load trusted code.
