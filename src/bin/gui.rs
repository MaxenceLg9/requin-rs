#![cfg_attr(target_family = "wasm", no_main)]

fn main() -> Result<(), std::io::Error> {
    shared::gui::run()
}
